use libbpf_rs::skel::{OpenSkel, SkelBuilder, Skel};
use std::fs::{OpenOptions, create_dir_all};
use std::io::{Read, Write, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime, Instant};
use std::f64::consts::PI;
use std::sync::{Arc, Mutex};
use std::env;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use bincode;

include!("bpf/monitore.skel.rs");

const TIMEOUT_MS: u64 = 3;
const NUM_POINTS: usize = 4000;
const RADIUS: f64 = 10.0;

#[derive(Serialize, Deserialize, Debug)]
enum Data {
    IntegerI128(i128),
    IntegerU128(u128),
    IntegerU64(u64),
    Float(f64),
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum MessageType {
    Start = 0,
    NTP = 1,
    NTP_Result = 2,
    PTP = 3,
    PTP_Result = 4,
    Calc = 5,
}

#[derive(Serialize, Deserialize, Debug)]
struct Message{
msg_type: MessageType,
seq: Option<u64>,
timestamp: Option<u128>,
primary_data: Option<Data>,
secondary_data:Option<Data>,
}

fn encode_message(
    msg_type: MessageType,
    seq: Option<u64>,
    timestamp: Option<u128>,
    primary_data: Option<Data>,
    secondary_data: Option<Data>,
) -> Result<Vec<u8>, anyhow::Error> {
    let msg = Message {
        msg_type,
        seq: seq,
        timestamp: timestamp,
        primary_data: primary_data,
        secondary_data: secondary_data,
    };

    let encoded = bincode::serialize(&msg).expect("Failed to serialize");
    Ok(encoded)
}

fn median(values: &Vec<i128>) -> i128 {
    let mut sorted_values = values.clone();
    sorted_values.sort();
    let len = sorted_values.len();
    if len % 2 == 1 {
        sorted_values[len / 2]
    } else {
        (sorted_values[len / 2 - 1] + sorted_values[len / 2]) / 2
    }
}

fn get_time_stamp() -> u128 {
    let time = SystemTime::now();
    time.duration_since(SystemTime::UNIX_EPOCH).expect("Systemtime is before UNIX-Time").as_nanos()
}

fn wait_until(next_tick: Instant) {
    let now = Instant::now();
    if next_tick > now {
        let sleep_time = next_tick - now;
        if sleep_time > Duration::from_micros(500) {
            thread::sleep(sleep_time - Duration::from_micros(200));
        }
        while Instant::now() < next_tick {
            std::hint::spin_loop();
        }
    }
}

fn handle_time(mut stream: TcpStream, disconnect_counter: Arc<Mutex<i32>>, standard: Arc<String>, frequency: Arc<String>, bandwith: Arc<String>, qos: Arc<String>)-> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0; 1024];
    if let Ok(n) = stream.read(&mut buffer) {
	let msg: Message = bincode::deserialize(&buffer[..n]).expect("Deserialization failed");
	if msg.msg_type == MessageType::Start {
            println!("----------------Time synchronisation started----------------");
            let mut min_latency = u128::MAX;
            let mut min_latency_index = 0;
            let interval = Duration::from_millis(TIMEOUT_MS);
            let mut next_tick = Instant::now() + interval;
            for i in 0..200 {
                let start_time = Instant::now();
		let encoded_msg = encode_message(MessageType::NTP, Some(i), Some(get_time_stamp()), None, None)?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let duration = start_time.elapsed().as_nanos();
                        if duration < min_latency {
                            min_latency = duration;
                            min_latency_index = i;
                        }
                    }
                    _ => eprintln!("Error while receiving"),
                }
                wait_until(next_tick);
                next_tick += interval;
            }
	    let encoded_msg = encode_message(MessageType::NTP_Result, None, None, Some(Data::IntegerU64(min_latency_index)), None)?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending result: {}", e);
            }
            println!("The shortest latency was at {} with {} ns", min_latency_index, min_latency);
            let mut offsets = Vec::with_capacity(200);
	    
            println!("--------------------Start PTP Mechanism---------------------");
            let mut next_tick = Instant::now() + interval;
            for i in 0..200 {
                let start_time = Instant::now();
		let encoded_msg = encode_message(MessageType::PTP, Some(i), Some(get_time_stamp()), None, None)?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let server_arrival = get_time_stamp();
                        let msg: Message = bincode::deserialize(&buffer[..n]).expect("Deserialization failed");
			
			if let (Some(Data::IntegerU128(server_sent)), Some(Data::IntegerU128(client_arrival)), Some(client_sent)) =
    			(msg.primary_data, msg.secondary_data, msg.timestamp)
			{
    				let first_offset = client_arrival as i128 - server_sent as i128;
    				let second_offset = server_arrival as i128 - client_sent as i128;
    				let optimal_offset = (first_offset + second_offset) / 2;
    				let offset = optimal_offset - second_offset;
                        	offsets.push(offset);
			} else {
    				eprintln!("PTP format is wrong");
			}
                    }
                    _ => eprintln!("Error while receiving"),
                }
                wait_until(next_tick);
                next_tick += interval;
            }
            let result_offset = median(&offsets);
            println!("Result-Offset {}", result_offset);
	    let encoded_msg = encode_message(MessageType::PTP_Result, None, None, Some(Data::IntegerI128(result_offset)), None)?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending result: {}", e);
            }
            println!("---------------------Start Latency Test---------------------");
            let mut control_values = Vec::with_capacity(NUM_POINTS);
            let mut next_tick = Instant::now() + interval;
            for i in 0..20 {
                let encoded_msg = encode_message(MessageType::PTP, Some(i), Some(get_time_stamp()), None, None)?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }

                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let server_arrival = get_time_stamp();
                        let msg: Message = bincode::deserialize(&buffer[..n]).expect("Deserialization failed");

                        if let (Some(Data::IntegerU128(server_sent)), Some(Data::IntegerU128(client_arrival)), Some(client_sent)) =
                        (msg.primary_data, msg.secondary_data, msg.timestamp)
                        {  
				let first_offset = client_arrival as i128 - server_sent as i128;
                                let second_offset = server_arrival as i128 - client_sent as i128;
                                let diff_test_offset = second_offset - first_offset;
                                control_values.push(diff_test_offset.abs());
                         } else {
                                eprintln!("Wrong PTP Format");
                         }
                    }
                    _ => eprintln!("Error while receiving"),
                }
                wait_until(next_tick);
                next_tick += interval;
            }
            let avg_error = median(&control_values);
            println!("AVG-Error is: {}", avg_error);
            let mut points = Vec::with_capacity(NUM_POINTS);
            let mut latency = Vec::with_capacity(NUM_POINTS);
            let mut last_y = 0.0;
            let calc_time = Instant::now();
            let mut next_tick = Instant::now() + interval;
            let mut i = 0;
            while calc_time.elapsed().as_secs() < 12 {
                let calc_start_time = Instant::now();
                let theta = 2.0 * PI * (i as f64) / (NUM_POINTS as f64);
                let x = RADIUS * theta.cos();
		let calc_send_time = Instant::now();

		let encoded_msg = encode_message(MessageType::Calc, Some(i), None, Some(Data::Float(theta)), Some(Data::Float(RADIUS)))?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }

                let mut first_duration = 0;
                let mut second_duration = 0;
                let mut calc_send_duration = Duration::ZERO;
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let calc_end_time = Instant::now();
			let msg: Message = bincode::deserialize(&buffer[..n]).expect("Deserialization failed");
			calc_send_duration = calc_send_time.elapsed();
                        if let (Some(Data::Float(y)), Some(client_time)) =
                        (msg.primary_data, msg.timestamp)
                        {
				first_duration = client_time as i128 - get_time_stamp() as i128;
                                second_duration = get_time_stamp() as i128 - client_time as i128;
                                last_y = if calc_send_duration.as_millis() <= TIMEOUT_MS as u128 {
                                    y
                                } else {
                                    last_y - 2.0
                                };

                         } else {
                                eprintln!("Wrong Calc Format");
                         }
			}
                    _ => eprintln!("Error while receiving"),
                }
                points.push((x, last_y));
                wait_until(next_tick);
                latency.push((first_duration, second_duration, calc_send_duration.as_nanos(), calc_start_time.elapsed().as_nanos()));
                next_tick += interval;
                i += 1;
            }
            let mut counter = disconnect_counter.lock().unwrap();
            *counter += 1;
            let result_path = format!("../results/standard_{}/frequency_{}/bandwith_{}/qos_{}", standard, frequency, bandwith, qos);
            if let Err(e) = create_dir_all(&result_path) {
                eprintln!("Error while creating directories: {}", e);
                return Ok(());
            }
            let mut circle_points = BufWriter::new(OpenOptions::new().write(true).create(true).truncate(true).open(format!("{}/circle_points_{}", result_path, counter)).unwrap());
            let mut latencies = BufWriter::new(OpenOptions::new().write(true).create(true).truncate(true).open(format!("{}/latencys_{}", result_path, counter)).unwrap());
            for (x, y) in &points {
                writeln!(circle_points, "{},{}", x, y).unwrap();
            }
            for (l1, l2, lg, c) in &latency {
                writeln!(latencies, "{},{},{},{}", l1, l2, lg, c).unwrap();
            }
            circle_points.flush().unwrap();
            latencies.flush().unwrap();
            println!("Points and Latencies written.");
            if *counter >= 1 {
                println!("3 Clients haben sich disconnected. Der Server wird beendet.");
                std::process::exit(0);
	} else {
		return Ok(());
	}   
       } else {
	return Ok(());
	}
    } else {
	return Ok (());
	}
}

fn main() -> Result<(), libbpf_rs::Error> {
    let open_skel = MonitoreSkelBuilder::default().open();
    println!("Skelett geöffnet.");
    let mut skel = open_skel?.load()?;
    println!("Skelett geladen.");
    skel.attach()?;
    println!("eBPF-Programm läuft …");
    let args: Vec<String> = env::args().collect();
    let standard = Arc::new(args[1].clone());
    let frequency = Arc::new(args[2].clone());
    let bandwith = Arc::new(args[3].clone());
    let qos = Arc::new(args[4].clone());
    let listener = TcpListener::bind("192.168.1.1:8080")?;
    println!("Server läuft auf 192.168.1.1:8080");
    let disconnect_counter = Arc::new(Mutex::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let standard = Arc::clone(&standard);
                let frequency = Arc::clone(&frequency);
                let bandwith = Arc::clone(&bandwith);
                let qos = Arc::clone(&qos);
                let disconnect_counter = Arc::clone(&disconnect_counter);
                thread::spawn(move || {
                    let _ = handle_time(stream, disconnect_counter, standard, frequency, bandwith, qos);
                });
            }
            Err(e) => eprintln!("Verbindungsfehler: {}", e),
        }
    }
    Ok(())
}
