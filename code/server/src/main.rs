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
use bytemuck::{Pod, Zeroable, bytes_of, from_bytes};
use std::convert::TryFrom;
use std::mem::{MaybeUninit, align_of};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::collections::VecDeque;
use libbpf_rs::{RingBufferBuilder, Program, UprobeOpts};

include!("bpf/monitore.skel.rs");

static CURRENT_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static USER_ZERO: OnceLock<Instant> = OnceLock::new();
static KERNEL_ZERO: OnceLock<u64> = OnceLock::new();
static TEST: OnceLock<Instant> = OnceLock::new();
const TIMEOUT_NS: u64 = 3000000;
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

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Message {
    timestamp: u128,
    first_u128: u128,
    second_u128: u128,
    i_val: i128,
    first_f64: f64,
    second_f64: f64,
    seq: u64,
    msg_type: u8,
    _padding: [u8; 7],
}

fn encode_message(
     msg_type: MessageType,
    seq: u64,
    timestamp: u128,
    first_u128: u128,
    second_u128: u128,
    first_f64: f64,
    second_f64: f64,
    i_val: i128,
) -> Result<Vec<u8>, anyhow::Error> {
    let msg = Message {
        msg_type: msg_type as u8,
        seq: seq,
        timestamp: timestamp,
        first_u128: first_u128,
	second_u128: second_u128,
	first_f64: first_f64,
	second_f64: second_f64,
	i_val: i_val,
	_padding: [0u8; 7],
    };

    let encoded: &[u8] = bytemuck::bytes_of(&msg);
    Ok(encoded.to_vec())
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct BpfData {
    msg_type: u8,
    _padding: [u8; 7], 
    seq: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Event {
    timestamp: u64,
    data: BpfData,

}

impl TryFrom<u8> for MessageType {
    type Error = std::convert::Infallible;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Start),
            1 => Ok(MessageType::NTP),
            2 => Ok(MessageType::NTP_Result),
            3 => Ok(MessageType::PTP),
            4 => Ok(MessageType::PTP_Result),
            5 => Ok(MessageType::Calc),
            _ => panic!("False Value for MessageType: {}", value),
        }
    }
}

#[no_mangle]
pub extern "C" fn measure_instant() -> Instant {
    Instant::now()
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
        SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
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

fn wait_for_event(
    number: u64,
    msg_t: MessageType,
) -> Event {
	let queue_arc = CURRENT_EVENT.get().expect("CURRENT_EVENT not initialized");
    loop {
        {
	    let mut queue = queue_arc.lock().unwrap();
            while let Some(evt) = queue.pop_front() {
		if let Ok(msg_type) = MessageType::try_from(evt.data.msg_type) {
                    if msg_type == msg_t && evt.data.seq == number {
                        return evt;
                    }
                }
            }
        }
        thread::sleep(Duration::from_nanos(50));
    }
}

fn handle_time(mut stream: TcpStream, disconnect_counter: Arc<Mutex<i32>>, standard: Arc<String>, frequency: Arc<String>, bandwith: Arc<String>, qos: Arc<String>)-> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    if let Ok(n) = stream.read(&mut buffer) {
	let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
	if msg.msg_type == MessageType::Start as u8 {
            println!("----------------Time synchronisation started----------------");
            let mut min_latency = u128::MAX;
            let mut min_latency_index = 0;
            let interval = Duration::from_nanos(TIMEOUT_NS);
            let mut next_tick = Instant::now() + interval;
            for i in 0..200 {
                let start_time = Instant::now();
                let elapsed_time = start_time.duration_since(*USER_ZERO.get().unwrap());

		let encoded_msg = encode_message(MessageType::NTP, i, elapsed_time.as_nanos(), 0, 0, 0.0, 0.0, 0)?;
		//println!("{:?}", encoded_msg);
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
			let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
			let number = msg.seq;
			let event_snapshot = wait_for_event(number, MessageType::NTP);

			let end_time = event_snapshot.timestamp - *KERNEL_ZERO.get().unwrap();
                        let nanos = end_time as u128 - elapsed_time.as_nanos();
			println!("Nanos {}", nanos);
			if nanos < min_latency {
                            	min_latency = nanos;
                            	min_latency_index = i;
                       	}
                    }
                    _ => eprintln!("Error while receiving"),
                }
                wait_until(next_tick);
                next_tick += interval;
            }
           // let test = unsafe{measure_instant()};
           // TEST.get_or_init(|| test);

	    let encoded_msg = encode_message(MessageType::NTP_Result, 0, 0, min_latency_index.into(), 0, 0.0, 0.0, 0)?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending result: {}", e);
            }
            println!("The shortest latency was at {} with {} ns", min_latency_index, min_latency);
            let mut offsets = Vec::with_capacity(200);
	    
            println!("--------------------Start PTP Mechanism---------------------");
            let mut next_tick = Instant::now() + interval;
            for i in 0..200 {
                let start_time = Instant::now();
		let elapsed_time = start_time.duration_since(*USER_ZERO.get().unwrap());
		let encoded_msg = encode_message(MessageType::PTP, i, elapsed_time.as_nanos(), 0, 0, 0.0, 0.0, 0)?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
 			let number = msg.seq;
                        let event_snapshot = wait_for_event(number, MessageType::PTP);
			let server_arrival = event_snapshot.timestamp - *KERNEL_ZERO.get().unwrap(); 
			if let (server_sent, client_arrival, client_sent) =
    			(msg.first_u128, msg.second_u128, msg.timestamp)
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
	    let encoded_msg = encode_message(MessageType::PTP_Result, 0, 0, 0, 0, 0.0, 0.0, result_offset)?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending result: {}", e);
            }
            println!("---------------------Start Latency Test---------------------");
            let mut control_values = Vec::with_capacity(NUM_POINTS);
            let mut next_tick = Instant::now() + interval;
            for i in 0..20 {
		let start_time = Instant::now();
                let elapsed_time = start_time.duration_since(*USER_ZERO.get().unwrap());
                let encoded_msg = encode_message(MessageType::PTP, i, elapsed_time.as_nanos(), 0, 0, 0.0, 0.0, 0)?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }

                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        
                        let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
			let number = msg.seq;
                        let event_snapshot = wait_for_event(number, MessageType::PTP);
                        let server_arrival = event_snapshot.timestamp - *KERNEL_ZERO.get().unwrap();

                        if let (server_sent, client_arrival, client_sent) =
                        (msg.first_u128, msg.second_u128, msg.timestamp)
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
            let calc_time = SystemTime::now();
            let mut next_tick = Instant::now() + interval;
            let mut i = 0;
            while calc_time.elapsed()?.as_secs() < 12 {
                let calc_start_time = Instant::now();
		let calc_start_elapsed = calc_start_time.duration_since(*USER_ZERO.get().unwrap());
                let theta = 2.0 * PI * (i as f64) / (NUM_POINTS as f64);
                let x = RADIUS * theta.cos();
		let calc_send_time = Instant::now();
		let calc_send_elapsed = calc_send_time.duration_since(*USER_ZERO.get().unwrap());


		let encoded_msg = encode_message(MessageType::Calc, i, 0, 0, 0, theta, RADIUS, 0)?;
                if let Err(e) = stream.write_all(&encoded_msg) {
                    eprintln!("Error while sending: {}", e);
                    return Ok(());
                }
		    

                let mut first_duration = 0;
                let mut second_duration = 0;
		let mut calc_send_duration = 0;
                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
			
			let number = msg.seq;
                        let event_snapshot = wait_for_event(number, MessageType::Calc);
                        let calc_end_time = event_snapshot.timestamp - *KERNEL_ZERO.get().unwrap();

			calc_send_duration = calc_end_time as u128 - calc_send_elapsed.as_nanos();
                        if let (y, client_time) =
                        (msg.first_f64, msg.timestamp)
                        {
				first_duration = client_time as i128 - calc_end_time as i128;
                                second_duration = calc_end_time as i128 - client_time as i128;
                                last_y = if calc_send_duration <= TIMEOUT_NS as u128 {
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
                latency.push((first_duration, second_duration, calc_send_duration, calc_start_time.elapsed().as_nanos()));
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
    let event_queue = Arc::new(Mutex::new(VecDeque::new()));
    CURRENT_EVENT.set(event_queue.clone()).unwrap();
    
    let event_ref = CURRENT_EVENT.get().expect("CURRENT_EVENT not initialized");
    let open_skel = MonitoreSkelBuilder::default().open();
    println!("Skelett geöffnet.");

    let mut skel = open_skel?.load()?;
    println!("Skelett geladen.");

    skel.attach()?;

    println!("eBPF-Programm läuft …");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let maps = skel.maps();
    // Callback-Funktion, wird bei jedem Ringbuffer-Event aufgerufen
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(maps.events(), move |data: &[u8]| {
            if data.len() != std::mem::size_of::<Event>() {
                eprintln!("Unexpected data size: {}", data.len());
                return 0;
            }

        let event = bytemuck::from_bytes::<Event>(data);
        let now = Instant::now();

        USER_ZERO.get_or_init(|| now);
        KERNEL_ZERO.get_or_init(|| event.timestamp);

        let elapsed = now.duration_since(*USER_ZERO.get().unwrap());
        let kernel_diff = event.timestamp - *KERNEL_ZERO.get().unwrap();
        let diff_ns = elapsed.as_nanos() as i128 - kernel_diff as i128;
/*
        println!(
                "Latenz: {:?} (User: {:?} - Kernel: {:?})",
                diff_ns,
                elapsed,
                Duration::from_nanos(kernel_diff),
        );
        if let Some(val) = TEST.get(){
                let usersp = val.duration_since(*USER_ZERO.get().unwrap());
                let test_diff = usersp.as_nanos() as i128 - kernel_diff as i128;
                
                println!(
                        "TEST: Latenz: {:?} (User: {:?} - Kernel: {:?})",
                        test_diff,
                        usersp,
                        Duration::from_nanos(kernel_diff),
        );
	} */
        let mut queue = event_ref.lock().unwrap();
        queue.push_back(*event);

        0 // Rückgabewert: 0 bedeutet "OK"
    })?;
    let mut ringbuf = ringbuf_builder.build()?;

// Separate Thread für Polling des Ringbuffers starten
let handle = thread::spawn(move || {
      let now = unsafe{measure_instant()};
      USER_ZERO.get_or_init(|| now);
    while r.load(Ordering::Relaxed) {
        ringbuf.poll(Duration::from_millis(100)).unwrap();
    
}
});

    println!("Size of Message: {}", std::mem::size_of::<Message>());
    
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
