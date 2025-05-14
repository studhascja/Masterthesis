use libbpf_rs::skel::{OpenSkel, SkelBuilder, Skel};
use std::fs::{OpenOptions, create_dir_all};
use std::io::{self, Read, Write, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime};
use std::f64::consts::PI;
use std::sync::{Arc, Mutex};
use std::env;
use anyhow::Result;

include!("bpf/monitore.skel.rs");


const TIMEOUT_MS: u64 = 3; 
const NUM_POINTS: usize = 200; 
const RADIUS: f64 = 10.0; 

fn median(values: &Vec<i128>) -> i128 {
    let mut sorted_values = values.clone(); 
    sorted_values.sort();  

    let len = sorted_values.len();
    
    if len % 2 == 1 {
    	return sorted_values[len / 2] 
    } else {
        return (sorted_values[len / 2 - 1] + sorted_values[len / 2]) / 2  // Average of 2 middle values
    }
}

fn get_time_stamp() -> u128 {
    let time = SystemTime::now();
    let timestamp_ns = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Systemtime is before UNIX-Time")
        .as_nanos();
    timestamp_ns as u128
}

fn hold_clock(start_time: SystemTime){
        if start_time.elapsed().unwrap().as_millis() < 3 {
        	thread::sleep(Duration::from_millis((3 - start_time.elapsed().unwrap().as_millis()).try_into().unwrap()));
	}
}

fn handle_time(mut stream: TcpStream, disconnect_counter: Arc<Mutex<i32>>, standard: Arc<String>, frequency: Arc<String>, bandwith: Arc<String>, qos: Arc<String>) {
    let mut buffer = [0; 1024];
    
    if let Ok(n) = stream.read(&mut buffer) {
        let msg = String::from_utf8_lossy(&buffer[..n]);
        if msg.trim() == "start" {
	    println!("------------------------------------------------------------");
            println!("----------------Time synchronisation started----------------");
	    println!("------------------------------------------------------------\n");

            let mut min_latency = u128::MAX;
            let mut min_latency_index = 0;

            for i in 0..NUM_POINTS {
                let start_time = SystemTime::now();
                                
                if let Err(e) = stream.write_all(format!("{} {}\n", i, get_time_stamp()).as_bytes()) {
                    eprintln!("Error while sending: {}", e);
                    return;
                }
                
               
                match stream.read(&mut buffer) {
                      Ok(n) if n > 0 => {
                        let duration = start_time.elapsed().unwrap();
                                        
                       if duration.as_nanos() < min_latency {
                            min_latency = duration.as_nanos();
                            min_latency_index = i;
                        }
                    }
                    _ => eprintln!("Error while reseaving"),
                }

                // 3 ms clock
		hold_clock(start_time);
	    }

            // Send result to Client
            if let Err(e) = stream.write_all(format!("result {}\n", min_latency_index).as_bytes()) {
                eprintln!("Error while sending result: {}", e);
            }

            println!("The shortes latency was at {} with {} ns", min_latency_index, min_latency);

	    let mut offsets = Vec::with_capacity(NUM_POINTS);

	    println!("------------------------------------------------------------");
	    println!("--------------------Start PTP Mechanism---------------------");
	    println!("------------------------------------------------------------\n");

	    //PTP Mechanism
	    for _i in 0..NUM_POINTS {
                let start_time = SystemTime::now();

                if let Err(e) = stream.write_all(format!("ptp {}\n", get_time_stamp()).as_bytes()) {
                    eprintln!("Error while sending: {}", e);
                    return;
                }

                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
			let server_arrival = get_time_stamp();
                        let received_str = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                        let parts: Vec<&str> = received_str.split_whitespace().collect();

                        if parts.len() == 3 {
			    if let (Ok(server_sent), Ok(client_arrival), Ok(client_sent)) = (
                                parts[0].parse::<u128>(),
                                parts[1].parse::<u128>(),
                                parts[2].parse::<u128>(),
                            ) {
				
				let first_offset = client_arrival as i128 - server_sent as i128;
				let second_offset = server_arrival as i128 - client_sent as i128;

				let optimal_offset = (first_offset + second_offset) / 2;
				let offset = optimal_offset - second_offset;
                                  

				offsets.push(offset);
				//println!("Latenz: {} Diff: {}", optimal_offset, offset_diff);

                            } else {
                                eprintln!("Error parsing timestamps: {:?}", parts);
                            }
			    
 		        } else {
                            eprintln!("Invalid response format: '{}'", received_str);
                        }
                    }
                    _ => eprintln!("Error while receiving"),
                }

                // 3 ms clock
                hold_clock(start_time);
            }
		
	    let result_offset = median(&offsets);
	    println!("Result-Offset {}", result_offset);

	    if let Err(e) = stream.write_all(format!("_result {}\n", result_offset).as_bytes()) {
            	eprintln!("Error while sending result: {}", e);
            }

	    let mut control_values = Vec::with_capacity(NUM_POINTS);

	    println!("------------------------------------------------------------");
	    println!("---------------------Start Latency Test---------------------");
	    println!("------------------------------------------------------------\n");

	    	    //Test
	    for _i in 0..20 {
                let start_time = SystemTime::now();

                if let Err(e) = stream.write_all(format!("ptp {}\n", get_time_stamp()).as_bytes()) {
                    eprintln!("Error while sending: {}", e);
                    return;
                }

                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
			let server_arrival1 = get_time_stamp();
                        let received_str = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                        let parts: Vec<&str> = received_str.split_whitespace().collect();

                        if parts.len() == 3 {
			    if let (Ok(server_sent1), Ok(client_arrival1), Ok(client_sent1)) = (
                                parts[0].parse::<u128>(),
                                parts[1].parse::<u128>(),
                                parts[2].parse::<u128>(),
                            ) {
				
				let first_test_offset = client_arrival1 as i128 - server_sent1 as i128;
				let second_test_offset = server_arrival1 as i128 - client_sent1 as i128;

				let diff_test_offset = second_test_offset - first_test_offset;
				control_values.push(diff_test_offset.abs());
                               //	println!("First Offset: {} Second Offset: {} Diffoffset: {}", first_test_offset, second_test_offset, diff_test_offset);
                            } else {
                                eprintln!("Error parsing timestamps: {:?}", parts);
                            }
			    
 		        } else {
                            eprintln!("Invalid response format: '{}'", received_str);
                        }
                    }
                    _ => eprintln!("Error while receiving"),
                }

                // 3 ms clock
                hold_clock(start_time);
            }

	    let avg_error = median(&control_values);
            println!("AVG-Error is: {}", avg_error);

	    let mut points = Vec::with_capacity(NUM_POINTS);
	    let mut latency = Vec::with_capacity(NUM_POINTS);
	    
	    println!("------------------------------------------------------------");
            println!("--------------------Calculation started---------------------");
	    println!("------------------------------------------------------------\n");

	    let mut last_y = 0.0;
            let mut calc_send_duration = Duration::ZERO;
	    let mut cycle_time = Duration::ZERO;
		
	    let mut first_duration = 0;
	    let mut second_duration = 0;

	    let calc_time = SystemTime::now();
	
	    let mut i = 0;

            while calc_time.elapsed().unwrap().as_secs() < 12{
                let calc_start_time = SystemTime::now();

		let theta = 2.0 * PI * (i as f64) / (40000 as f64);
                let x = RADIUS * theta.cos();
		
            	let calc_send_time = SystemTime::now();
            	if let Err(e) = stream.write_all(format!("calc {} {}\n", theta, RADIUS).as_bytes()) {
                	eprintln!("Error while sending: {}", e);
                	return;
            	}

             match stream.read(&mut buffer) {
               	Ok(n) if n > 0 => {
			let received_str = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                        let parts: Vec<&str> = received_str.split_whitespace().collect();
                	calc_send_duration = calc_send_time.elapsed().unwrap();
			let calc_end_time = SystemTime::now();
			if parts.len() == 2 {
                            if let (Ok(y), Ok(client_time)) = (
                                parts[0].parse::<f64>(),
                                parts[1].parse::<u128>()
                            ) {
				first_duration = client_time as i128 - calc_start_time.duration_since(SystemTime::UNIX_EPOCH).expect("Time before UNIX-Time").as_nanos() as i128;
				second_duration = calc_end_time.duration_since(SystemTime::UNIX_EPOCH).expect("Time before UNIX-Time").as_nanos() as i128 - client_time as i128;

			    	if calc_send_duration.as_millis() <= TIMEOUT_MS as u128 {
			    		last_y = y;
			    	} else {
			    		last_y = last_y - 2.0;
			    	}
                            } else {
                                eprintln!("Error parsing timestamps: {:?}", parts);
                            }

                        } else {
                            eprintln!("Invalid response format: '{}'", received_str);
                        }
                   },
			Ok(_) | Err(_) => eprintln!("Error while reseaving")
		}
            points.push((x, last_y));
	    hold_clock(calc_start_time);
	    
	    i += 1;
	   cycle_time = calc_start_time.elapsed().unwrap();
	   latency.push((first_duration, second_duration, calc_send_duration.as_nanos(), cycle_time.as_nanos()));
}
     	    let mut counter = disconnect_counter.lock().unwrap();
            *counter += 1;
	   
	    let result_path = format!("../results/standard_{}/frequency_{}/bandwith_{}/qos_{}", standard, frequency, bandwith, qos);
	    
	     if let Err(e) = create_dir_all(format!("{}", result_path)) {
             eprintln!("Error while creating the result directories: {}", e);
             return;
    	     }

	    let mut circle_points = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!("{}/circle_points_{}", result_path, counter))
                .unwrap()
        	);

       	     let mut latencies = BufWriter::new(
             OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(format!("{}/latencys_{}", result_path, counter))
                .unwrap()
        	);

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
                std::process::exit(0); // Beendet den Server
        }
      }
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

    println!("Usage: {}", qos);

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
                    handle_time(stream, disconnect_counter, standard, frequency, bandwith, qos);
                });
            }
            Err(e) => eprintln!("Verbindungsfehler: {}", e),
        }
    }
    Ok(())
}
