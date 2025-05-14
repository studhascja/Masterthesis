use libbpf_rs::skel::{OpenSkel, SkelBuilder, Skel};
use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process;
use std::process::{Command, Stdio};
use std::time::{SystemTime, Duration};
use std::thread;
use anyhow::Result;

include!("bpf/monitore.skel.rs");


fn adjust_time(diff: i128) -> u128 {
    let adjusted_time = if diff >= 0 {
        SystemTime::now() - Duration::from_nanos(diff as u64)
    } else {
        SystemTime::now() + Duration::from_nanos((-diff) as u64)
    };

    let timestamp_ns = adjusted_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Systemtime is before UNIX-Time")
        .as_nanos();

    timestamp_ns as u128
}

fn main() -> Result<()> {

    let open_skel = MonitoreSkelBuilder::default().open();
    println!("Skelett geöffnet.");

    let mut skel = open_skel?.load()?;
    println!("Skelett geladen.");

    skel.attach()?;
    println!("eBPF-Programm läuft …");

    let mut difference = 0;
    let server_address = "192.168.1.1:8080";
    match TcpStream::connect(server_address) {
        Ok(mut stream) => {
            println!("Connected to server: {}", server_address);
            stream.write_all(b"start\n")?;

            let mut buffer = [0; 1024];
            let mut time_diffs: Vec<(usize, i128)> = Vec::new();   

            while let Ok(size) = stream.read(&mut buffer) {
                if size == 0 {
                    break; 
                }

                let received_str = String::from_utf8_lossy(&buffer[..size]).trim().to_string();
                let parts: Vec<&str> = received_str.split_whitespace().collect();
		 	
               if received_str.starts_with("result") {
                    let parts: Vec<&str> = received_str.split_whitespace().collect();
                    if parts.len() == 2 {
                        if let Ok(index) = parts[1].parse::<usize>() {
                            if let Some((_, diff)) = time_diffs.get(index) {
				difference = *diff;
				println!("Number: {} Difference {}", index, difference);
                                //adjust_time(difference);
                            }
                        }
                    }
                }

	       else if received_str.starts_with("calc") {
                    let parts: Vec<&str> = received_str.split_whitespace().collect();
                    if parts.len() == 3 {
                        if let (Ok(theta), Ok(radius)) = (parts[1].parse::<f64>(), parts[2].parse::<f64>()){
				let y = radius * theta.sin();
				let y_str = format!("{} {}\n", y, adjust_time(difference));
				
				if let Err(e) = stream.write_all(y_str.as_bytes()) {
					eprintln!("Error while sending the y coordinate: {}", e);
				} 
			}
                    }
                }
		
               else if received_str.starts_with("_result") {
		    println!("test");
                    let parts: Vec<&str> = received_str.split_whitespace().collect();
                    if parts.len() == 2 {
                        if let Ok(offset_diff) = parts[1].parse::<i128>() {
                            difference = difference + offset_diff;
			  println!("test");
			        thread::spawn(|| {
        				let mut status = Command::new("iperf3")
            					.arg("-c")
            					.arg("192.168.1.1")
            					.arg("-u")
            					.arg("-b")
            					.arg("15M")
            					.arg("-t")
            					.arg("12")
            					.arg("-p")
            					.arg("5202")
            					.stderr(Stdio::piped())
            					.stdout(Stdio::piped())
            					.spawn()
            					.expect("Failed to start iperf3");
	
       	 				let _ = status.wait().expect("Failed to wait for iperf3 process");
    				});
				println!("Störer ausgeführt");
                        }else {
                                        eprintln!("Error while parsing: {}", parts[1]);
                                }

                    }
                }

		else if received_str.starts_with("test") {
    			let parts: Vec<&str> = received_str.split_whitespace().collect();
    			if parts.len() == 2 {
        			let timestamp_str = parts[1].trim_end_matches("ns"); 

        			if let Ok(received_timestamp) = timestamp_str.parse::<u128>() {                       
            				let test_time = adjust_time(difference);                         
            				let diff = test_time as i128 - received_timestamp as i128;
					
					let unadjusted_time = SystemTime::now();
					let without_diff = unadjusted_time
        					.duration_since(SystemTime::UNIX_EPOCH)
        					.expect("Systemtime is before UNIX-Time")
        					.as_nanos();

            				println!("Testdifference: {} Servertime: {} Client time {} Client time without diff {}", diff, received_timestamp, test_time, without_diff);
        			} else {
            				eprintln!("Error while parsing: {}", parts[1]);
        			}
    			}
		}

		else if received_str.starts_with("ptp") {
			let time_of_arrival = adjust_time(difference);
                        let parts: Vec<&str> = received_str.split_whitespace().collect();
                        if parts.len() == 2 {
                                let timestamp_str = parts[1].trim_end_matches("ns");

                                if let Ok(received_timestamp) = timestamp_str.parse::<u128>() {
                                        let time_of_depature = adjust_time(difference);
					if let Err(e) = stream.write_all(format!("{} {} {}\n", received_timestamp, time_of_arrival, time_of_depature).as_bytes()) {
                    				eprintln!("Error while sending: {}", e);
                			}

                                 } else {
                                        eprintln!("Error while parsing: {}", parts[1]);
                                }
                        }
                }



		else if parts.len() == 2 {
   			let number = parts[0].parse::<usize>();
    			let timestamp_str = parts[1];
 
    			let timestamp_str = timestamp_str.trim_end_matches("ns");
    
    			if let (Ok(number), Ok(received_timestamp)) = (number, timestamp_str.parse::<u128>()) {
        			let current_time = SystemTime::now();
                        	let elapsed_time = current_time
					.duration_since(SystemTime::UNIX_EPOCH)
                            		.expect("Time is before UNIX-Time");

                        let diff = elapsed_time.as_nanos() as i128 - received_timestamp as i128;
                      
                        time_diffs.push((number, diff.try_into().unwrap()));
        	
			stream.write_all(b"ACK\n")?;
    			}
		} 
		else {
        		println!("Error while parsing: number={} timestamp={}", parts[0], parts[1]);
    		}
            }
        }
        Err(e) => {
            eprintln!("Error while connection to server: {}", e);
            process::exit(1);
        }
    }

    Ok(())
}

