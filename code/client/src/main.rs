use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process;
use std::time::{SystemTime, Duration};
use std::f64::consts::PI;
use std::{thread, time};
use std::process::Command;

fn adjust_time(diff: u128) -> u128 {
    let adjusted_time = SystemTime::now() - Duration::from_nanos(diff as u64);
    let timestamp_ns = adjusted_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Systemtime is before UNIX-Time")
        .as_nanos();

    println!("Adjusted time is: {:?}", adjusted_time);
    timestamp_ns as u128
}

fn main() -> io::Result<()> {
    let mut difference = 0;
    let server_address = "192.168.1.1:8080";
    match TcpStream::connect(server_address) {
        Ok(mut stream) => {
            println!("Connected to server: {}", server_address);
            stream.write_all(b"start\n")?;

            let mut buffer = [0; 1024];
            let mut time_diffs = Vec::new(); 

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
                                adjust_time(difference);
                            }
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


		else if parts.len() == 2 {
   			let number = parts[0].parse::<usize>();
    			let timestamp_str = parts[1];
 
    			let timestamp_str = timestamp_str.trim_end_matches("ns");
    
    			if let (Ok(number), Ok(received_timestamp)) = (number, timestamp_str.parse::<u128>()) {
        			let current_time = SystemTime::now();
                        	let elapsed_time = current_time
					.duration_since(SystemTime::UNIX_EPOCH)
                            		.expect("Time is before UNIX time");

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

