use std::fs::OpenOptions;
use std::io::{self, Read, Write, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime};
use std::f64::consts::PI;

const TIMEOUT_MS: u64 = 3; 
const NUM_POINTS: usize = 1000; 
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

fn handle_time(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    let mut latencies = Vec::with_capacity(NUM_POINTS);

    if let Ok(n) = stream.read(&mut buffer) {
        let msg = String::from_utf8_lossy(&buffer[..n]);
        if msg.trim() == "start" {
            println!("Time synchronisation started");

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
                        latencies.push(duration.as_nanos());

                
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
		
	    thread::sleep(Duration::from_millis(50));

	    if let Err(e) = stream.write_all(format!("test {}\n", get_time_stamp()).as_bytes()) {
                eprintln!("Error while sending: {}", e);
            }

	    let mut offsets = Vec::with_capacity(NUM_POINTS);

	    //PTP Mechanism
	    for i in 0..NUM_POINTS {
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

				let mut offset_diff = 0;
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

	    if let Err(e) = stream.write_all(format!("result2 {}\n", result_offset).as_bytes()) {
            	eprintln!("Error while sending result: {}", e);
            }

	    let mut control_values = Vec::with_capacity(NUM_POINTS);

	    	    //Test
	    for i in 0..NUM_POINTS {
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
           println!("AVG-Error: {}", avg_error);

            let mut latencies_file = BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("../latencys")
                    .unwrap()
            );

            for latency in latencies {
                writeln!(latencies_file, "{}", latency).unwrap();
            }

            latencies_file.flush().unwrap();
            println!("Latenzen wurden in Datei gespeichert.");
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    let mut points = Vec::with_capacity(NUM_POINTS);
    let mut latency = Vec::with_capacity(NUM_POINTS);

    if let Ok(n) = stream.read(&mut buffer) {
        let msg = String::from_utf8_lossy(&buffer[..n]);
        if msg.trim() == "start" {
            println!("Berechnung gestartet...");
            let mut last_y = 0.0;
            let mut duration = Duration::ZERO;

            for i in 0..NUM_POINTS {
                let theta = 2.0 * PI * (i as f64) / (NUM_POINTS as f64);
                let x = RADIUS * theta.cos();

                thread::sleep(Duration::from_millis(TIMEOUT_MS));
                let start_time = SystemTime::now();
                if let Err(e) = stream.write_all(format!("{} {}\n", theta, RADIUS).as_bytes()) {
                    eprintln!("Fehler beim Senden: {}", e);
                    return;
                }

                match stream.read(&mut buffer) {
                    Ok(n) if n > 0 => {
                        duration = start_time.elapsed().unwrap();

                        if duration.as_millis() > TIMEOUT_MS as u128 {
                            println!("Timeout überschritten, alter y-Wert verwendet");
                        } else {
                            if let Ok(y) = String::from_utf8_lossy(&buffer[..n]).trim().parse::<f64>() {
                                last_y = y;
                            }
                        }
                    }
                    _ => println!("Fehler beim Empfang oder keine Antwort erhalten"),
                }

                points.push((x, last_y));
                latency.push(duration.as_nanos());
            }

            let mut circle_points = BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("../circle_points")
                    .unwrap()
            );

            let mut latencies = BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("../latencys")
                    .unwrap()
            );

            for (x, y) in points {
                writeln!(circle_points, "{},{}", x, y).unwrap();
            }

            for l in latency {
                writeln!(latencies, "{}", l).unwrap();
            }

            circle_points.flush().unwrap();
            latencies.flush().unwrap();

            println!("Points and Latencies written.");
        }
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("192.168.1.1:8080")?;
    println!("Server läuft auf 192.168.1.1:8080");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_time(stream);
                });
            }
            Err(e) => eprintln!("Verbindungsfehler: {}", e),
        }
    }
    Ok(())
}
