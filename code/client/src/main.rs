use libbpf_rs::skel::{OpenSkel, SkelBuilder, Skel};
use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process;
use std::process::{Command, Stdio};
use std::time::{SystemTime, Duration};
use std::thread;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use bincode;


include!("bpf/monitore.skel.rs");

#[derive(Serialize, Deserialize, Debug)]
enum Data {
    IntegerI128(i128),
    IntegerU128(u128),
    IntegerU64(u64),
    Float(f64),
}

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug)]
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
     return Ok(encoded);
}


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
            let encoded_msg = encode_message(MessageType::Start, None, None, None, None)?;
            stream.write_all(&encoded_msg)?;

            let mut buffer = [0; 1024];
            let mut time_diffs: Vec<(u64, i128)> = Vec::new();   

            while let Ok(size) = stream.read(&mut buffer) {
                if size == 0 {
                    break; 
                }
		let msg: Message = bincode::deserialize(&buffer[..size]).expect("Deserialization failed");
		
		match msg.msg_type {
			MessageType::Start => {
			println!("Error: Start should not be sent to client");
			},
			MessageType::NTP => {
				let number = msg.seq;
				let timestamp = msg.timestamp;
				let current_time = SystemTime::now();
                                let elapsed_time = current_time
                                        .duration_since(SystemTime::UNIX_EPOCH)
                                        .expect("Time is before UNIX-Time");
				if let Some(ts) = timestamp {
					let diff = elapsed_time.as_nanos() as i128 - ts as i128;
					time_diffs.push((number.expect("Sequence-Number is empty"), diff.try_into().unwrap()));
				}
				let encoded_msg = encode_message(MessageType::NTP, number, None, None, None)?;
				stream.write_all(&encoded_msg);

			}, 
			MessageType::NTP_Result => {
				let index = msg.primary_data;
				if let Some(Data::IntegerU64(i)) = index {
					if let Some((_, diff)) = time_diffs.get(i as usize) {
                                		difference = *diff;
                                		println!("Number: {} Difference {}", i, difference);
                            		}
				}
			},
			MessageType::PTP => {
				let time_of_arrival = adjust_time(difference);
				let received_timestamp = msg.timestamp;
				let time_of_depature = adjust_time(difference);
				let encoded_msg = encode_message(MessageType::PTP, msg.seq, Some(time_of_depature), Some(Data::IntegerU128(received_timestamp.expect("Received Timestamp empty"))), Some(Data::IntegerU128(time_of_arrival)))?;
				stream.write_all(&encoded_msg);	
			}, 
			MessageType::PTP_Result => {
				let offset_diff = msg.primary_data;
  				if let Some(Data::IntegerI128(offset_diff)) = offset_diff {
					difference = difference + offset_diff;
				}
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

			},
			MessageType::Calc => {
				if let (Some(Data::Float(theta)), Some(Data::Float(radius))) =
				(msg.primary_data, msg.secondary_data) {
					let y = radius * theta.sin();
					let encoded_msg = encode_message(MessageType::Calc, msg.seq, Some(adjust_time(difference)), Some(Data::Float(y)), None)?;
					if let Err(e) = stream.write_all(&encoded_msg) {
                                        eprintln!("Error while sending the y coordinate: {}", e);
                                } 

				}
			}
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
