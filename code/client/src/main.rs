use libbpf_rs::skel::{OpenSkel, SkelBuilder, Skel};
use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process;
use std::process::{Command, Stdio};
use std::time::{SystemTime, Duration};
use std::thread;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use bytemuck::{Pod, Zeroable, bytes_of, from_bytes};
use std::convert::TryFrom;
use std::mem::{MaybeUninit, align_of};

include!("bpf/monitore.skel.rs");

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

#[repr(C)]
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
            let encoded_msg = encode_message(MessageType::Start, 0, 0, 0, 0, 0.0, 0.0, 0)?;
            stream.write_all(&encoded_msg)?;

            let mut buffer = [0u8; std::mem::size_of::<Message>()];
            let mut time_diffs: Vec<(u64, i128)> = Vec::new();   

            while let Ok(size) = stream.read(&mut buffer) {
                if size == 0 {
                    break; 
                }
		
		
		let mut raw = MaybeUninit::<Message>::uninit();
    		let raw_ptr = raw.as_mut_ptr() as *mut u8;

    		unsafe {
        		std::ptr::copy_nonoverlapping(
            		buffer.as_ptr(),
            		raw_ptr,
            		std::mem::size_of::<Message>(),
        	);
		

        	let msg = raw.assume_init();
		
		
		match MessageType::try_from(msg.msg_type) {
			Ok(MessageType::Start) => {
			println!("Error: Start should not be sent to client");
			},
			Ok(MessageType::NTP) => {
				let number = msg.seq;
				let timestamp = msg.timestamp;
				let current_time = SystemTime::now();
                                let elapsed_time = current_time
                                        .duration_since(SystemTime::UNIX_EPOCH)
                                        .expect("Time is before UNIX-Time");
				let diff = elapsed_time.as_nanos() as i128 - timestamp as i128;
				time_diffs.push((number, diff.try_into().unwrap()));
				
				let encoded_msg = encode_message(MessageType::NTP, number, 0, 0, 0, 0.0, 0.0, 0)?;
				stream.write_all(&encoded_msg);

			}, 
			Ok(MessageType::NTP_Result) => {
				let index = msg.first_u128;
			 	if let Some((_, diff)) = time_diffs.get(index as usize) {
                                		difference = *diff;
                                		println!("Number: {} Difference {}", index, difference);
                            	}
			},
			Ok(MessageType::PTP) => {
				let time_of_arrival = adjust_time(difference);
				let received_timestamp = msg.timestamp;
				let time_of_depature = adjust_time(difference);
				let encoded_msg = encode_message(MessageType::PTP, msg.seq, time_of_depature, received_timestamp, time_of_arrival, 0.0, 0.0, 0)?;
				stream.write_all(&encoded_msg);	
			}, 
			Ok(MessageType::PTP_Result) => {
				let offset_diff = msg.i_val;
  				difference = difference + offset_diff;
		
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
			Ok(MessageType::Calc) => {
				if let (theta, radius) =
				(msg.first_f64, msg.second_f64) {
					let y = radius * theta.sin();
					let encoded_msg = encode_message(MessageType::Calc, msg.seq, adjust_time(difference), 0, 0, y, 0.0, 0)?;
					if let Err(e) = stream.write_all(&encoded_msg) {
                                        eprintln!("Error while sending the y coordinate: {}", e);
                                } 

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

