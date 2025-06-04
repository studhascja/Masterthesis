use libbpf_rs::skel::{OpenSkel, SkelBuilder, Skel};
use libbpf_rs::{RingBufferBuilder, Program, UprobeOpts};
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::OnceLock;
use std::env;
use std::time::Instant;
use std::collections::VecDeque;
use once_cell::sync::Lazy;

static CURRENT_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static CURRENT_QUEUE_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));

static USER_ZERO: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
static TEST: OnceLock<Instant> = OnceLock::new();

include!("bpf/monitore.skel.rs");

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
    event_type: u8,
    _padding: [u8; 7],
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

#[no_mangle]
pub extern "C" fn measure_instant() -> Instant {
    Instant::now()
}

pub fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

fn wait_for_queue_event(timestamp: u64) -> Option<Event> {
let mut queue_arc = CURRENT_QUEUE_EVENT.get().expect("CURRENT_QUEUE_EVENT not initialized");
let count = *MESSAGE_COUNT.lock().unwrap() as usize;

let mut queue = queue_arc.lock().unwrap();
for i in 1..queue.len() {
        if queue.len() >= count && (queue[queue.len() - i].timestamp - get_kernel_zero()) < timestamp {
                return Some(queue[queue.len() - i].clone());
        }
        thread::sleep(Duration::from_nanos(50));
    }
println!("Falsch");
return None;
}

fn wait_for_event(number: u64, msg_t: MessageType, event_t: u8) -> Event {
        let mut queue_arc = CURRENT_EVENT.get().expect("CURRENT_EVENT not initialized");
        loop {
        {
            let mut queue = queue_arc.lock().unwrap();
            while let Some(evt) = queue.pop_front() {
                if let Ok(msg_type) = MessageType::try_from(evt.data.msg_type) {
                    if msg_type == msg_t && evt.data.seq == number && evt.event_type == event_t {
                        return evt;
                    }
                }
            }
        }
        thread::sleep(Duration::from_nanos(50));
    }
}

fn set_kernel_zero(value: u64) {
    let mut kernel = KERNEL_ZERO.lock().unwrap();
    *kernel = value;
}

fn get_kernel_zero() -> u64 {
    let kernel = KERNEL_ZERO.lock().unwrap();
    *kernel
}

fn update_user_zero() {
    let mut time = USER_ZERO.lock().unwrap();
    *time = measure_instant();
}

fn read_user_zero() -> Instant {
    let time = USER_ZERO.lock().unwrap();
    *time
}


fn main() -> Result<()> {
    let event_queue = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));

    CURRENT_EVENT.set(event_queue.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    let event_ref = CURRENT_EVENT.get().expect("CURRENT_EVENT not initialized");
    let queue_event_ref = CURRENT_QUEUE_EVENT.get().expect("CURRENT_EVENT not initialized");


    let mut client_sent_time = 0;
    let mut client_queue_time = 0;

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
	if event.event_type == 0 {
            set_kernel_zero(event.timestamp);
        }
	else if event.event_type == 3 {
            let mut queue = queue_event_ref.lock().unwrap();
            queue.push_back(*event);
        }
        else {
                let mut queue = event_ref.lock().unwrap();
                queue.push_back(*event);

        }


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

	}*/
	0 
    })?;
    let mut ringbuf = ringbuf_builder.build()?;

// Separate Thread für Polling des Ringbuffers starten
let handle = thread::spawn(move || {
      while r.load(Ordering::Relaxed) {
        ringbuf.poll(Duration::from_millis(100)).unwrap();
    }
});
    let mut difference = 0;
    let server_address = "192.168.1.1:8080";
    match TcpStream::connect(server_address) {
        Ok(mut stream) => {
            println!("Connected to server: {}", server_address);
            let encoded_msg = encode_message(MessageType::Start, 0, 0, 0, 0, 0.0, 0.0, 0)?;
            stream.write_all(&encoded_msg)?;
	    increment_message_count();

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
				update_user_zero();
				let number = msg.seq;
        			let encoded_msg = encode_message(MessageType::NTP, number, 0, 0, 0, 0.0, 0.0, 0)?;
				stream.write_all(&encoded_msg)?;
				increment_message_count();	
			}, 
			Ok(MessageType::NTP_Result) => {
				//let test = unsafe{measure_instant()};
				//TEST.get_or_init(|| test);
				let number = msg.seq;
                                let event_snapshot = wait_for_event(number, MessageType::NTP_Result, 1);
				let client_receive = event_snapshot.timestamp - get_kernel_zero();

                                let received_timestamp = msg.timestamp;
                                let now = Instant::now();
                                let time_of_depature = now.duration_since(read_user_zero());
                                let encoded_msg = encode_message(MessageType::NTP_Result, msg.seq, client_sent_time, received_timestamp, client_receive.into(), 0.0, 0.0, 0)?;
                                stream.write_all(&encoded_msg);
				increment_message_count();
				let event_snapshot_send = wait_for_event(number, MessageType::NTP_Result, 2);
				client_sent_time = (event_snapshot_send.timestamp - get_kernel_zero()) as u128;
			},
			Ok(MessageType::PTP) => {
				update_user_zero();
                                let number = msg.seq;
                                let encoded_msg = encode_message(MessageType::PTP, number, 0, 0, 0, 0.0, 0.0, 0)?;
                                stream.write_all(&encoded_msg)?;
				increment_message_count();
			}, 
			Ok(MessageType::PTP_Result) => {
				let offset_diff = msg.i_val;
  				difference = difference + offset_diff;
		/*
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
                                });*/
                                println!("Störer ausgeführt");
			},

			Ok(MessageType::Calc) => {
				if let (theta, radius) =
				(msg.first_f64, msg.second_f64) {
					let y = radius * theta.sin();
					let number = msg.seq;
                                	let event_snapshot = wait_for_event(number, MessageType::Calc, 1);
                                	let client_receive = event_snapshot.timestamp - get_kernel_zero();

					let encoded_msg = encode_message(MessageType::Calc, msg.seq, client_queue_time as u128, client_receive as u128, client_sent_time as u128, y, 0.0, 0)?;
					if let Err(e) = stream.write_all(&encoded_msg) {
                                        	eprintln!("Error while sending the y coordinate: {}", e);
                                	}
					increment_message_count();

					let event_snapshot_send = wait_for_event(number, MessageType::Calc, 2);
	                                client_sent_time = (event_snapshot_send.timestamp - get_kernel_zero()) as u128;
						
					let event_snapshot_queue = wait_for_queue_event(client_sent_time as u64);
                                        client_queue_time = (event_snapshot_queue.unwrap().timestamp - get_kernel_zero()) as u128
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

