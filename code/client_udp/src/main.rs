use std::{
    convert::TryFrom,
    fs::OpenOptions,
    io::{Read, Write},
    mem::{MaybeUninit},
    net::UdpSocket,
    process::{self, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
    collections::VecDeque,
    os::unix::process::CommandExt
};
use anyhow::Result;
use bytemuck::{bytes_of, from_bytes, Pod, Zeroable};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use libc::{sched_param, pthread_setschedparam, pthread_self, SCHED_OTHER, SCHED_RR, sched_setscheduler};

include!("bpf/monitore.skel.rs");

// Global state
static CURRENT_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static CURRENT_QUEUE_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));
static USER_ZERO: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
//static TEST: OnceLock<Instant> = OnceLock::new();

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum MessageType {
    Start = 0,
    NTP = 1,
    NtpResult = 2,
    PTP = 3,
    PtpResult = 4,
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

// Convert u8 to MessageType
impl TryFrom<u8> for MessageType {
    type Error = std::convert::Infallible;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => MessageType::Start,
            1 => MessageType::NTP,
            2 => MessageType::NtpResult,
            3 => MessageType::PTP,
            4 => MessageType::PtpResult,
            5 => MessageType::Calc,
            _ => panic!("Invalid MessageType value: {}", value),
        })
    }
}

// Encodes a message struct into a byte vector
fn encode_message(
    msg_type: MessageType,
    seq: u64,
    timestamp: u128,
    first_u128: u128,
    second_u128: u128,
    first_f64: f64,
    second_f64: f64,
    i_val: i128,
) -> Result<Vec<u8>> {
    let msg = Message {
        msg_type: msg_type as u8,
        seq,
        timestamp,
        first_u128,
        second_u128,
        first_f64,
        second_f64,
        i_val,
        _padding: [0u8; 7],
    };

    Ok(bytes_of(&msg).to_vec())
}

// Set real-time thread priority using SCHED_RR
fn set_rt_priority(priority: i32) {
    unsafe {
        let mut param = sched_param {
            sched_priority: priority,
        };
        if pthread_setschedparam(pthread_self(), SCHED_RR, &mut param) != 0 {
            eprintln!("⚠️ Failed to set RT priority.");
        } else {
            println!("✅ RT priority set to {}", priority);
        }
    }
}

// Notify external process (e.g., Python script)
fn notify_python() {
    if let Ok(mut pipe) = OpenOptions::new().write(true).open("/tmp/notify_pipe") {
        let _ = writeln!(pipe, "START");
    } else {
        eprintln!("⚠️ Could not open /tmp/notify_pipe.");
    }
}

#[no_mangle]
pub extern "C" fn measure_instant() {
    let mut time = USER_ZERO.lock().unwrap();
    *time = Instant::now();
}

// Atomic message counter
fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

// Global time helpers
fn set_kernel_zero(value: u64) {
    let mut kernel = KERNEL_ZERO.lock().unwrap();
    *kernel = value;
}

fn get_kernel_zero() -> u64 {
    *KERNEL_ZERO.lock().unwrap()
}

fn update_user_zero() {
    measure_instant();
}

/*
fn read_user_zero() -> Instant {
    *USER_ZERO.lock().unwrap()
}
*/
fn wait_for_event(seq: u64, msg_type: MessageType, event_type: u8) -> Event {
    let queue = CURRENT_EVENT
        .get()
        .expect("CURRENT_EVENT not initialized")
        .clone();

    loop {
        {
            let mut queue_lock = queue.lock().unwrap();
            while let Some(event) = queue_lock.pop_front() {
                 let Ok(t) = MessageType::try_from(event.data.msg_type);
                    if t == msg_type && event.data.seq == seq && event.event_type == event_type {
                        return event;
                    }
            }
        }
        thread::sleep(Duration::from_nanos(5));
    }
}

fn wait_for_queue_event(timestamp: u64) -> Option<Event> {
    let queue = CURRENT_QUEUE_EVENT
        .get()
        .expect("CURRENT_QUEUE_EVENT not initialized")
        .clone();

    let count = *MESSAGE_COUNT.lock().unwrap() as usize;

    let queue_lock = queue.lock().unwrap();
    for i in 1..queue_lock.len() {
        let idx = queue_lock.len() - i;
        let event = &queue_lock[idx];
        if queue_lock.len() >= count.saturating_sub(3)
            && (event.timestamp - get_kernel_zero()) < timestamp
        {
            return Some(event.clone());
        }

        thread::sleep(Duration::from_nanos(5));
    }

    queue_lock.back().cloned()
}


fn main() -> Result<()> {
    set_rt_priority(99);
    let mut _difference = 0;
    let event_queue = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));
    CURRENT_EVENT.set(event_queue.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    // Initialize and load BPF skeleton
    let open_skel = MonitoreSkelBuilder::default().open()?;
    println!("✅ BPF skeleton opened.");
    let mut skel = open_skel.load()?;
    println!("✅ BPF skeleton loaded.");
    skel.attach()?;
    println!("✅ eBPF program attached and running.");

    let event_ref = CURRENT_EVENT.get().unwrap().clone();
    let queue_event_ref = CURRENT_QUEUE_EVENT.get().unwrap().clone();
    let running = Arc::new(AtomicBool::new(true));
    let maps = skel.maps();

    // Setup ring buffer with callback
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(maps.events(), move |data: &[u8]| {
        if data.len() != std::mem::size_of::<Event>() {
            eprintln!("⚠️ Invalid event size: {}", data.len());
            return 0;
        }

        let event = *from_bytes::<Event>(data);

        match event.event_type {
            0 => set_kernel_zero(event.timestamp),
            3 => {
                let mut queue = queue_event_ref.lock().unwrap();
                queue.push_back(event);
            }
            _ => {
                let mut queue = event_ref.lock().unwrap();
                queue.push_back(event);
            }
        }

        0
    })?;

    let ringbuf = ringbuf_builder.build()?;

    // Start polling thread for ring buffer
    let ring_running = running.clone();
    let poll_thread = thread::spawn(move || {
        while ring_running.load(Ordering::Relaxed) {
            ringbuf.poll(Duration::from_millis(100)).unwrap();
        }
    });
 
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.168.1.1:8080")?;
    // Send Start message
    let start_msg = encode_message(MessageType::Start, 0, 0, 0, 0, 0.0, 0.0, 0)?;
    socket.send(&start_msg)?;
    increment_message_count();

    let mut buf = [0u8; std::mem::size_of::<Message>()];
    let mut client_sent_time = 0u128;
    let mut client_queue_time = 0u128;

    loop {
        let size = socket.recv(&mut buf)?;
        if size == 0 {
            break;
        }

        let mut raw = MaybeUninit::<Message>::uninit();
        let ptr = raw.as_mut_ptr() as *mut u8;
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, size);
            let msg = raw.assume_init();
		
            match MessageType::try_from(msg.msg_type) {
	        Ok(MessageType::Start) => {
                    println!("⚠️ Received unexpected Start message from server.");
                }
                Ok(MessageType::NTP) => {
	            update_user_zero();
                    let encoded = encode_message(MessageType::NTP, msg.seq, 0, 0, 0, 0.0, 0.0, 0)?;
                    socket.send(&encoded)?;
                    increment_message_count();
                }
                Ok(MessageType::NtpResult) => {
			let seq = msg.seq;
                        let event = wait_for_event(seq, MessageType::NtpResult, 1);
                        let client_recv = event.timestamp - get_kernel_zero();

                            //let duration = Instant::now().duration_since(read_user_zero());
                        let encoded = encode_message(
                            MessageType::NtpResult,
                            seq,
                            client_sent_time,
                            msg.timestamp,
                            client_recv as u128,
                            0.0,
                            0.0,
                            0,
                        )?;
                        socket.send(&encoded)?;
                        increment_message_count();
			let send_event = wait_for_event(seq, MessageType::NtpResult, 2);
                        client_sent_time = (send_event.timestamp - get_kernel_zero()) as u128;
                    }
                        Ok(MessageType::PTP) => {
                            update_user_zero();
                            let encoded = encode_message(MessageType::PTP, msg.seq, 0, 0, 0, 0.0, 0.0, 0)?;
                            socket.send(&encoded)?;
                            increment_message_count();
                        }
                        Ok(MessageType::PtpResult) => {
				_difference += msg.i_val;
                        }
                        Ok(MessageType::Calc) => {
                            let (theta, radius) = (msg.first_f64, msg.second_f64);
                            let y = radius * theta.sin();
                            let seq = msg.seq;

                            // Launch iperf3 in background
                            if seq == 0 {
                                thread::spawn(|| {
                                    let mut command = Command::new("iperf3");
                                    let _ = command
                                        .args(["-c", "192.168.1.1", "-u", "-b", "15M", "-t", "12", "-p", "5202"])
                                        .stderr(Stdio::piped())
                                        .stdout(Stdio::piped())
                                        .pre_exec(|| {
                                            let param = sched_param { sched_priority: 0 };
                                            let ret = sched_setscheduler(0, SCHED_OTHER, &param);
                                            if ret != 0 {
                                                return Err(std::io::Error::last_os_error());
                                            }
                                            Ok(())
                                        })
                                        .spawn()
                                        .and_then(|mut child| {
                                            notify_python();
                                            child.wait()?;
                                            Ok(())
                                        });
                                });
                            }

                            let start = Instant::now();
                            let recv_event = wait_for_event(seq, MessageType::Calc, 1);
                            let client_recv = recv_event.timestamp - get_kernel_zero();

                            let encoded = encode_message(
                                MessageType::Calc,
                                seq,
                                client_queue_time,
                                client_recv as u128,
                                client_sent_time,
                                y,
                                0.0,
                                0,
                            )?;
                            socket.send(&encoded)?;
                            increment_message_count();

                            let send_event = wait_for_event(seq, MessageType::Calc, 2);
                            client_sent_time = (send_event.timestamp - get_kernel_zero()) as u128;
			    let duration_queue = start.elapsed();

                            let queue_event = wait_for_queue_event(client_sent_time as u64);
                            if let Some(evt) = queue_event {
                                client_queue_time = (evt.timestamp - get_kernel_zero()) as u128;
                            }

                            let duration = start.elapsed();
                            if duration.as_millis() > 2 {
                                println!("⚠️ Calc function took {:.4?} ms", duration);
				println!(" ^z   ^o Calc function without queue took {:.4?} ms", duration_queue);
                            }
			    if seq == u64::MAX {
				break;
			    }
                        }
                        Err(_) => {
                            eprintln!("⚠️ Unknown message type: {}", msg.msg_type);
                        }
                    }
                }
            }
    Ok(())
}
