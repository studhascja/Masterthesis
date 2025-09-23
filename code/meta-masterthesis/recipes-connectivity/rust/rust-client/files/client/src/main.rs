use anyhow::Result;
use bytemuck::{bytes_of, from_bytes, Pod, Zeroable};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use libc::{
    pthread_self, pthread_setschedparam, sched_param, sched_setscheduler, SCHED_OTHER, SCHED_RR,
};
use std::env;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    convert::TryFrom,
    fs::OpenOptions,
    io::{Read, Write},
    mem::MaybeUninit,
    net::TcpStream,
    os::unix::process::CommandExt,
    process::{self, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

include!("bpf/monitore.skel.rs");

// Global state
static CURRENT_EVENT_REC: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static CURRENT_EVENT_SEND: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
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
    tcp_seq: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Event {
    event_type: u8,
    _padding: [u8; 7],
    timestamp: u64,
    pid: u32,
    _padding_pid: [u8; 4],
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


fn read_user_zero() -> Instant {
    *USER_ZERO.lock().unwrap()
}

fn wait_for_event(seq: u64, msg_type: MessageType, event_type: u8) -> Option<Event> {
    let start = Instant::now();
    let queue;
    if event_type == 1 {
        queue = CURRENT_EVENT_REC
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone();
    } else if event_type ==2 {
        queue = CURRENT_EVENT_SEND
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone();
    } else {
           queue = CURRENT_QUEUE_EVENT
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone();
    }
    loop {
        if start.elapsed() > Duration::from_millis(10) {
            println!("Nix: {}", event_type);
            return None;
        }
        let mut queue_lock = queue.lock().unwrap();
        //println!("Message Queue length: {}", queue_lock.len());
        if let Some(pos) = queue_lock.iter().position(|event| {
            let Ok(t) = MessageType::try_from(event.data.msg_type);
            t == msg_type && event.data.seq == seq && event.event_type == event_type
        }) {
            let result = Some(queue_lock.remove(pos).unwrap());
            queue_lock.clear();
            return result;
        }

        drop(queue_lock);
        thread::sleep(Duration::from_nanos(5));
    }
}

fn main() -> Result<()> {
    set_rt_priority(99);

    let event_queue_rec = Arc::new(Mutex::new(VecDeque::new()));
    let event_queue_send = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));
    CURRENT_EVENT_REC.set(event_queue_rec.clone()).unwrap();
    CURRENT_EVENT_SEND.set(event_queue_send.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    // Initialize and load BPF skeleton
    let open_skel = MonitoreSkelBuilder::default().open()?;
    println!("✅ BPF skeleton opened.");
    let mut skel = open_skel.load()?;
    println!("✅ BPF skeleton loaded.");
    skel.attach()?;
    println!("✅ eBPF program attached and running.");

    let event_ref_rec = CURRENT_EVENT_REC.get().unwrap().clone();
    let event_ref_send = CURRENT_EVENT_SEND.get().unwrap().clone();
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

         let my_pid = std::process::id() as u32;
        match event.event_type{
            0 if event.pid == my_pid => {
                let diff = Instant::now().duration_since(read_user_zero()).as_nanos() as i128;
                let timestamp = event.timestamp;
                set_kernel_zero(timestamp);
            }
            1 if event.pid == my_pid => {
                let mut queue = event_ref_rec.lock().unwrap();
                queue.push_back(event);
            }
            2 if event.pid == my_pid => {
                let mut queue = event_ref_send.lock().unwrap();
                queue.push_back(event);
            }
            3 if event.pid == my_pid => {
                let mut queue = queue_event_ref.lock().unwrap();
                queue.push_back(event);
            }
            _ => {
                let r_pid = event.pid;
                let n_pid = my_pid;
                eprintln!("⚠️ Unknown event type: {} {} {}", event.event_type, r_pid, n_pid);
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

    let args: Vec<String> = env::args().collect();
    let iperf_o= Arc::new(args[1].clone());
    let time_c_o= Arc::new(args[2].clone());
    let size_p_o= Arc::new(args[3].clone());
    // Connect to server
    let server_addr = "192.168.1.1:8080";
    let mut _difference = 0;

    match TcpStream::connect(server_addr) {
        Ok(mut stream) => {
            println!("✅ Connected to server at {}", server_addr);

            // Send initial START message
            let start_msg = encode_message(MessageType::Start, 0, 0, 0, 0, 0.0, 0.0, 0)?;
            stream.write_all(&start_msg)?;
            increment_message_count();

            let mut buffer = [0u8; std::mem::size_of::<Message>()];
            let mut client_sent_time = 0u128;
            let mut client_sent_time_calc = 0u128;
            let mut client_queue_time_calc = 0u128;

            while let Ok(size) = stream.read(&mut buffer) {
                if size == 0 {
                    break;
                }
		
                let iperf = Arc::clone(&iperf_o);
    		let time_c = Arc::clone(&time_c_o);
            let size_p = Arc::clone(&size_p_o);

		// Deserialize incoming message
                let mut raw = MaybeUninit::<Message>::uninit();
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        raw.as_mut_ptr() as *mut u8,
                        std::mem::size_of::<Message>(),
                    );
                    let msg = raw.assume_init();

                    match MessageType::try_from(msg.msg_type) {
                        Ok(MessageType::Start) => {
                            println!("⚠️ Received unexpected Start message from server.");
                        }
                        Ok(MessageType::NTP) => {
                            update_user_zero();
                            let encoded =
                                encode_message(MessageType::NTP, msg.seq, 0, 0, 0, 0.0, 0.0, 0)?;
                            stream.write_all(&encoded)?;
                            increment_message_count();
                        }
                        Ok(MessageType::NtpResult) => {
                            let seq = msg.seq;
                            let mut client_recv =
                                Instant::now().duration_since(read_user_zero()).as_nanos() as u64;

                            if let Some(event) = wait_for_event(seq, MessageType::NtpResult, 1) {
                                client_recv = event.timestamp - get_kernel_zero();
                            }
                            let kernel = get_kernel_zero();

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
                            stream.write_all(&encoded)?;
                            increment_message_count();

                            client_sent_time =
                                Instant::now().duration_since(read_user_zero()).as_nanos() as u128;

                            if let Some(event) = wait_for_event(seq, MessageType::NtpResult, 2) {
                                client_sent_time = (event.timestamp - get_kernel_zero()) as u128;
                            }
                            //    println!("durchgekommen");
                        }
                        Ok(MessageType::PTP) => {
                            update_user_zero();
                            let encoded =
                                encode_message(MessageType::PTP, msg.seq, 0, 0, 0, 0.0, 0.0, 0)?;
                            stream.write_all(&encoded)?;
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
                                thread::spawn(move || {
                                    let mut command = Command::new("iperf3");
                                    let _ = command
                                        .args([
                                            "-c",
                                            "192.168.1.1",
                                            "-u",
                                            "-b",
                                            &iperf,
                                            "-t",
                                            &time_c,
                                            "-l",
                                            &size_p,
                                            "-p",
                                            "5202",
                                        ])
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
                            let mut client_recv =
                                start.duration_since(read_user_zero()).as_nanos() as u64;

                            if let Some(event) = wait_for_event(seq, MessageType::Calc, 1) {
                                client_recv = event.timestamp - get_kernel_zero();
                            }

                            let encoded = encode_message(
                                MessageType::Calc,
                                seq,
                                client_queue_time_calc,
                                client_recv as u128,
                                client_sent_time_calc,
                                y,
                                0.0,
                                0,
                            )?;
                            stream.write_all(&encoded)?;
                            increment_message_count();

                            client_sent_time_calc =
                                Instant::now().duration_since(read_user_zero()).as_nanos() as u128;
                            let mut tcp_seq = 0 as u64;
                            if let Some(event) = wait_for_event(seq, MessageType::Calc, 2) {
                                client_sent_time_calc = (event.timestamp - get_kernel_zero()) as u128;
                                tcp_seq = event.data.tcp_seq;
                            } else{
                                println!("No matching send event found for seq {}", seq);
                            }
                            
                            let duration_queue = start.elapsed();
                            let queue_event = wait_for_event(tcp_seq, MessageType::Calc, 3);
                            if let Some(evt) = queue_event {
                                 client_queue_time_calc = (evt.timestamp - get_kernel_zero()) as u128;
                            }

                            let duration = start.elapsed();
                            if duration.as_millis() > 2 {
                                println!("⚠️ Calc function took {:.4?} ms", duration);
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
        }
        Err(e) => {
            eprintln!("❌ Could not connect to server: {}", e);
            process::exit(1);
        }
    }

    running.store(false, Ordering::Relaxed);
    let _ = poll_thread.join();
    Ok(())
}
