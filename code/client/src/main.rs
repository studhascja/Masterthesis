use anyhow::Result;
use bytemuck::{bytes_of, from_bytes, Pod, Zeroable};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use libc::{
    mlockall, pthread_self, pthread_setschedparam, sched_param, sched_setscheduler, MCL_CURRENT,
    MCL_FUTURE, SCHED_OTHER, SCHED_RR,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
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

// Generated eBPF skeleton (libbpf-rs)
// This file provides access to the mapped tracepoints
include!("bpf/monitore.skel.rs");

// ============================================================================
// Global State
// ============================================================================

/// Queue for netif_receive_skb tracepoint events
static CURRENT_EVENT_REC: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

/// Queue for net_dev_xmit tracepoint events
static CURRENT_EVENT_SEND: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

/// Queue for net_dev_queue tracepoint events
static CURRENT_QUEUE_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

/// Global message sequence counter
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));

/// Reference timestamp in user space
static USER_ZERO: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

/// Reference timestamp in kernel space
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

// ============================================================================
// Protocol Definitions
// ============================================================================

/// Application-level message types exchanged via TCP.
///
/// Values are serialized as `u8` and must remain stable.
#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum MessageType {
    /// Initial handshake message
    Start = 0,

    /// Network Time Protocol request
    NTP = 1,

    /// For Checkphase, to test the result of NTP and PTP
    NtpResult = 2,

    /// Precision Time Protocol request
    PTP = 3,

    /// PTP result message
    PtpResult = 4,

    /// RT Phase (Calcuation)
    Calc = 5,
}

/// Structure of sent messages.
///
/// Not all fields are necessary for all phases.
#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Message {
    /// Generic timestamp field
    timestamp: u128,

    /// First 128-bit integer payload (Timestamps of Client/Server)
    first_u128: u128,

    /// Second 128-bit integer payload (Timestamps of Client/Server)
    second_u128: u128,

    /// Signed integer value (used for latency accumulation)
    i_val: i128,

    /// First floating-point payload (Y-Value / Theta for Calc phase)
    first_f64: f64,

    /// Second floating-point payload (Radius for Calc phase)
    second_f64: f64,

    /// Message sequence number
    seq: u64,

    /// Encoded MessageType
    msg_type: u8,

    /// Padding for alignment
    _padding: [u8; 7],
}

// ============================================================================
// eBPF Data Structures
// ============================================================================

/// Data portion of an eBPF event.
///
/// This structure is embedded inside `Event`.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct BpfData {
    /// Encoded MessageType
    msg_type: u8,

    /// Padding for alignment
    _padding: [u8; 7],

    /// Message sequence number
    seq: u64,

    /// TCP sequence number (from kernel)
    tcp_seq: u64,
}

/// Event emitted from the eBPF program through the ring buffer.
///
/// Each event corresponds to a network-related kernel activity.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Event {
    /// Kernel-defined event type
    event_type: u8,

    /// Padding for alignment
    _padding: [u8; 7],

    /// Kernel timestamp in nanoseconds
    timestamp: u64,

    /// Process ID associated with this event
    pid: u32,

    /// Padding for alignment
    _padding_pid: [u8; 4],

    /// Embedded event-specific data
    data: BpfData,
}

// ============================================================================
// Utility Implementations
// ============================================================================

/// Convert a raw `u8` value into `MessageType`.
///
/// Panics if an invalid value is received.
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

// ============================================================================
// Message Encoding
// ============================================================================

/// Serialize a `Message` into a byte buffer suitable for TCP transmission.
///
/// Uses zero-copy encoding via `bytemuck`.
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

// ============================================================================
// Real-Time Scheduling
// ============================================================================

/// Elevates the current thread to real-time priority using `SCHED_RR`.
///
/// This will be tested in the Test Suite
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

// ============================================================================
// External Notification
// ============================================================================

/// Notify Client Test Suite via a named pipe.
///
/// Used to signal the start of the iperf3 workload and the begin of the calc Phase.
fn notify_python() {
    if let Ok(mut pipe) = OpenOptions::new().write(true).open("/tmp/notify_pipe") {
        let _ = writeln!(pipe, "START");
    } else {
        eprintln!("⚠️ Could not open /tmp/notify_pipe.");
    }
}

// ============================================================================
// Time Synchronization Helpers
// ============================================================================

/// Updates the user-space reference timestamp.
///
/// Exposed as `extern "C"` to allow to attach a uprobe.
#[no_mangle]
pub extern "C" fn measure_instant() {
    let mut time = USER_ZERO.lock().unwrap();
    *time = Instant::now();
}

/// Increment and return the global message counter.
fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

/// Set the kernel-space reference timestamp in userspace.
fn set_kernel_zero(value: u64) {
    let mut kernel = KERNEL_ZERO.lock().unwrap();
    *kernel = value;
}

/// Get the kernel-space reference timestamp.
fn get_kernel_zero() -> u64 {
    *KERNEL_ZERO.lock().unwrap()
}

/// Refresh the user-space reference timestamp an trigger uprobe.
fn update_user_zero() {
    measure_instant();
}

/// Read the current user-space reference timestamp.
fn read_user_zero() -> Instant {
    *USER_ZERO.lock().unwrap()
}

// ============================================================================
// Event Synchronization
// ============================================================================

/// Wait for a specific kernel event matching sequence number, message type,
/// and event type.
///
/// Polls the corresponding queue with a short timeout.
fn wait_for_event(seq: u64, msg_type: MessageType, event_type: u8) -> Option<Event> {
    let start = Instant::now();

    // Select the appropriate event queue
    let queue = if event_type == 1 {
        CURRENT_EVENT_REC
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone()
    } else if event_type == 2 {
        CURRENT_EVENT_SEND
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone()
    } else {
        CURRENT_QUEUE_EVENT
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone()
    };

    loop {
        if start.elapsed() > Duration::from_millis(1) {
            return None;
        }

        let mut queue_lock = queue.lock().unwrap();

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

// ============================================================================
// Main Application Entry Point
// ============================================================================

/// Main entry point of the application.
///
/// Responsibilities:
/// - Set real-time scheduling
/// - Initialize global queues
/// - Load and attach eBPF programs
/// - Handle TCP communication
/// - Correlate kernel and user-space timestamps
/// - React on Server
fn main() -> Result<()> {
    // Elevate current thread to real-time round-robin scheduling
    set_rt_priority(99);
    unsafe {
        if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
            panic!("mlockall failed");
        }
    }

    // Initialize global event queues
    let event_queue_rec = Arc::new(Mutex::new(VecDeque::new()));
    let event_queue_send = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));

    CURRENT_EVENT_REC.set(event_queue_rec.clone()).unwrap();
    CURRENT_EVENT_SEND.set(event_queue_send.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    // ------------------------------------------------------------------------
    // eBPF Initialization
    // ------------------------------------------------------------------------

    // Open, load and attach the eBPF skeleton
    let open_skel = MonitoreSkelBuilder::default().open()?;
    println!("✅ BPF skeleton opened.");

    let mut skel = open_skel.load()?;
    println!("✅ BPF skeleton loaded.");

    skel.attach()?;
    println!("✅ eBPF program attached and running.");

    // Shared references to event queues
    let event_ref_rec = CURRENT_EVENT_REC.get().unwrap().clone();
    let event_ref_send = CURRENT_EVENT_SEND.get().unwrap().clone();
    let queue_event_ref = CURRENT_QUEUE_EVENT.get().unwrap().clone();

    // Shared flag to stop background threads
    let running = Arc::new(AtomicBool::new(true));
    let maps = skel.maps();

    // ------------------------------------------------------------------------
    // Ring Buffer Setup
    // ------------------------------------------------------------------------

    // Build ring buffer and register callback invoked for each kernel event
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(maps.events(), move |data: &[u8]| {
        // Validate event size
        if data.len() != std::mem::size_of::<Event>() {
            eprintln!("⚠️ Invalid event size: {}", data.len());
            return 0;
        }

        // Deserialize event from raw bytes
        let event = *from_bytes::<Event>(data);
        let my_pid = std::process::id() as u32;

        // Recognize event on event type and PID
        match event.event_type {
            // Kernel reference timestamp event
            // Reaction to triggered Uprobe
            0 if event.pid == my_pid => {
                let _diff = Instant::now().duration_since(read_user_zero()).as_nanos() as i128;
                set_kernel_zero(event.timestamp);
            }

            // Tracepoint receive event
            1 if event.pid == my_pid => {
                let mut queue = event_ref_rec.lock().unwrap();
                queue.push_back(event);
            }

            // Tracepoint send event
            2 if event.pid == my_pid => {
                let mut queue = event_ref_send.lock().unwrap();
                queue.push_back(event);
            }

            // Tracepoint queue event
            3 if event.pid == my_pid => {
                let mut queue = queue_event_ref.lock().unwrap();
                queue.push_back(event);
            }

            // Ignore unrelated events
            _ => {
                let pid = event.pid;
                eprintln!(
                    "⚠️ Unknown event type: {} (pid {}, expected {})",
                    event.event_type, pid, my_pid
                );
            }
        }

        0
    })?;

    let ringbuf = ringbuf_builder.build()?;

    // ------------------------------------------------------------------------
    // Ring Buffer Polling Thread
    // ------------------------------------------------------------------------

    // Background thread polling the eBPF ring buffer
    let ring_running = running.clone();
    let poll_thread = thread::spawn(move || {
        while ring_running.load(Ordering::Relaxed) {
            ringbuf.poll(Duration::from_millis(100)).unwrap();
        }
    });

    // ------------------------------------------------------------------------
    // Argument Parsing
    // ------------------------------------------------------------------------

    // Runtime parameters forwarded to iperf3 from test suite
    let args: Vec<String> = env::args().collect();
    let iperf_o = Arc::new(args[1].clone());
    let time_c_o = Arc::new(args[2].clone());
    let size_p_o = Arc::new(args[3].clone());

    // ------------------------------------------------------------------------
    // TCP Client Setup
    // ------------------------------------------------------------------------

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

            // Client-side timestamps used for synchronization
            let mut client_sent_time = 0u128;
            let mut client_sent_time_calc = 0u128;
            let mut client_queue_time_calc = 0u128;

            // ----------------------------------------------------------------
            // TCP Message Processing Loop
            // ----------------------------------------------------------------

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
                        // ----------------------------------------------------
                        // Unexpected START message
                        // ----------------------------------------------------
                        Ok(MessageType::Start) => {
                            println!("⚠️ Unexpected Start message.");
                        }

                        // ----------------------------------------------------
                        // NTP request handling (Rough Time Sync)
                        // ----------------------------------------------------
                        Ok(MessageType::NTP) => {
                            update_user_zero();

                            let encoded =
                                encode_message(MessageType::NTP, msg.seq, 0, 0, 0, 0.0, 0.0, 0)?;
                            stream.write_all(&encoded)?;
                            increment_message_count();
                        }

                        // ----------------------------------------------------
                        // NTP result processing (For check Phase)
                        // ----------------------------------------------------
                        Ok(MessageType::NtpResult) => {
                            let seq = msg.seq;

                            let mut client_recv =
                                Instant::now().duration_since(read_user_zero()).as_nanos() as u64;

                            if let Some(event) = wait_for_event(seq, MessageType::NtpResult, 1) {
                                client_recv = event.timestamp - get_kernel_zero();
                            }

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
                                client_sent_time =
                                    event.timestamp.checked_sub(get_kernel_zero()).unwrap();
                            }
                        }

                        // ----------------------------------------------------
                        // PTP request handling (Precise Time Sync)
                        // ----------------------------------------------------
                        Ok(MessageType::PTP) => {
                            update_user_zero();
                            let encoded =
                                encode_message(MessageType::PTP, msg.seq, 0, 0, 0, 0.0, 0.0, 0)?;
                            stream.write_all(&encoded)?;
                            increment_message_count();
                        }

                        // ----------------------------------------------------
                        // PTP result accumulation
                        // ----------------------------------------------------
                        Ok(MessageType::PtpResult) => {
                            _difference += msg.i_val;
                        }

                        // ----------------------------------------------------
                        // Calculation & workload message
                        // ----------------------------------------------------
                        Ok(MessageType::Calc) => {
                            let (theta, radius) = (msg.first_f64, msg.second_f64);
                            let y = radius * theta.sin();
                            let seq = msg.seq;

                            // Launch iperf3 background workload (only once)
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

                            // Match receive event
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

                            client_queue_time_calc =
                                Instant::now().duration_since(read_user_zero()).as_nanos() as u128;
                            client_sent_time_calc =
                                Instant::now().duration_since(read_user_zero()).as_nanos() as u128;

                            let mut tcp_seq = 0u64;

                            // Match send event
                            if let Some(event) = wait_for_event(seq, MessageType::Calc, 2) {
                                client_sent_time_calc =
                                    (event.timestamp - get_kernel_zero()) as u128;
                                tcp_seq = event.data.tcp_seq;
                            }

                            // Match queueing event
                            if let Some(evt) = wait_for_event(tcp_seq, MessageType::Calc, 3) {
                                client_queue_time_calc =
                                    (evt.timestamp - get_kernel_zero()) as u128;
                            }

                            let duration = start.elapsed();
                            if duration.as_millis() > 2 {
                                println!("⚠️ Calc took {:?}", duration);
                            }

                            // Termination condition
                            if seq == u64::MAX {
                                break;
                            }
                        }

                        // ----------------------------------------------------
                        // Unknown message type
                        // ----------------------------------------------------
                        Err(_) => {
                            eprintln!("⚠️ Unknown message type {}", msg.msg_type);
                        }
                    }
                }
            }
        }

        // Connection failure
        Err(e) => {
            eprintln!("❌ Could not connect to server: {}", e);
            process::exit(1);
        }
    }

    // ------------------------------------------------------------------------
    // Graceful Shutdown
    // ------------------------------------------------------------------------

    running.store(false, Ordering::Relaxed);
    let _ = poll_thread.join();

    Ok(())
}
