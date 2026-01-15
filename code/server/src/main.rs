use anyhow::Result;
use bytemuck::{from_bytes, Pod, Zeroable};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use libc::{
    mlockall, pthread_self, pthread_setschedparam, sched_param, MCL_CURRENT, MCL_FUTURE, SCHED_RR,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::env;
use std::f64::consts::PI;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

// ============================================================================
// eBPF Skeleton
// ============================================================================
//
// Generated eBPF skeleton (libbpf-rs)
// This file provides access to the mapped tracepoints
//
include!("bpf/monitore.skel.rs");

// ============================================================================
// Global State
// ============================================================================

/// Queue for `netif_receive_skb`-related events (receive).
static CURRENT_EVENT_REC: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

/// Queue for `net_dev_xmit`-related events (send).
static CURRENT_EVENT_SEND: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

/// Queue for `net_dev_queue`-related events (queueing).
static CURRENT_QUEUE_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

/// User-space reference timestamp.
static USER_ZERO: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

/// Kernel reference timestamp (nanoseconds) captured from eBPF side.
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

/// Global message sequence counter
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

// ============================================================================
// Constants
// ============================================================================

/// Phase-level timeout in *nanoseconds* for pacing.
const TIMEOUT_NS: u64 = 3000000;

/// Radius used for the calculation phase (generating circle points).
const RADIUS: f64 = 10.0;

#[derive(Serialize, Deserialize, Debug)]
/// Heterogeneous data payload.
enum Data {
    IntegerI128(i128),
    IntegerU128(u128),
    IntegerU64(u64),
    Float(f64),
}

/// Complete runtime context of the TCP server.
// ============================================================================
// Context and State Machine Types
// ============================================================================
struct SetupContext {
    stream: TcpStream,

    /// Configuration inputs (forwarded in results path).
    standard: Arc<String>,
    frequency: Arc<String>,
    bandwith: Arc<String>,
    qos: Arc<String>,
    time: Arc<String>,
    config: Arc<String>,

    /// Coordination flag to stop background threads (ring buffer polling).
    running: Arc<AtomicBool>,

    /// Send/receive pacing interval (derived from TIMEOUT_NS).
    interval: Duration,

    /// Counter used when writing result files.
    counter: u64,

    /// Results of the calculation phase: (points, latency).
    calculation_result: (Vec<(f64, f64)>, Vec<CalcTimestampSet>),

    /// Measured RTT of NTP-like phase.
    needed_time: u128,

    /// PTP-like phase success flag.
    ptp_result: bool,

    /// Regulation factor for PTP Phase.
    latency_reg: f64,

    /// Latency test success flag.
    latency_result: bool,
}

#[derive(Default)]

/// Optional overrides used to derive updated contexts between phases.
struct SetupContextOverrides {
    pub running: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub counter: Option<u64>,
    pub calculation_result: Option<(Vec<(f64, f64)>, Vec<CalcTimestampSet>)>,
    pub needed_time: Option<u128>,
    pub ptp_result: Option<bool>,
    pub latency_reg: Option<f64>,
    pub latency_result: Option<bool>,
}

/// High-level control states of the server.
enum State {
    Error,
    WaitForStart,
    Ntp,
    Ptp,
    LatencyTest,
    Calculation,
    SaveResults,
    Done,
}

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
#[repr(C, packed)]
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

/// Create a derived context from a base one by applying overrides.
fn update_context(base: &SetupContext, overrides: SetupContextOverrides) -> SetupContext {
    SetupContext {
        stream: base.stream.try_clone().expect("Failed to clone stream"),
        standard: base.standard.clone(),
        frequency: base.frequency.clone(),
        bandwith: base.bandwith.clone(),
        qos: base.qos.clone(),
        time: base.time.clone(),
        config: base.config.clone(),
        running: overrides.running.unwrap_or_else(|| base.running.clone()),
        interval: base.interval,
        counter: overrides.counter.unwrap_or_else(|| base.counter.clone()),
        calculation_result: overrides
            .calculation_result
            .unwrap_or_else(|| base.calculation_result.clone()),
        needed_time: overrides.needed_time.unwrap_or(base.needed_time),
        ptp_result: overrides.ptp_result.unwrap_or(base.ptp_result),
        latency_reg: overrides.latency_reg.unwrap_or(base.latency_reg),
        latency_result: overrides.latency_result.unwrap_or(base.latency_result),
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

// ============================================================================
// eBPF Event Payloads
// ============================================================================

/// Data section embedded within an eBPF ring buffer event.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct BpfData {
    msg_type: u8,
    _padding: [u8; 7],
    seq: u64,
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

/// ============================================================================
/// Timestamp Bundles
/// ============================================================================

/// Timestamp set for PTP-like measurements (server <-> client).
#[derive(Default, Clone)]
struct PTPTimestampSet {
    server_arrival: u128,
    server_arrival_kernel: u128,
    server_sent: u128,
    server_kernel_sent: u128,
    client_arrival: u128,
    client_sent: Option<u128>,
}

/// Timestamp set collected during the Calculation phase.
///
/// This aligns kernel/user times across both directions, including device queueing.
#[derive(Default, Clone)]
struct CalcTimestampSet {
    server_arrival: u128,
    server_arrival_kernel: u128,
    server_queue: u128,
    server_sent: u128,
    server_sent_kernel: u128,
    client_queue: Option<u128>,
    client_arrival_kernel: u128,
    client_sent_kernel: Option<u128>,
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
        match value {
            0 => Ok(MessageType::Start),
            1 => Ok(MessageType::NTP),
            2 => Ok(MessageType::NtpResult),
            3 => Ok(MessageType::PTP),
            4 => Ok(MessageType::PtpResult),
            5 => Ok(MessageType::Calc),
            _ => panic!("False Value for MessageType: {}", value),
        }
    }
}

/// Exposed as `extern "C"` to allow attaching an uprobe from eBPF.
///
/// Updates the `USER_ZERO` timestamp to now.
#[no_mangle]
pub extern "C" fn measure_instant() {
    let mut time = USER_ZERO.lock().unwrap();
    *time = Instant::now();
}

/// Return the median of a vector of i128.
fn median(values: &Vec<i128>) -> i128 {
    let mut sorted_values = values.clone();
    sorted_values.sort();
    let len = sorted_values.len();
    if len % 2 == 1 {
        sorted_values[len / 2]
    } else {
        (sorted_values[len / 2 - 1] + sorted_values[len / 2]) / 2
    }
}

/// Set current thread to real-time `SCHED_RR` priority.
fn set_rt_priority(prio: i32) {
    unsafe {
        let mut param = sched_param {
            sched_priority: prio,
        };
        let ret = pthread_setschedparam(pthread_self(), SCHED_RR, &mut param);
        if ret != 0 {
            eprintln!("Failed to set RT priority: {}", ret);
        } else {
            println!("RT priority set to {}", prio);
        }
    }
}

/// Busy-wait until `next_tick` with a short pre-sleep to avoid long spinning.
fn wait_until(next_tick: Instant) {
    let now = Instant::now();
    if next_tick > now {
        let sleep_time = next_tick - now;
        if sleep_time > Duration::from_micros(500) {
            thread::sleep(sleep_time - Duration::from_micros(200));
        }
        while Instant::now() < next_tick {
            std::hint::spin_loop();
        }
    }
}

/// Increment and return the global message counter.
pub fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

/// Wait for a specific eBPF event matching `(seq, msg_type, event_type)`.
///
/// Polls the corresponding queue with a short timeout.
fn wait_for_event(seq: u64, msg_type: MessageType, event_type: u8) -> Option<Event> {
    let start = Instant::now();
    let queue;
    if event_type == 1 {
        queue = CURRENT_EVENT_REC
            .get()
            .expect("CURRENT_EVENT not initialized")
            .clone();
    } else if event_type == 2 {
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
            println!("Nix {}", event_type);
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

/// Set kernel reference timestamp in userspace.
fn set_kernel_zero(value: u64) {
    let mut kernel = KERNEL_ZERO.lock().unwrap();
    *kernel = value;
}

/// Get kernel reference timestamp.
fn get_kernel_zero() -> u64 {
    let kernel = KERNEL_ZERO.lock().unwrap();
    *kernel
}

/// Trigger uprobe to refresh the user-space reference timestamp.
fn update_user_zero() {
    measure_instant();
}

/// Read current user-space reference timestamp.
fn read_user_zero() -> Instant {
    let time = USER_ZERO.lock().unwrap();
    *time
}

// ============================================================================
// Phases
// ============================================================================

/// Waits for the initial `Start` message from the client.
fn wait_for_start_message(context: &SetupContext) {
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    if let Ok(mut stream) = context.stream.try_clone() {
        if let Ok(_n) = stream.read(&mut buffer) {
            let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
            if msg.msg_type == MessageType::Start as u8 {
                return;
            }
        } else {
            eprintln!("Error while reading start message");
        }
    }
}

/// NTP-like phase: meassures the per-message round-trip to obtain "needed_time".
///
/// Sends `NTP` and waits for client reflection to measure elapsed times.
fn ntp_phase(context: &SetupContext) -> Result<SetupContext> {
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    let stabilization_iterations = 200;
    println!("----------------Time synchronisation started----------------");
    update_user_zero();
    let interval = Duration::from_nanos(TIMEOUT_NS);
    let mut next_tick = Instant::now() + interval;
    let mut needed_time = u128::MAX;
    let mut i = 0;
    let mut ntp_regulation = 500000;

    if let Ok(mut stream) = context.stream.try_clone() {
        while needed_time > ntp_regulation {
            let start_time = Instant::now();
            let elapsed_start_time = start_time.duration_since(read_user_zero());
            let encoded_msg = encode_message(MessageType::NTP, i, 0, 0, 0, 0.0, 0.0, 0)?;
            //println!("{:?}", encoded_msg);
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending: {}", e);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        running: Some(Arc::new(AtomicBool::new(false))),
                        ..Default::default()
                    },
                ));
            }
            increment_message_count();

            // Await response
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
                    let number = msg.seq;

                    // Prefer kernel timestamp (receive tracepoint)
                    let mut end_time =
                        Instant::now().duration_since(read_user_zero()).as_nanos() as u64;
                    if let Some(event) = wait_for_event(number, MessageType::NTP, 1) {
                        end_time = event.timestamp - get_kernel_zero();
                    }

                    needed_time = end_time as u128 - elapsed_start_time.as_nanos();
                    /*
                    println!(
                        "Needed Time {} Elapsed {} Start_Elapsed {}",
                        needed_time,
                        elapsed_time.as_nanos(),
                        elapsed_start_time.as_nanos()
                    ); */
                }
                _ => eprintln!("Error while receiving"),
            }
            wait_until(next_tick);
            next_tick += interval;
            i += 1;

            // Simple regulation after initial stabilization
            if needed_time > ntp_regulation && i > stabilization_iterations {
                let difference = needed_time - ntp_regulation;
                ntp_regulation = ntp_regulation + (difference / 2);
                //println!("Regulation {} Need {}", ntp_regulation, needed_time);
            }
        }
        return Ok(update_context(
            context,
            SetupContextOverrides {
                needed_time: Some(needed_time),
                ..Default::default()
            },
        ));
    } else {
        eprintln!("Error while reading NTP message");
        return Ok(update_context(
            context,
            SetupContextOverrides {
                running: Some(Arc::new(AtomicBool::new(false))),
                ..Default::default()
            },
        ));
    }
}

/// PTP-like phase: try to align server/client timing by waiting a calibrated delay (time of RTT from NTP)
/// and measuring the difference to `needed_time`.
fn ptp_phase(context: &SetupContext) -> Result<SetupContext> {
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    let max_ptp_tolerance = 5000; // in nanoseconds
    let mut ptp_diff = u128::MAX;
    let needed_time = context.needed_time.clone();
    let interval = context.interval.clone();
    println!("PTP: {:?}", context.latency_reg);
    if let Ok(mut stream) = context.stream.try_clone() {
        println!("--------------------Start PTP Mechanism---------------------");
        let mut j = 0;
        let mut ptp_regulation = 1000;
        let mut next_tick = Instant::now() + interval;
        while ptp_diff > 10000 {
            let start_time = Instant::now();
            let encoded_msg = encode_message(MessageType::PTP, j, 0, 0, 0, 0.0, 0.0, 0)?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending: {}", e);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        running: Some(Arc::new(AtomicBool::new(false))),
                        ..Default::default()
                    },
                ));
            }
            increment_message_count();

            // Wait a fraction of the previously measured needed_time (normally latency_reg = 2)
            let wait_time = Instant::now()
                + Duration::from_nanos((needed_time as f64 / context.latency_reg).round() as u64);
            wait_until(wait_time);
            update_user_zero();

            // Await response
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let end_time = Instant::now();
                    let ptp_duration = end_time - start_time;
                    ptp_diff = ptp_duration.as_nanos().abs_diff(needed_time);
                }
                _ => eprintln!("Error while receiving"),
            }
            j += 1;
            ptp_regulation += 1;

            wait_until(next_tick);
            next_tick += interval;
            if ptp_regulation > max_ptp_tolerance {
                //println!(
                //    "PTP Phase exceeded a tolerance of {} , stopping.",
                //    max_ptp_tolerance
                //);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        ptp_result: Some(false),
                        ..Default::default()
                    },
                ));
            }
        }
        //println!("PTP-Diff = {} {}", ptp_diff, j);
        return Ok(update_context(
            context,
            SetupContextOverrides {
                ptp_result: Some(true),
                ..Default::default()
            },
        ));
    } else {
        eprintln!("Error while reading NTP message");
        return Ok(update_context(
            context,
            SetupContextOverrides {
                running: Some(Arc::new(AtomicBool::new(false))),
                ..Default::default()
            },
        ));
    }
}

/// Latency Test phase: exchanges `NtpResult` messages to measure path offsets
/// to calibrate latency regulation and not assume a symmetric network
fn latency_test_phase(context: &SetupContext) -> Result<SetupContext> {
    println!("---------------------Start Latency Test---------------------");
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    let test_mesg_count: u64 = 1000;
    let mut i = 0;
    let max_tolerance = 10000; // in nanoseconds
    let interval = context.interval.clone();
    let mut next_tick = Instant::now() + interval;
    let mut timestamps: Vec<PTPTimestampSet> =
        vec![PTPTimestampSet::default(); test_mesg_count as usize];
    if let Ok(mut stream) = context.stream.try_clone() {
        while i < test_mesg_count + 1 {
            let index = i as usize;
            let start_time = Instant::now();
            let elapsed_time = start_time.duration_since(read_user_zero());
            let encoded_msg = encode_message(
                MessageType::NtpResult,
                i,
                elapsed_time.as_nanos(),
                0,
                0,
                0.0,
                0.0,
                0,
            )?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending: {}", e);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        running: Some(Arc::new(AtomicBool::new(false))),
                        ..Default::default()
                    },
                ));
            }
            increment_message_count();

            // Prefer kernel send timestamp
            let mut server_kernel_sent =
                Instant::now().duration_since(read_user_zero()).as_nanos() as u64;
            if let Some(event) = wait_for_event(i, MessageType::NtpResult, 2) {
                server_kernel_sent = event.timestamp - get_kernel_zero();
            }

            // Await response
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let mut server_arrival_kernel =
                        Instant::now().duration_since(read_user_zero()).as_nanos() as u64;
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
                    let number = msg.seq;

                    let server_arrival = Instant::now().duration_since(read_user_zero()).as_nanos();

                    if let Some(event) = wait_for_event(number, MessageType::NtpResult, 1) {
                        server_arrival_kernel = event.timestamp - get_kernel_zero();
                    }
                    let (server_sent, client_arrival, client_sent) =
                        (msg.first_u128, msg.second_u128, msg.timestamp);
                    // Gather All EBPF Timestamps
                    if i < test_mesg_count {
                        timestamps[index].server_arrival = server_arrival;
                        timestamps[index].server_arrival_kernel = server_arrival_kernel as u128;
                        timestamps[index].server_sent = server_sent;
                        timestamps[index].server_kernel_sent = server_kernel_sent as u128;
                        timestamps[index].client_arrival = client_arrival;
                    }
                    // Last message carries client_sent for previous message
                    if i > 0 {
                        timestamps[index - 1].client_sent = Some(client_sent);
                    }
                }
                _ => {
                    return Ok(update_context(
                        context,
                        SetupContextOverrides {
                            running: Some(Arc::new(AtomicBool::new(false))),
                            ..Default::default()
                        },
                    ));
                }
            }
            wait_until(next_tick);
            next_tick += interval;
            i += 1;
        }

        // Compute offset across samples
        let mut diff_all: Vec<i128> = vec![0; test_mesg_count as usize];
        for (i, ts) in timestamps.iter().enumerate() {
            if let Some(client_sent) = ts.client_sent {
                let first_offset = ts.client_arrival as i128 - ts.server_kernel_sent as i128;
                let second_offset = ts.server_arrival_kernel as i128 - client_sent as i128;
                //   let whole = ts.server_arrival as i128 - ts.server_sent as i128;
                let diff_test_offset = second_offset - first_offset;
                diff_all[i] = diff_test_offset;
                /*
                println!(
                    "#{i}: Diff_Offset: {}, Whole: {}, First: {}, Second: {}",
                    diff_test_offset, whole, first_offset, second_offset
                ); */
            } else {
                //println!("#{i}: Incomplete timestamp set");
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        latency_result: Some(false),
                        ..Default::default()
                    },
                ));
            }
        }

        // Computer Median of all offsets
        let med = median(&diff_all);
        if med.abs() > max_tolerance as i128 {
            if med < 0 {
                //println!("Median is too low: {}", med);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        latency_reg: Some(context.latency_reg + 0.02),
                        latency_result: Some(false),
                        ..Default::default()
                    },
                ));
            } else {
                //println!("Median is too high: {}", med);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        latency_reg: Some((context.latency_reg - 0.02).max(0.1)),
                        latency_result: Some(false),
                        ..Default::default()
                    },
                ));
            }
        }
        println!("Median of Latency Test: {}", med);
        return Ok(update_context(
            context,
            SetupContextOverrides {
                latency_result: Some(true),
                ..Default::default()
            },
        ));
    } else {
        eprintln!("Error while reading NTP message");
        return Ok(update_context(
            context,
            SetupContextOverrides {
                running: Some(Arc::new(AtomicBool::new(false))),
                ..Default::default()
            },
        ));
    }
}

/// Calculation phase: streams `Calc` messages (theta & radius) to client,
/// collects timestamps and reconstructs a circle waveform from returned samples.
fn calculation_phase(context: &SetupContext) -> Result<SetupContext> {
    println!("Start Calculation");
    let mut buffer = [0u8; std::mem::size_of::<Message>()];

    let interval = context.interval.clone();
    let mut last_y = 0.0;
    let calc_time = SystemTime::now();
    let mut next_tick = Instant::now() + interval;
    let mut i = 0;
    let context_time: u64 = context
        .time
        .as_str()
        .parse()
        .expect("Invalid number in time");

    // Calculate number of points to generate
    let num_points = (context_time * 1000000000) / TIMEOUT_NS;

    let mut points = Vec::with_capacity(num_points as usize);
    let mut latency: Vec<CalcTimestampSet> = vec![CalcTimestampSet::default(); num_points as usize];

    if let Ok(mut stream) = context.stream.try_clone() {
        while calc_time.elapsed()?.as_secs() < context_time {
            let index = i as usize;
            //  let calc_start_time = Instant::now();
            //  let calc_start_elapsed = calc_start_time.duration_since(read_user_zero());
            let theta = 2.0 * PI * (i as f64) / (num_points as f64);
            let x = RADIUS * theta.cos();
            let calc_send_time = Instant::now();
            let calc_send_elapsed = calc_send_time.duration_since(read_user_zero());
            //println!("Calc {}", i);
            let encoded_msg = encode_message(MessageType::Calc, i, 0, 0, 0, theta, RADIUS, 0)?;
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending: {}", e);
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        running: Some(Arc::new(AtomicBool::new(false))),
                        ..Default::default()
                    },
                ));
            }
            increment_message_count();

            // Kernel send timestamp (xmit)
            let mut server_sent_kernel =
                Instant::now().duration_since(read_user_zero()).as_nanos() as u64;
            let mut tcp_sec = 0;
            if let Some(event) = wait_for_event(i, MessageType::Calc, 2) {
                server_sent_kernel = event.timestamp - get_kernel_zero();
                tcp_sec = event.data.tcp_seq;
            }

            // Queueing snapshot (dev_queue)
            let event_snapshot_queue = wait_for_event(tcp_sec, MessageType::Calc, 3);
            let server_queue = event_snapshot_queue.unwrap().timestamp - get_kernel_zero();

            let calc_send_duration;

            // Await response with y-value and client-side kernel timing
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let end_time = Instant::now();
                    let calc_end_time = end_time.duration_since(read_user_zero());
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);

                    let number = msg.seq;
                    let mut server_arrival_kernel =
                        Instant::now().duration_since(read_user_zero()).as_nanos() as u64;

                    // Kernel receive timestamp
                    if let Some(event) = wait_for_event(number, MessageType::Calc, 1) {
                        server_arrival_kernel = event.timestamp - get_kernel_zero();
                    }

                    calc_send_duration = calc_end_time.as_nanos() - calc_send_elapsed.as_nanos();

                    match (
                        msg.first_f64,
                        msg.timestamp,
                        msg.first_u128,
                        msg.second_u128,
                    ) {
                        (y, client_queue, client_arrival_kernel, client_sent) => {
                            latency[index].server_arrival = calc_end_time.as_nanos();
                            latency[index].server_arrival_kernel = server_arrival_kernel as u128;
                            latency[index].server_queue = server_queue as u128;
                            latency[index].server_sent = calc_send_elapsed.as_nanos();
                            latency[index].server_sent_kernel = server_sent_kernel as u128;
                            latency[index].client_arrival_kernel = client_arrival_kernel;
                            if i > 0 {
                                latency[index - 1].client_sent_kernel = Some(client_sent);
                                latency[index - 1].client_queue = Some(client_queue);
                            }
                            // If the per-message latency exceeded timeout window, reuse last y with penalty
                            last_y = if calc_send_duration <= TIMEOUT_NS as u128 {
                                y
                            } else {
                                last_y - 2.0
                            };
                        }
                    }
                }
                _ => eprintln!("Error while receiving"),
            }
            points.push((x, last_y));
            wait_until(next_tick);
            next_tick += interval;
            i += 1;
        }

        // Send termination message for Calc exchange
        let encoded_msg = encode_message(
            MessageType::Calc,
            num_points.try_into().unwrap(),
            0,
            0,
            0,
            0.0,
            0.0,
            0,
        )?;
        if let Err(e) = stream.write_all(&encoded_msg) {
            eprintln!("Error while sending: {}", e);
            return Ok(update_context(
                context,
                SetupContextOverrides {
                    running: Some(Arc::new(AtomicBool::new(false))),
                    ..Default::default()
                },
            ));
        }
        increment_message_count();

        // Receive final client kernel send & queue timestamps for last element
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
                match (msg.second_u128, msg.timestamp) {
                    (client_sent, client_queue) => {
                        latency[num_points as usize - 1].client_sent_kernel = Some(client_sent);
                        latency[num_points as usize - 1].client_queue = Some(client_queue);
                    }
                }
            }
            _ => eprintln!("Error while receiving"),
        }
        return Ok(update_context(
            context,
            SetupContextOverrides {
                calculation_result: Some((points, latency)),
                ..Default::default()
            },
        ));
    } else {
        eprintln!("Error while reading NTP message");
        return Ok(update_context(
            context,
            SetupContextOverrides {
                running: Some(Arc::new(AtomicBool::new(false))),
                ..Default::default()
            },
        ));
    }
}

/// Persist collected circle points and latency breakdowns to disk.
///
/// Folder layout:
///   ../{config}/results/standard_{standard}/frequency_{frequency}/bandwith_{bandwith}/qos_{qos}/tcp/
fn save_results(context: &SetupContext) -> Result<SetupContext> {
    let result_path = format!(
        "../{}/results/standard_{}/frequency_{}/bandwith_{}/qos_{}/tcp/",
        &context.config, &context.standard, &context.frequency, &context.bandwith, &context.qos
    );
    if let Err(e) = create_dir_all(&result_path) {
        eprintln!("Error while creating directories: {}", e);
        return Ok(update_context(
            context,
            SetupContextOverrides {
                counter: Some(context.counter.clone() + 1),
                ..Default::default()
            },
        ));
    }

    // Write latencies
    let mut latencies = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!(
                "{}/latencys_{}",
                result_path,
                context.counter.clone()
            ))
            .unwrap(),
    );

    for (i, ts) in context.calculation_result.1.iter().enumerate() {
        if let (Some(client_sent_kernel), Some(client_queue)) =
            (ts.client_sent_kernel, ts.client_queue)
        {
            let work_t1 = ts.server_queue as i128 - ts.server_sent as i128;
            let queue_t1 = ts.server_sent_kernel as i128 - ts.server_queue as i128;
            let send_t1 = ts.client_arrival_kernel as i128 - ts.server_sent_kernel as i128;
            let work_t2 = client_queue as i128 - ts.client_arrival_kernel as i128;
            let queue_t2 = client_sent_kernel as i128 - client_queue as i128;
            let send_t2 = ts.server_arrival_kernel as i128 - client_sent_kernel as i128;
            let whole = ts.server_arrival as i128 - ts.server_sent as i128;
            writeln!(
                latencies,
                "{},{},{},{},{},{},{}",
                work_t1, queue_t1, send_t1, work_t2, queue_t2, send_t2, whole
            )
            .unwrap();
        } else {
            println!("#{}: Incomplete timestamp set", i);
        }
    }

    let mut circle_points = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!(
                "{}/circle_points_{}",
                result_path,
                context.counter.clone()
            ))
            .unwrap(),
    );

    for (x, y) in &context.calculation_result.0 {
        writeln!(circle_points, "{},{}", x, y).unwrap();
    }

    circle_points.flush().unwrap();
    latencies.flush().unwrap();
    println!("Points and Latencies written.");
    return Ok(update_context(
        context,
        SetupContextOverrides {
            counter: Some(context.counter.clone() + 1),
            ..Default::default()
        },
    ));
}

/// Send a terminal `Calc/u64::MAX` message repeatedly to ensure the client
/// observes the stop condition, then return.
fn handle_error(context: &SetupContext) -> Result<()> {
    if let Ok(mut stream) = context.stream.try_clone() {
        let encoded_msg = encode_message(MessageType::Calc, u64::MAX, 0, 0, 0, 0.0, 0.0, 0)?;
        for _ in 0..100 {
            if let Err(e) = stream.write_all(&encoded_msg) {
                eprintln!("Error while sending: {}", e);
            }
        }

        increment_message_count();
    } else {
        eprintln!("Error while reading NTP message");
    }
    Ok(())
}

// ============================================================================
// Entry Point
// ============================================================================
fn main() -> Result<(), libbpf_rs::Error> {
    set_rt_priority(99);
    unsafe {
        if mlockall(MCL_CURRENT | MCL_FUTURE) != 0 {
            panic!("mlockall failed");
        }
    }

    // Initialize global event queues for eBPF callbacks
    let event_queue_rec = Arc::new(Mutex::new(VecDeque::new()));
    let event_queue_send = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));

    CURRENT_EVENT_REC.set(event_queue_rec.clone()).unwrap();
    CURRENT_EVENT_SEND.set(event_queue_send.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    let event_ref_rec = CURRENT_EVENT_REC.get().unwrap().clone();
    let event_ref_send = CURRENT_EVENT_SEND.get().unwrap().clone();
    let queue_event_ref = CURRENT_QUEUE_EVENT.get().unwrap().clone();

    // ---- Load & attach eBPF
    let open_skel = MonitoreSkelBuilder::default().open();
    println!("Skelett geöffnet.");

    let mut skel = open_skel?.load()?;
    println!("Skelett geladen.");

    skel.attach()?;

    println!("eBPF-Programm läuft …");
    let running = Arc::new(AtomicBool::new(true));

    // ---- Build ring buffer and start polling thread
    let r = running.clone();
    let maps = skel.maps();
    // Callback-Funktion, wird bei jedem Ringbuffer-Event aufgerufen
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(maps.events(), move |data: &[u8]| {
        if data.len() != std::mem::size_of::<Event>() {
            eprintln!(
                "Unexpected data size: {} {}",
                data.len(),
                std::mem::size_of::<Event>()
            );
            return 0;
        }

        let my_pid = std::process::id() as u32;
        let event = *from_bytes::<Event>(data);
        match event.event_type {
            // Kernel reference time snapshot (uprobed in userspace)
            0 if event.pid == my_pid => {
                let timestamp = event.timestamp;
                set_kernel_zero(timestamp);
            }
            // Receive tracepoint
            1 if event.pid == my_pid => {
                let mut queue = event_ref_rec.lock().unwrap();
                queue.push_back(event);
            }
            // Send tracepoint
            2 if event.pid == my_pid => {
                let mut queue = event_ref_send.lock().unwrap();
                queue.push_back(event);
            }
            // Queue tracepoint
            3 if event.pid == my_pid => {
                let mut queue = queue_event_ref.lock().unwrap();
                queue.push_back(event);
            }
            _ => {
                eprintln!("⚠️ Unknown event type: {}", event.event_type);
            }
        }

        0
    })?;
    let ringbuf = ringbuf_builder.build()?;

    // Poll ring buffer in background
    let _handle = thread::spawn(move || {
        while r.load(Ordering::Relaxed) {
            ringbuf.poll(Duration::from_millis(100)).unwrap();
        }
    });

    println!("Size of Message: {}", std::mem::size_of::<Message>());

    let args: Vec<String> = env::args().collect();
    let config = Arc::new(args[1].clone());
    let standard = Arc::new(args[2].clone());
    let frequency = Arc::new(args[3].clone());
    let bandwith = Arc::new(args[4].clone());
    let qos = Arc::new(args[5].clone());
    let time = Arc::new(args[6].clone());
    let listener = TcpListener::bind("192.168.1.1:8080")?;
    println!("TCPServer läuft auf 192.168.1.1:8080");
    let running = Arc::new(AtomicBool::new(true));

    for stream in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                let standard = Arc::clone(&standard);
                let frequency = Arc::clone(&frequency);
                let bandwith = Arc::clone(&bandwith);
                let qos = Arc::clone(&qos);
                let running_thread = Arc::clone(&running);
                let handle = thread::spawn(move || {
                    let context = SetupContext {
                        stream,
                        standard,
                        frequency,
                        bandwith,
                        qos,
                        time,
                        config,
                        running: running_thread,
                        interval: Duration::from_nanos(TIMEOUT_NS),
                        counter: 0,
                        calculation_result: (Vec::new(), Vec::new()),
                        needed_time: u128::MAX,
                        ptp_result: false,
                        latency_reg: 2.0,
                        latency_result: false,
                    };
                    _ = run_state_machine(context);
                });
                let _ = handle.join();
            }
            Err(e) => eprintln!("Verbindungsfehler: {}", e),
        }
        println!("test");
        break;
    }
    Ok(())
}

// ============================================================================
// State Machine
// ============================================================================

/// Drives the server through its phases until completion or error.
fn run_state_machine(mut context: SetupContext) -> Result<()> {
    let mut state = State::WaitForStart;

    loop {
        state = match state {
            State::WaitForStart => {
                wait_for_start_message(&context);
                State::Ntp
            }

            State::Ntp => {
                context = ntp_phase(&context)?;
                if !context.running.load(Ordering::Relaxed) {
                    State::Error
                } else {
                    State::Ptp
                }
            }

            State::Ptp => {
                context = ptp_phase(&context)?;
                if !context.running.load(Ordering::Relaxed) {
                    State::Error
                } else if context.ptp_result {
                    State::LatencyTest
                } else {
                    State::Ntp
                }
            }

            State::LatencyTest => {
                context = latency_test_phase(&context)?;
                if !context.running.load(Ordering::Relaxed) {
                    State::Error
                } else if context.latency_result {
                    State::Calculation
                } else {
                    State::Ptp
                }
            }

            State::Calculation => {
                context = calculation_phase(&context)?;
                if !context.running.load(Ordering::Relaxed) {
                    State::Error
                } else {
                    State::SaveResults
                }
            }

            State::SaveResults => {
                save_results(&context)?;
                State::Done
            }

            State::Done => {
                context.running.store(false, Ordering::Relaxed);
                break;
            }

            State::Error => {
                handle_error(&context)?;
                println!("Error occurred, resetting state machine.");
                break;
            }
        }
    }
    println!("State machine finished.");
    Ok(())
}
