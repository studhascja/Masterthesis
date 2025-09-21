use anyhow::Result;
use bytemuck::{Pod, Zeroable, from_bytes};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use libc::{pthread_self, pthread_setschedparam, sched_param, SCHED_RR};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::env;
use std::f64::consts::PI;
use std::fs::{create_dir_all, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

include!("bpf/monitore.skel.rs");

static CURRENT_EVENT_REC: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static CURRENT_EVENT_SEND: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static CURRENT_QUEUE_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

static USER_ZERO: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
static TIMEOUT_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

const TIMEOUT_NS: u64 = 3000000;

const RADIUS: f64 = 10.0;
const TIMEOUT_DURATION: Duration = Duration::from_millis(300);

struct SetupContext {
    socket: UdpSocket,
    src_client: SocketAddr,
    standard: Arc<String>,
    frequency: Arc<String>,
    bandwith: Arc<String>,
    qos: Arc<String>,
    time: Arc<String>,
    config: Arc<String>,
    running: Arc<AtomicBool>,
    interval: Duration,
    counter: u64,
    calculation_result: (Vec<(f64, f64)>, Vec<CalcTimestampSet>),
    needed_time: u128,
    ptp_result: bool,
    latency_reg: f64,
    latency_result: bool,
}
#[derive(Default)]
struct SetupContextOverrides {
    pub src_client: Option<std::net::SocketAddr>,
    pub running: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub counter: Option<u64>,
    pub calculation_result: Option<(Vec<(f64, f64)>, Vec<CalcTimestampSet>)>,
    pub needed_time: Option<u128>,
    pub ptp_result: Option<bool>,
    pub latency_reg: Option<f64>,
    pub latency_result: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
enum Data {
    IntegerI128(i128),
    IntegerU128(u128),
    IntegerU64(u64),
    Float(f64),
}

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

#[repr(C, packed)]
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

#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct BpfData {
    msg_type: u8,
    _padding: [u8; 7],
    seq: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Event {
    event_type: u8,
    _padding: [u8; 7],
    timestamp: u64,
    pid: u32,
    _padding_pid: [u8; 4],
    data: BpfData,
}

#[derive(Default, Clone)]
struct PTPTimestampSet {
    server_arrival: u128,
    server_arrival_kernel: u128,
    server_sent: u128,
    server_kernel_sent: u128,
    client_arrival: u128,
    client_sent: Option<u128>,
}

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

#[no_mangle]
pub extern "C" fn measure_instant() {
    let mut time = USER_ZERO.lock().unwrap();
    *time = Instant::now();
}

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

fn update_context(base: &SetupContext, overrides: SetupContextOverrides) -> SetupContext {
    SetupContext {
        socket: base.socket.try_clone().expect("Failed to clone socket"),
        src_client: overrides.src_client.unwrap_or(base.src_client),
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

pub fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

pub fn increment_timeout_count() -> bool {
    let mut count = TIMEOUT_COUNT.lock().unwrap();
    *count += 1;
    if *count > 10 {
        return true;
    } else {
        return false;
    }
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
            println!("Nix");
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

fn set_kernel_zero(value: u64) {
    let mut kernel = KERNEL_ZERO.lock().unwrap();
    *kernel = value;
}

fn get_kernel_zero() -> u64 {
    let kernel = KERNEL_ZERO.lock().unwrap();
    *kernel
}

fn update_user_zero() {
    measure_instant();
}

fn read_user_zero() -> Instant {
    let time = USER_ZERO.lock().unwrap();
    *time
}

fn setup() -> anyhow::Result<SetupContext> {
    set_rt_priority(99);

    let args: Vec<String> = env::args().collect();
    let config = Arc::new(args[1].clone());
    let standard = Arc::new(args[2].clone());
    let frequency = Arc::new(args[3].clone());
    let bandwith = Arc::new(args[4].clone());
    let qos = Arc::new(args[5].clone());
    let time = Arc::new(args[6].clone());

    let socket = UdpSocket::bind("192.168.1.1:8080")?;
    socket.set_nonblocking(true)?;
    println!("Server läuft auf 192.168.1.1:8080");
    println!("Size of Message: {}", std::mem::size_of::<Message>());
    let src_client: SocketAddr = "192.168.1.10:12345".parse().unwrap();

    let running = Arc::new(AtomicBool::new(true));

    Ok(SetupContext {
        socket,
        src_client,
        standard,
        frequency,
        bandwith,
        qos,
        time,
        config,
        running,
        interval: Duration::from_nanos(TIMEOUT_NS),
        counter: 0,
        calculation_result: (Vec::new(), Vec::new()),
        needed_time: u128::MAX,
        ptp_result: false,
        latency_reg: 2.0,
        latency_result: false,
    })
}

fn wait_for_start_message(context: &SetupContext) -> SetupContext {
    let mut buf = [0u8; std::mem::size_of::<Message>()];
    let socket = &context.socket;
    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                let msg: Message = *bytemuck::from_bytes(&buf[..amt]);
                println!("Nachricht von {} empfangen: {:?}", src, msg);

                if msg.msg_type == MessageType::Start as u8 {
                    update_user_zero();
                    return update_context(
                        context,
                        SetupContextOverrides {
                            src_client: Some(src),
                            ..Default::default()
                        },
                    );
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Error while receiving: {}", e);
            }
        }
    }
}

fn ntp_phase(context: &SetupContext) -> Result<SetupContext> {
    let stabilization_iterations = 200;

    let mut buf = [0u8; std::mem::size_of::<Message>()];
    let socket = &context.socket;
    let interval = context.interval.clone();
    println!("--------------------Start NTP Mechanism---------------------");
    let mut next_tick = Instant::now() + interval;
    let mut i = 0;
    let mut ntp_regulation = 500000;
    let mut needed_time = u128::MAX;

    while needed_time > ntp_regulation {
        let start_time = Instant::now();
        let elapsed_start_time = start_time.duration_since(read_user_zero());
        let encoded_msg = encode_message(MessageType::NTP, i, 0, 0, 0, 0.0, 0.0, 0)?;
        socket.send_to(&encoded_msg, &context.src_client)?;
        increment_message_count();

        loop {
            if start_time.elapsed() > TIMEOUT_DURATION {
                println!("Timeout in NTP Phase");
                next_tick = Instant::now() + interval;
                if increment_timeout_count() {
                    println!("Too many timeouts, stopping NTP Phase.");
                    return Ok(update_context(
                        context,
                        SetupContextOverrides {
                            running: Some(Arc::new(AtomicBool::new(false))),
                            needed_time: Some(needed_time),
                            ..Default::default()
                        },
                    ));
                }
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((amt, _src)) => {
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buf[..amt]);
                    let number = msg.seq;
                    let mut end_time =
                        Instant::now().duration_since(read_user_zero()).as_nanos() as u64;
                    if let Some(event) = wait_for_event(number, MessageType::NTP, 1) {
                        end_time = event.timestamp - get_kernel_zero();
                    }

                    needed_time = end_time as u128 - elapsed_start_time.as_nanos();
                    /*println!(
                            "Needed Time {} Elapsed {} Start_Elapsed {}",
                            needed_time,
                            elapsed_time.as_nanos(),
                            elapsed_start_time.as_nanos()
                    );*/
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_nanos(10));
                }
                Err(e) => {
                    eprintln!("Error while receiving: {}", e);
                }
            }
        }
        wait_until(next_tick);
        next_tick += interval;
        i += 1;
        if needed_time > ntp_regulation && i > stabilization_iterations {
            let difference = needed_time - ntp_regulation;
            ntp_regulation = ntp_regulation + (difference / 2);
            println!("Regulation {} Need {}", ntp_regulation, needed_time);
        }
    }
    return Ok(update_context(
        context,
        SetupContextOverrides {
            needed_time: Some(needed_time),
            ..Default::default()
        },
    ));
}

fn ptp_phase(context: &SetupContext) -> Result<SetupContext> {
    let max_ptp_tolerance = 5000; // in nanoseconds

    let mut buf = [0u8; std::mem::size_of::<Message>()];
    let socket = &context.socket;
    let interval = context.interval.clone();
    let mut ptp_diff = u128::MAX;
    println!("PTP: {:?}", context.latency_reg);
    println!("--------------------Start PTP Mechanism---------------------");
    let mut j = 0;
    let mut ptp_regulation = 1000;
    let mut next_tick = Instant::now() + interval;
    while ptp_diff > ptp_regulation {
        let start_time = Instant::now();
        let encoded_msg = encode_message(MessageType::PTP, j, 0, 0, 0, 0.0, 0.0, 0)?;
        socket.send_to(&encoded_msg, &context.src_client)?;
        increment_message_count();
        let wait_time = Instant::now()
            + Duration::from_nanos(
                (context.needed_time as f64 / context.latency_reg).round() as u64
            );
        wait_until(wait_time);
        update_user_zero();

        loop {
            if start_time.elapsed() > TIMEOUT_DURATION {
                println!("Timeout in PTP Phase");
                next_tick = Instant::now() + interval;
                if increment_timeout_count() {
                    println!("Too many timeouts, stopping PTP Phase.");
                    return Ok(update_context(
                        context,
                        SetupContextOverrides {
                            running: Some(Arc::new(AtomicBool::new(false))),
                            ..Default::default()
                        },
                    ));
                }
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((_amt, _src)) => {
                    let end_time = Instant::now();
                    let ptp_duration = end_time - start_time;
                    ptp_diff = ptp_duration.as_nanos().abs_diff(context.needed_time);
                    //println!("PTP-Diff = {} {}", ptp_diff, j);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_nanos(10));
                }
                Err(e) => {
                    eprintln!("Error while receiving: {}", e);
                }
            }
        }

        j += 1;
        ptp_regulation += 1;

        wait_until(next_tick);
        next_tick += interval;

        if ptp_regulation > max_ptp_tolerance {
            println!(
                "PTP Phase exceeded a tolerance of {} , stopping.",
                max_ptp_tolerance
            );
            return Ok(update_context(
                context,
                SetupContextOverrides {
                    ptp_result: Some(false),
                    ..Default::default()
                },
            ));
        }
    }
    println!("PTP-Diff = {} {}", ptp_diff, j);
    return Ok(update_context(
        context,
        SetupContextOverrides {
            ptp_result: Some(true),
            ..Default::default()
        },
    ));
}

fn latency_test_phase(context: &SetupContext) -> Result<SetupContext> {
    let test_mesg_count: u64 = 1000;
    let max_tolerance = 10000; // in nanoseconds
    let mut i = 0;
    let mut buf = [0u8; std::mem::size_of::<Message>()];
    let socket = &context.socket;
    let interval = context.interval.clone();
    println!("---------------------Start Latency Test---------------------");
    let mut next_tick = Instant::now() + interval;
    let mut timestamps: Vec<PTPTimestampSet> =
        vec![PTPTimestampSet::default(); test_mesg_count as usize];

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
        socket.send_to(&encoded_msg, &context.src_client)?;
        increment_message_count();

        let mut server_kernel_sent =
            Instant::now().duration_since(read_user_zero()).as_nanos() as u64;
        if let Some(event) = wait_for_event(i, MessageType::NtpResult, 2) {
            server_kernel_sent = event.timestamp - get_kernel_zero();
        }

        loop {
            if start_time.elapsed() > TIMEOUT_DURATION {
                println!("Timeout in Latency Test Phase");
                if i > 0{
                    i = i - 1;
                }
                next_tick = Instant::now() + interval;
                if increment_timeout_count() {
                    println!("Too many timeouts, stopping Test Phase.");
                    return Ok(update_context(
                        context,
                        SetupContextOverrides {
                            running: Some(Arc::new(AtomicBool::new(false))),
                            ..Default::default()
                        },
                    ));
                }
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((amt, _src)) => {
                    let mut server_arrival_kernel =
                        Instant::now().duration_since(read_user_zero()).as_nanos() as u64;

                    let msg: Message = *bytemuck::from_bytes::<Message>(&buf[..amt]);
                    let number = msg.seq;

                    let server_arrival = Instant::now().duration_since(read_user_zero()).as_nanos();

                    if let Some(event) = wait_for_event(number, MessageType::NtpResult, 1) {
                        server_arrival_kernel = event.timestamp - get_kernel_zero();
                    }

                    match (msg.first_u128, msg.second_u128, msg.timestamp) {
                        (server_sent, client_arrival, client_sent) => {
                            if i < test_mesg_count {
                                timestamps[index].server_arrival = server_arrival;
                                timestamps[index].server_arrival_kernel =
                                    server_arrival_kernel as u128;
                                timestamps[index].server_sent = server_sent;
                                timestamps[index].server_kernel_sent = server_kernel_sent as u128;
                                timestamps[index].client_arrival = client_arrival;
                            }
                            if i > 0 {
                                timestamps[index - 1].client_sent = Some(client_sent);
                            }
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_nanos(10));
                }
                Err(e) => {
                    eprintln!("Error while receiving: {}", e);
                }
            }
        }
        wait_until(next_tick);
        next_tick += interval;
        i = i + 1;
    }
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
            println!("#{i}: Incomplete timestamp set");
            return Ok(update_context(
                context,
                SetupContextOverrides {
                    latency_result: Some(false),
                    ..Default::default()
                },
            ));
        }
    }
    let med = median(&diff_all);

    if med.abs() > max_tolerance as i128 {
        if med < 0 {
            println!("Median is too low: {}", med);
            return Ok(update_context(
                context,
                SetupContextOverrides {
                    latency_reg: Some(context.latency_reg + 0.02),
                    latency_result: Some(false),
                    ..Default::default()
                },
            ));
        } else {
            println!("Median is too high: {}", med);
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
}

fn calculation_phase(context: &SetupContext) -> Result<SetupContext> {
    let mut buf = [0u8; std::mem::size_of::<Message>()];
    let socket = &context.socket;
    let interval = context.interval.clone();
    println!("Start Calculation");
    let context_time: u64 = context.time.as_str().parse().expect("Invalid number in time");
    let num_points =  (context_time * 1000000000) / TIMEOUT_NS; 

    let mut points = Vec::with_capacity(num_points as usize);
    let mut latency: Vec<CalcTimestampSet> = vec![CalcTimestampSet::default(); num_points as usize];

    let mut last_y = 0.0;
    let calc_time = SystemTime::now();
    let mut next_tick = Instant::now() + interval;
    let mut i = 0;
    

    while calc_time.elapsed()?.as_secs() < context_time {
        let index = i as usize;
        //let calc_start_time = Instant::now();
        let theta = 2.0 * PI * (i as f64) / (num_points as f64);
        let x = RADIUS * theta.cos();
        let calc_send_time = Instant::now();
        let calc_send_elapsed = calc_send_time.duration_since(read_user_zero());

        let encoded_msg = encode_message(MessageType::Calc, i, 0, 0, 0, theta, RADIUS, 0)?;
        socket.send_to(&encoded_msg, &context.src_client)?;
        increment_message_count();

        let mut server_sent_kernel =
            Instant::now().duration_since(read_user_zero()).as_nanos() as u64;

        if let Some(event) = wait_for_event(i, MessageType::Calc, 2) {
            server_sent_kernel = event.timestamp - get_kernel_zero();
        }

        let event_snapshot_queue = wait_for_event(i, MessageType::Calc, 3);
        let server_queue = event_snapshot_queue.unwrap().timestamp - get_kernel_zero();

        let calc_send_duration;
        loop {
            if calc_send_time.elapsed() > TIMEOUT_DURATION {
                println!("Timeout in Latency Calc Phase");
                if i > 0{
                    i = i - 1;
                }
                next_tick = Instant::now() + interval;
                if increment_timeout_count() {
                    println!("Too many timeouts, stopping Calculation Phase.");
                    return Ok(update_context(
                        context,
                        SetupContextOverrides {
                            running: Some(Arc::new(AtomicBool::new(false))),
                            ..Default::default()
                        },
                    ));
                }
                break;
            }
            match socket.recv_from(&mut buf) {
                Ok((amt, _src)) => {
                    let end_time = Instant::now();
                    let calc_end_time = end_time.duration_since(read_user_zero());
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buf[..amt]);

                    let number = msg.seq;

                    let mut server_arrival_kernel =
                        Instant::now().duration_since(read_user_zero()).as_nanos() as u64;

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
                            last_y = if calc_send_duration <= TIMEOUT_NS as u128 {
                                y
                            } else {
                                last_y - 2.0
                            };
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_nanos(10));
                }
                Err(e) => {
                    eprintln!("Error while receiving: {}", e);
                }
            }
        }

        points.push((x, last_y));
        wait_until(next_tick);
        next_tick += interval;
        i += 1;
    }

    let encoded_msg = encode_message(MessageType::Calc, u64::MAX, 0, 0, 0, 0.0, 0.0, 0)?;
    socket.send_to(&encoded_msg, &context.src_client)?;
    increment_message_count();
    let start_time = Instant::now();
    loop {
        if start_time.elapsed() > TIMEOUT_DURATION {
            println!("Timeout in Latency Test Phase");
            if increment_timeout_count() {
                println!("Too many timeouts, stopping Calculation Phase.");
                return Ok(update_context(
                    context,
                    SetupContextOverrides {
                        running: Some(Arc::new(AtomicBool::new(false))),
                        ..Default::default()
                    },
                ));
            }
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((amt, _src)) => {
                let msg: Message = *bytemuck::from_bytes::<Message>(&buf[..amt]);
                match (msg.second_u128, msg.timestamp) {
                    (client_sent, client_queue) => {
                        latency[num_points as usize - 1].client_sent_kernel = Some(client_sent);
                        latency[num_points as usize - 1].client_queue = Some(client_queue);
                        break;
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_nanos(10));
            }
            Err(e) => {
                eprintln!("Error while receiving: {}", e);
            }
        }
    }
    return Ok(update_context(
        context,
        SetupContextOverrides {
            calculation_result: Some((points, latency)),
            ..Default::default()
        },
    ));
}

fn save_results(context: &SetupContext) -> Result<SetupContext> {
    let result_path = format!(
        "../{}/results/standard_{}/frequency_{}/bandwith_{}/qos_{}/udp/",
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

fn handle_error(context: &SetupContext) -> Result<()> {
    let socket = &context.socket;
    let encoded_msg = encode_message(MessageType::Calc, u64::MAX, 0, 0, 0, 0.0, 0.0, 0)?;
    for _ in 0..100 {
        if let Err(e) = socket.send_to(&encoded_msg, &context.src_client) {
            eprintln!("Error sending error message: {}", e);
            thread::sleep(Duration::from_millis(100));
        }
    }

    increment_message_count();
    Ok(())
}
fn main() -> anyhow::Result<()> {
    let context = setup()?;

    let event_queue_rec = Arc::new(Mutex::new(VecDeque::new()));
    let event_queue_send = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));
    
    CURRENT_EVENT_REC.set(event_queue_rec.clone()).unwrap();
    CURRENT_EVENT_SEND.set(event_queue_send.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    let event_ref_rec = CURRENT_EVENT_REC.get().unwrap().clone();
    let event_ref_send = CURRENT_EVENT_SEND.get().unwrap().clone();
    let queue_event_ref = CURRENT_QUEUE_EVENT.get().unwrap().clone();

    let open_skel = MonitoreSkelBuilder::default().open();
    println!("Skelett ge  ffnet.");

    let mut skel = open_skel?.load()?;
    println!("Skelett geladen.");

    skel.attach()?;

    println!("eBPF-Programm l  uft  ^` ");
    let r = context.running.clone();
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
        match event.event_type{
            0 if event.pid == my_pid => {
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
                eprintln!("⚠️ Unknown event type: {}", event.event_type);
            }
        }

        0
    })?;

    let ringbuf = ringbuf_builder.build()?;

    // Separate Thread f  r Polling des Ringbuffers starten
    let _handle = thread::spawn(move || {
        while r.load(Ordering::Relaxed) {
            ringbuf.poll(Duration::from_millis(100)).unwrap();
        }
    });
    println!("Kerneltime: {}", get_kernel_zero());
    run_state_machine(context)?;
    Ok(())
}

fn run_state_machine(mut context: SetupContext) -> Result<()> {
    let mut state = State::WaitForStart;

    loop {
        state = match state {
            State::WaitForStart => {
                context = wait_for_start_message(&context);
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
                break;
            }

            State::Error => {
                handle_error(&context)?;
                break;
            }
        }
    }

    Ok(())
}
