use anyhow::Result;
use bytemuck::{Pod, Zeroable};
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
use std::io::{BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

include!("bpf/monitore.skel.rs");

static CURRENT_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();
static CURRENT_QUEUE_EVENT: OnceLock<Arc<Mutex<VecDeque<Event>>>> = OnceLock::new();

static USER_ZERO: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

const TIMEOUT_NS: u64 = 3000000;
const NUM_POINTS: usize = 4000;
const RADIUS: f64 = 10.0;

#[derive(Serialize, Deserialize, Debug)]
enum Data {
    IntegerI128(i128),
    IntegerU128(u128),
    IntegerU64(u64),
    Float(f64),
}

struct SetupContext {
    stream: TcpStream,
    standard: Arc<String>,
    frequency: Arc<String>,
    bandwith: Arc<String>,
    qos: Arc<String>,
    running: Arc<AtomicBool>,
    interval: Duration,
    counter: u64,
    calculation_result: (Vec<(f64, f64)>, Vec<CalcTimestampSet>),
    needed_time: u128,
    ptp_result: bool,
    latency_result: bool,
}

#[derive(Default)]
struct SetupContextOverrides {
    pub running: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub counter: Option<u64>,
    pub calculation_result: Option<(Vec<(f64, f64)>, Vec<CalcTimestampSet>)>,
    pub needed_time: Option<u128>,
    pub ptp_result: Option<bool>,
    pub latency_result: Option<bool>,
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
fn update_context(base: &SetupContext, overrides: SetupContextOverrides) -> SetupContext {
    SetupContext {
        stream: base.stream.try_clone().expect("Failed to clone stream"),
        standard: base.standard.clone(),
        frequency: base.frequency.clone(),
        bandwith: base.bandwith.clone(),
        qos: base.qos.clone(),
        running: overrides.running.unwrap_or_else(|| base.running.clone()),
        interval: base.interval,
        counter: overrides.counter.unwrap_or_else(|| base.counter.clone()),
        calculation_result: overrides
            .calculation_result
            .unwrap_or_else(|| base.calculation_result.clone()),
        needed_time: overrides.needed_time.unwrap_or(base.needed_time),
        ptp_result: overrides.ptp_result.unwrap_or(base.ptp_result),
        latency_result: overrides.latency_result.unwrap_or(base.latency_result),
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

pub fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

fn wait_for_queue_event(timestamp: u64) -> Option<Event> {
    let queue_arc = CURRENT_QUEUE_EVENT
        .get()
        .expect("CURRENT_QUEUE_EVENT not initialized");
    let count = *MESSAGE_COUNT.lock().unwrap() as usize;

    let queue = queue_arc.lock().unwrap();
    //println!("Queue count: {} Msg count: {}", queue.len(), count);
    for i in 1..queue.len() {
        //let actual_timestamp = queue[queue.len() -i].timestamp;
        //println!("{:?} {:?}", actual_timestamp, timestamp);
        //        println!("Queue: {} Count: {}", queue.len(), count);
        if queue.len() >= count
            && (queue[queue.len() - i].timestamp - get_kernel_zero()) < timestamp
        {
            return Some(queue[queue.len() - i].clone());
        }
        thread::sleep(Duration::from_nanos(50));
    }
    println!("Falsch");
    return None;
}

fn wait_for_event(number: u64, msg_t: MessageType, event_t: u8) -> Event {
    let queue_arc = CURRENT_EVENT.get().expect("CURRENT_EVENT not initialized");
    loop {
        {
            let mut queue = queue_arc.lock().unwrap();
            while let Some(evt) = queue.pop_front() {
                let msg_type = MessageType::try_from(evt.data.msg_type).unwrap();
                //		    println!("MSG-Type: {:?}", msg_type);
                //		    let seq = evt.data.seq;
                //		    let even = evt.event_type;
                //		    println!("Number: {}, Actual: {}", number, seq);
                //		    println!("Event: {}, Actual: {}", event_t, even);
                if msg_type == msg_t && evt.data.seq == number && evt.event_type == event_t {
                    return evt;
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
    measure_instant();
}

fn read_user_zero() -> Instant {
    let time = USER_ZERO.lock().unwrap();
    *time
}

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
            println!("{}", i);
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
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
                    let number = msg.seq;
                    let event_snapshot = wait_for_event(number, MessageType::NTP, 1);

                    let end_time = event_snapshot.timestamp - get_kernel_zero();

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

fn ptp_phase(context: &SetupContext) -> Result<SetupContext> {
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    let max_ptp_tolerance = 5000; // in nanoseconds
    let mut ptp_diff = u128::MAX;
    let needed_time = context.needed_time.clone();
    let interval = context.interval.clone();
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
            let wait_time =
                Instant::now() + Duration::from_nanos((needed_time as f64 / 2.0).round() as u64);
            wait_until(wait_time);
            update_user_zero();

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
            let event_snapshot_sending = wait_for_event(i, MessageType::NtpResult, 2);
            let server_kernel_sent = event_snapshot_sending.timestamp - get_kernel_zero();

            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let end_time = Instant::now();
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
                    let number = msg.seq;
                    let event_snapshot = wait_for_event(number, MessageType::NtpResult, 1);
                    let server_arrival = end_time.duration_since(read_user_zero());
                    let server_arrival_kernel = event_snapshot.timestamp - get_kernel_zero();

                    let (server_sent, client_arrival, client_sent) =
                        (msg.first_u128, msg.second_u128, msg.timestamp);
                    if i < test_mesg_count {
                        timestamps[index].server_arrival = server_arrival.as_nanos();
                        timestamps[index].server_arrival_kernel = server_arrival_kernel as u128;
                        timestamps[index].server_sent = server_sent;
                        timestamps[index].server_kernel_sent = server_kernel_sent as u128;
                        timestamps[index].client_arrival = client_arrival;
                    }

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
            println!("Median is too high: {}", med);
            return Ok(update_context(
                context,
                SetupContextOverrides {
                    latency_result: Some(false),
                    ..Default::default()
                },
            ));
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

fn calculation_phase(context: &SetupContext) -> Result<SetupContext> {
    println!("Start Calculation");
    let mut buffer = [0u8; std::mem::size_of::<Message>()];
    let mut points = Vec::with_capacity(NUM_POINTS);
    let mut latency: Vec<CalcTimestampSet> = vec![CalcTimestampSet::default(); NUM_POINTS];
    let interval = context.interval.clone();
    let mut last_y = 0.0;
    let calc_time = SystemTime::now();
    let mut next_tick = Instant::now() + interval;
    let mut i = 0;
    if let Ok(mut stream) = context.stream.try_clone() {
        while calc_time.elapsed()?.as_secs() < 12 {
            let index = i as usize;
            //   let calc_start_time = Instant::now();
            //  let calc_start_elapsed = calc_start_time.duration_since(read_user_zero());
            let theta = 2.0 * PI * (i as f64) / (NUM_POINTS as f64);
            let x = RADIUS * theta.cos();
            let calc_send_time = Instant::now();
            let calc_send_elapsed = calc_send_time.duration_since(read_user_zero());

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

            let event_snapshot_sending = wait_for_event(i, MessageType::Calc, 2);
            let server_sent_kernel = event_snapshot_sending.timestamp - get_kernel_zero();

            let event_snapshot_queue = wait_for_queue_event(server_sent_kernel);
            let server_queue = event_snapshot_queue.unwrap().timestamp - get_kernel_zero();

            let calc_send_duration;
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let end_time = Instant::now();
                    let calc_end_time = end_time.duration_since(read_user_zero());
                    let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);

                    let number = msg.seq;
                    let event_snapshot = wait_for_event(number, MessageType::Calc, 1);
                    let server_arrival_kernel = event_snapshot.timestamp - get_kernel_zero();

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

        let encoded_msg = encode_message(
            MessageType::Calc,
            NUM_POINTS.try_into().unwrap(),
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
        match stream.read(&mut buffer) {
            Ok(n) if n > 0 => {
                let msg: Message = *bytemuck::from_bytes::<Message>(&buffer);
                match (msg.second_u128, msg.timestamp) {
                    (client_sent, client_queue) => {
                        latency[NUM_POINTS - 1].client_sent_kernel = Some(client_sent);
                        latency[NUM_POINTS - 1].client_queue = Some(client_queue);
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

fn save_results(context: &SetupContext) -> Result<SetupContext> {
    let result_path = format!(
        "../results/standard_{}/frequency_{}/bandwith_{}/qos_{}/tcp/",
        &context.standard, &context.frequency, &context.bandwith, &context.qos
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

fn main() -> Result<(), libbpf_rs::Error> {
    set_rt_priority(99);
    let event_queue = Arc::new(Mutex::new(VecDeque::new()));
    let queue_event_queue = Arc::new(Mutex::new(VecDeque::new()));

    CURRENT_EVENT.set(event_queue.clone()).unwrap();
    CURRENT_QUEUE_EVENT.set(queue_event_queue.clone()).unwrap();

    let event_ref = CURRENT_EVENT.get().expect("CURRENT_EVENT not initialized");
    let queue_event_ref = CURRENT_QUEUE_EVENT
        .get()
        .expect("CURRENT_EVENT not initialized");

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
            eprintln!(
                "Unexpected data size: {} {}",
                data.len(),
                std::mem::size_of::<Event>()
            );
            return 0;
        }

        let event = bytemuck::from_bytes::<Event>(data);
        if event.event_type == 0 {
            set_kernel_zero(event.timestamp);
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
        } */
        else if event.event_type == 3 {
            let mut queue = queue_event_ref.lock().unwrap();
            queue.push_back(*event);
        } else {
            let mut queue = event_ref.lock().unwrap();
            queue.push_back(*event);
        }
        0 // Rückgabewert: 0 bedeutet "OK"
    })?;
    let ringbuf = ringbuf_builder.build()?;

    // Separate Thread für Polling des Ringbuffers starten
    let _handle = thread::spawn(move || {
        while r.load(Ordering::Relaxed) {
            ringbuf.poll(Duration::from_millis(100)).unwrap();
        }
    });

    println!("Size of Message: {}", std::mem::size_of::<Message>());

    let args: Vec<String> = env::args().collect();
    let standard = Arc::new(args[1].clone());
    let frequency = Arc::new(args[2].clone());
    let bandwith = Arc::new(args[3].clone());
    let qos = Arc::new(args[4].clone());
    let listener = TcpListener::bind("192.168.1.1:8080")?;
    println!("Server läuft auf 192.168.1.1:8080");
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

                thread::spawn(move || {
                    let context = SetupContext {
                        stream,
                        standard,
                        frequency,
                        bandwith,
                        qos,
                        running: running_thread,
                        interval: Duration::from_nanos(TIMEOUT_NS),
                        counter: 0,
                        calculation_result: (Vec::new(), Vec::new()),
                        needed_time: u128::MAX,
                        ptp_result: false,
                        latency_result: false,
                    };
                    let _ = run_state_machine(context);
                });
            }
            Err(e) => eprintln!("Verbindungsfehler: {}", e),
        }
    }
    Ok(())
}

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
