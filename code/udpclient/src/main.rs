use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{RingBufferBuilder};
use std::net::UdpSocket;
use std::time::{SystemTime, Duration};
use std::thread;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use bytemuck::{Pod, Zeroable, bytes_of, from_bytes};
use std::convert::TryFrom;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use once_cell::sync::Lazy;
use libc::{sched_param, pthread_setschedparam, pthread_self, SCHED_RR};
use libbpf_rs::skel::Skel;

include!("bpf/monitore.skel.rs");

static CURRENT_EVENT: Lazy<Arc<Mutex<VecDeque<Event>>>> = Lazy::new(|| Arc::new(Mutex::new(VecDeque::new())));
static MESSAGE_COUNT: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));
static USER_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
static KERNEL_ZERO: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum MessageType {
    Start = 0,
    NTP = 1,
    NTP_Result = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Zeroable, Pod)]
struct Message {
    timestamp: u128,
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
            _ => panic!("Invalid MessageType: {}", value),
        }
    }
}

#[no_mangle]
pub extern "C" fn measure_instant() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos() as u64
}

fn encode_message(msg_type: MessageType, seq: u64, timestamp: u128) -> Vec<u8> {
    let msg = Message {
        msg_type: msg_type as u8,
        seq,
        timestamp,
        _padding: [0u8; 7],
    };
    bytes_of(&msg).to_vec()
}

fn set_rt_priority(prio: i32) {
    unsafe {
        let mut param = sched_param { sched_priority: prio };
        let ret = pthread_setschedparam(pthread_self(), SCHED_RR, &mut param);
        if ret != 0 {
            eprintln!("Failed to set RT priority: {}", ret);
        }
    }
}

fn set_kernel_zero(val: u64) {
    *KERNEL_ZERO.lock().unwrap() = val;
}

fn get_kernel_zero() -> u64 {
    *KERNEL_ZERO.lock().unwrap()
}

fn set_user_zero(val: u64) {
    *USER_ZERO.lock().unwrap() = val;
}

fn get_user_zero() -> u64 {
    *USER_ZERO.lock().unwrap()
}

fn increment_message_count() -> u64 {
    let mut count = MESSAGE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

fn main() -> Result<()> {
    set_rt_priority(99);

    // UDP Setup
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.168.1.1:8080")?;

    // BPF Init
    let open_skel = MonitoreSkelBuilder::default().open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let maps = skel.maps();
    let event_queue = CURRENT_EVENT.clone();

    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(maps.events(), move |data: &[u8]| {
        if data.len() == std::mem::size_of::<Event>() {
            let event = *from_bytes::<Event>(data);
            if event.event_type == 0 {
                set_kernel_zero(event.timestamp);
            } else {
                let mut queue = event_queue.lock().unwrap();
                queue.push_back(event);
            }
        }
        0
    })?;
    let mut ringbuf = ringbuf_builder.build()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    thread::spawn(move || {
        while r.load(Ordering::Relaxed) {
            ringbuf.poll(Duration::from_millis(100)).unwrap();
        }
    });

    // Send Start message
    let start_msg = encode_message(MessageType::Start, 0, 0);
    socket.send(&start_msg)?;
    increment_message_count();

    let mut buf = [0u8; std::mem::size_of::<Message>()];
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
                Ok(MessageType::NTP) => {
                    let ts = measure_instant() as u128;
                    set_user_zero(ts as u64);
                    let encoded = encode_message(MessageType::NTP, msg.seq, ts);
                    socket.send(&encoded)?;
                    increment_message_count();
                }
                Ok(MessageType::NTP_Result) => {
                    let event = CURRENT_EVENT.lock().unwrap().pop_front();
                    if let Some(evt) = event {
                        let client_recv = evt.timestamp - get_kernel_zero();
                        let encoded = encode_message(MessageType::NTP_Result, msg.seq, client_recv as u128);
                        socket.send(&encoded)?;
                        increment_message_count();
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}
