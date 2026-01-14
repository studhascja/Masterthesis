#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* Required license declaration for eBPF programs */
char __license[] SEC("license") = "GPL";

/*
 * Stores the PID of the server process once it is detected.
 * Used later to associate incoming packets with the server.
 */
__u32 my_pid = 0;

/* Size of the MAC header in bytes */
#define MAC_HEADER_SIZE 14;

/*
 * Helper macro to safely read a member from a kernel structure.
 * This avoids direct dereferencing, which is not allowed in eBPF.
 */
#define member_read(destination, source_struct, source_member)                          \
    do                                                                                  \
    {                                                                                   \
        bpf_probe_read(                                                                 \
            destination,                                                                \
            sizeof(source_struct->source_member),                                       \
            ((char *)source_struct) + offsetof(typeof(*source_struct), source_member)); \
    } while (0)

/*
 * Message structure of Userspace contained in the TCP payload.
 * Packed to avoid padding added by the compiler.
 */
struct Message
{
    __u64 timestamp_lo;
    __u64 timestamp_hi;
    __u64 first_u128_lo;
    __u64 first_u128_hi;
    __u64 second_u128_lo;
    __u64 second_u128_hi;
    __u64 i_val_lo;
    __u64 i_val_hi;
    double first_f64;
    double second_f64;
    __u64 seq;
    __u8 msg_type;
    __u8 _padding[7];
} __attribute__((packed));

struct BPF_Data
{
    __u8 msg_type;
    __u8 _padding[7];
    __u64 seq;
    __u64 tcp_seq;
};

/*
 * Event structure written to the ring buffer and
 * consumed by user space.
 */
struct Event
{
    __u8 event_type; // To identify the type of event (e.g., uretprobe, skb consume, etc.)
    __u64 timestamp; // Kernel timestamp (ns)
    __u32 pid;       // Process ID
    struct BPF_Data data;
};

/*
 * Ring buffer map used to send events to user space.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/*
 * Uretprobe attached to server::measure_instant().
 * Triggered when the function returns.
 */
SEC("uretprobe//code/client/target/release/client:measure_instant")
int trace_measure_instant(struct pt_regs *ctx)
{
    __u64 timestamp = bpf_ktime_get_ns();
    struct Event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    /* Reserve space in the ring buffer */
    if (!e)
    {
        return 0;
    }

    /* Store server PID globally */
    my_pid = bpf_get_current_pid_tgid() >> 32;

    /* Fill event fields */
    e->event_type = 0;
    e->data.msg_type = 0;
    e->data.seq = 0;
    e->data.tcp_seq = 0;
    e->pid = my_pid; // Necessary for recognizing the message in user space
    e->timestamp = timestamp;

    /* Submit event to user space */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Tracepoint triggered when an sk_buff is consumed
 * Parses TCP packets and extracts application-level messages.
 */
SEC("tracepoint/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_consume_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    char *head;
    u16 mac_header;

    /* Read skb data pointer and MAC header offset */
    member_read(&head, skb, head); // Pointer to beginning of data
    member_read(&mac_header, skb, mac_header);

    /* Calculate IP header address */
    char *ip_header_address = head + mac_header + MAC_HEADER_SIZE;

    u8 ip_version;
    bpf_probe_read(&ip_version, sizeof(u8), ip_header_address);
    ip_version = ip_version >> 4 & 0xf;

    struct iphdr iph;
    bpf_probe_read(&iph, sizeof(iph), ip_header_address);

    /* Only process TCP packets */
    if (iph.protocol != IPPROTO_TCP)
        return 0;

    /* Inspect last byte of source IP */
    u32 src_ip = __builtin_bswap32(iph.saddr);
    u8 a = (src_ip >> 24) & 0xff;
    u8 b = (src_ip >> 16) & 0xff;
    u8 c = (src_ip >> 8) & 0xff;
    u8 d = src_ip & 0xff;

    // len of IP header in bytes (iph.ihl is in 32-bit words)
    u8 ip_header_len = iph.ihl * 4;

    // TCP-Header
    char *tcp_header = ip_header_address + ip_header_len;

    struct tcphdr tcph = {};
    bpf_probe_read(&tcph, sizeof(tcph), tcp_header);

    // len of TCP header in bytes (iph.ihl is in 32-bit words)
    u8 tcp_header_len = tcph.doff * 4;

    /* Only handle packets from server (IP ends with 1) */
    if (d == 1)
    {
        /* Read TCP payload */
        char *payload = tcp_header + tcp_header_len;

        struct Message msg = {};
        bpf_probe_read(&msg, sizeof(msg), payload);

        /* Validate message type */
        if (msg.msg_type < 0 || msg.msg_type > 5)
            return 0;

        /* Emit event */
        struct Event *event;
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
            return 0;

        /* Fill event fields */
        event->event_type = 1;
        event->data.msg_type = msg.msg_type;
        event->data.seq = msg.seq;
        event->data.tcp_seq = 0;
        event->pid = my_pid; // Necessary for recognizing the message in user space
        event->timestamp = bpf_ktime_get_ns();

        /* Submit event to user space */
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

/*
 * Tracepoint triggered when a packet is transmitted
 * by a network device.
 */
SEC("tracepoint/net/net_dev_xmit")
int handle_net_dev_xmit(struct trace_event_raw_net_dev_xmit *ctx)
{
    char devname[16] = {};

    /*
     * __data_loc field:
     * lower 16 bits store the offset to the string data
     */
    u32 offset = ctx->__data_loc_name & 0xFFFF;

    // Calculate Address: (void *)ctx + offset
    const char *name_ptr = (const char *)ctx + offset;

    /* Safely read the device name */
    bpf_core_read_str(devname, sizeof(devname), name_ptr);

    int pid = bpf_get_current_pid_tgid() >> 32;

    /* Read process name */
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Extract data of Tracepoint */
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    char *head;
    u16 mac_header;

    member_read(&head, skb, head); // Zeiger auf den Beginn der Daten
    member_read(&mac_header, skb, mac_header);

    char *ip_header_address = head + mac_header + MAC_HEADER_SIZE;
    struct iphdr iph;
    bpf_probe_read(&iph, sizeof(iph), ip_header_address);

    /* Only TCP packets */
    if (iph.protocol != IPPROTO_TCP)
        return 0;

    /* Extract last byte of source IP */
    u32 src_ip = __builtin_bswap32(iph.saddr);
    u8 d = src_ip & 0xff;

    /* Extract last byte of destination IP */
    u32 dst_ip = __builtin_bswap32(iph.daddr);
    u8 dd = dst_ip & 0xff;

    // len of IP header in bytes (iph.ihl is in 32-bit words)
    u8 ip_header_len = iph.ihl * 4;

    /* Only inspect packets sent by the "client" process */
    if (__builtin_strcmp(comm, "client") == 0)
    {
        char *tcp_header = ip_header_address + ip_header_len;

        struct tcphdr tcph = {};
        bpf_probe_read(&tcph, sizeof(tcph), tcp_header);
        u8 tcp_header_len = tcph.doff * 4;

        /* Filter by source and destination IP suffix client -> server */
        if (d == 43 && dd == 1)
        {
            char *payload = tcp_header + tcp_header_len;

            struct Message msg = {};
            bpf_probe_read(&msg, sizeof(msg), payload);
            if (msg.msg_type < 0 || msg.msg_type > 5)
                return 0;
            struct Event *event;
            event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (!event)
                return 0;

            /* Fill event fields */
            event->event_type = 2;
            event->data.msg_type = msg.msg_type;
            event->data.seq = msg.seq;
            event->data.tcp_seq = tcph.seq;
            event->pid = bpf_get_current_pid_tgid() >> 32; // Necessary for recognizing the message in user space
            event->timestamp = bpf_ktime_get_ns();

            /* Submit event to user space */
            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

/*
 * Tracepoint triggered when a packet is queued for transmission.
 */
SEC("tracepoint/net/net_dev_queue")
int handle_net_dev_queue(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    char *head;
    u16 mac_header;

    /* Only process packets from the server process */
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (__builtin_strcmp(comm, "client") != 0)
        return 0;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);

    char *ip_header_address = head + mac_header + MAC_HEADER_SIZE;

    struct iphdr iph;
    bpf_probe_read(&iph, sizeof(iph), ip_header_address);

    /* Only TCP packets */
    if (iph.protocol != IPPROTO_TCP)
        return 0;

    /* Extract last byte of source IP */
    u32 src_ip = __builtin_bswap32(iph.saddr);
    u8 d = src_ip & 0xff;

    /* Extract last byte of destination IP */
    u32 dst_ip = __builtin_bswap32(iph.daddr);
    u8 dd = dst_ip & 0xff;

    // len of IP header in bytes (iph.ihl is in 32-bit words)
    u8 ip_header_len = iph.ihl * 4;

    if (__builtin_strcmp(comm, "client") == 0)
    {
        // TCP-Header
        char *tcp_header = ip_header_address + ip_header_len;

        struct tcphdr tcph = {};
        bpf_probe_read(&tcph, sizeof(tcph), tcp_header);
        u8 tcp_header_len = tcph.doff * 4;

        /* Filter by source and destination IP suffix client -> server */
        if (d == 43 && dd == 1)
        {
            char *payload = tcp_header + tcp_header_len;

            struct Message msg = {};
            bpf_probe_read(&msg, sizeof(msg), payload);
            bpf_printk("msg_type=%d seq=%llu\n", msg.msg_type, msg.seq);
            struct Event *event;
            event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (!event)
                return 0;

            /* Fill event fields */
            event->event_type = 3;
            event->data.msg_type = 5;
            event->data.seq = tcph.seq;
            event->data.tcp_seq = 0;
            event->pid = bpf_get_current_pid_tgid() >> 32; // Necessary for recognizing the message in user space
            event->timestamp = bpf_ktime_get_ns();

            /* Submit event to user space */
            bpf_ringbuf_submit(event, 0);

            return 0;
        }
    }
}
