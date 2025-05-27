#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

#define member_read(destination, source_struct, source_member)                 \
  do{                                                                          \
    bpf_probe_read(                                                            \
      destination,                                                             \
      sizeof(source_struct->source_member),                                    \
      ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
  } while(0)


struct Message {
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
}__attribute__((packed));

struct BPF_Data {
	__u8 msg_type;
	__u64 seq;
};

struct Event {
	__u64 timestamp;
	struct BPF_Data data;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("uretprobe//home/jakob/Masterthesis/code/client/target/debug/client:measure_instant")
int trace_measure_instant(struct pt_regs *ctx) {
    __u64 timestamp = bpf_ktime_get_ns();
    struct Event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    	if (!e) {
        return 0;
    	}
    	
        e->data.msg_type = 0;
        e->data.seq = 0;
        e->timestamp = timestamp;

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tracepoint/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_consume_skb *ctx) {
struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
char *head;
u16 mac_header;

member_read(&head, skb, head); // Zeiger auf den Beginn der Daten
member_read(&mac_header, skb, mac_header);


#define MAC_HEADER_SIZE 14;
char* ip_header_address = head + mac_header + MAC_HEADER_SIZE;


u8 ip_version;
bpf_probe_read(&ip_version, sizeof(u8), ip_header_address);
ip_version = ip_version >> 4 & 0xf;


bpf_printk("IP: %d", ip_version);
struct iphdr iph;
bpf_probe_read(&iph, sizeof(iph), ip_header_address);
if (iph.protocol != IPPROTO_TCP)
    return 0;

u32 src_ip = __builtin_bswap32(iph.saddr);
u8 a = (src_ip >> 24) & 0xff;
u8 b = (src_ip >> 16) & 0xff;
u8 c = (src_ip >> 8) & 0xff;
u8 d = src_ip & 0xff;

bpf_printk("IPv4 Src: %d.%d.%d.%d", a, b, c, d);

u8 ip_header_len = iph.ihl * 4;

// TCP-Header
char *tcp_header = ip_header_address + ip_header_len;

struct tcphdr tcph = {};
bpf_probe_read(&tcph, sizeof(tcph), tcp_header);

u8 tcp_header_len = tcph.doff * 4;
if(d == 1){
	char *payload = tcp_header + tcp_header_len;

	struct Message msg = {};
	bpf_probe_read(&msg, sizeof(msg), payload);	
	bpf_printk("Size of eBPF Message struct: %d", sizeof(struct Message));
	bpf_printk("TCP Payload: Type: %u Seq: %llu", msg.msg_type, msg.seq);
	
	struct Event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) return 0;

	event->data.msg_type = msg.msg_type;
	event->data.seq = msg.seq;
	event->timestamp = bpf_ktime_get_ns();

	bpf_ringbuf_submit(event, 0);
}

return 0;
}

SEC("tracepoint/net/net_dev_xmit")
int handle_net_dev_xmit(struct trace_event_raw_net_dev_xmit *ctx) {
    char devname[16] = {};
    
    // __data_loc-Feld: niederwertige 16 Bit enthalten den Offset
    u32 offset = ctx->__data_loc_name & 0xFFFF;

    // Adresse berechnen: (void *)ctx + offset
    const char *name_ptr = (const char *)ctx + offset;

    // String sicher lesen
    bpf_core_read_str(devname, sizeof(devname), name_ptr);

    int pid = bpf_get_current_pid_tgid() >> 32;
    
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (__builtin_strcmp(comm, "client") == 0) {
        // Nur dann etwas ausgeben, wenn der Prozessname übereinstimmt
        bpf_printk("net_dev_xmit: pid=%d dev=%s skbaddr=%p len=%u rc=%d comm=%s\n",
                   pid,
                   devname,
                   (void *)ctx->skbaddr,
                   ctx->len,
                   ctx->rc,
                   comm);
    }

    return 0;
}


