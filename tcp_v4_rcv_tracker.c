#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>

// Structure to hold packet information
struct packet_info {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 timestamp;
    u32 drop_reason;
};

// Structure for statistics
struct tcp_stats {
    u64 total_packets;
    u64 not_for_host;
    u64 no_socket;
    u64 time_wait;
    u64 checksum_error;
    u64 listen_state;
    u64 socket_busy;
    u64 xfrm_policy_drop;
    u64 new_syn_recv;
};

// Maps
BPF_HASH(stats_map, u32, struct tcp_stats);
BPF_PERF_OUTPUT(packet_events);
BPF_HASH(drop_reasons, u32, u64);

// Helper to extract packet info from skb
static inline int extract_packet_info(struct sk_buff *skb, struct packet_info *info) {
    // Read network header offset
    u16 network_header = 0;
    bpf_probe_read(&network_header, sizeof(network_header), 
                   (void *)skb + offsetof(struct sk_buff, network_header));
    
    // Get IP header
    struct iphdr iph = {};
    void *ip_header = (void *)skb + offsetof(struct sk_buff, head);
    bpf_probe_read(&ip_header, sizeof(ip_header), ip_header);
    ip_header = ip_header + network_header;
    bpf_probe_read(&iph, sizeof(iph), ip_header);
    
    info->saddr = iph.saddr;
    info->daddr = iph.daddr;
    
    // Get TCP header
    struct tcphdr tcph = {};
    void *tcp_header = ip_header + (iph.ihl * 4);
    bpf_probe_read(&tcph, sizeof(tcph), tcp_header);
    
    info->sport = ntohs(tcph.source);
    info->dport = ntohs(tcph.dest);
    info->timestamp = bpf_ktime_get_ns();
    
    return 0;
}

// Main entry - track overall statistics
int trace_tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    u32 key = 0;
    struct tcp_stats *stats, zero_stats = {};
    
    stats = stats_map.lookup_or_try_init(&key, &zero_stats);
    if (stats) {
        stats->total_packets++;
    }
    
    return 0;
}

// Track "not for host" branch (offset 0x73)
int trace_not_for_host(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->not_for_host++;
    }
    
    struct packet_info info = {};
    info.drop_reason = 2; // SKB_DROP_REASON_NOT_SPECIFIED
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Track "no socket found" branch (offset 0x722)
int trace_no_socket(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->no_socket++;
    }
    
    // Try to get skb from context
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct packet_info info = {};
    extract_packet_info(skb, &info);
    info.drop_reason = 3; // SKB_DROP_REASON_NO_SOCKET
    
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    // Track drop reason
    u32 reason = 3;
    u64 *count = drop_reasons.lookup(&reason);
    if (count) {
        (*count)++;
    } else {
        u64 init_count = 1;
        drop_reasons.update(&reason, &init_count);
    }
    
    return 0;
}

// Track TIME_WAIT state (offset 0x279)
int trace_time_wait(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->time_wait++;
    }
    
    return 0;
}

// Track checksum error (offset 0x2e8)
int trace_checksum_error(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->checksum_error++;
    }
    
    struct packet_info info = {};
    info.drop_reason = 5; // SKB_DROP_REASON_TCP_CSUM
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    // Track drop reason
    u32 reason = 5;
    u64 *count = drop_reasons.lookup(&reason);
    if (count) {
        (*count)++;
    } else {
        u64 init_count = 1;
        drop_reasons.update(&reason, &init_count);
    }
    
    return 0;
}

// Track LISTEN state processing (offset 0xedf)
int trace_listen_state(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->listen_state++;
    }
    
    return 0;
}

// Track socket busy/backlog (offset 0xec2)
int trace_socket_busy(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->socket_busy++;
    }
    
    return 0;
}

// Track XFRM policy drop (offset 0x8e5)
int trace_xfrm_policy_drop(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->xfrm_policy_drop++;
    }
    
    struct packet_info info = {};
    info.drop_reason = 14; // SKB_DROP_REASON_XFRM_POLICY
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Track NEW_SYN_RECV state (offset 0x5db)
int trace_new_syn_recv(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        stats->new_syn_recv++;
    }
    
    return 0;
}