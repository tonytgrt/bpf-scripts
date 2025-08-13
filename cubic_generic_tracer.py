#!/usr/bin/env python3
"""
cubic_generic_tracer.py - Track CUBIC congestion control using generic TCP hooks
Works even when cubictcp_cong_avoid is inlined or not directly traceable
"""

from bcc import BPF
import ctypes as ct
import signal
import sys
import time
from datetime import datetime

# BPF program that hooks into generic TCP functions
bpf_text = """
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/ptrace.h>

// TCP congestion ops structure
struct tcp_congestion_ops {
    struct list_head list;
    u32 key;
    u32 flags;
    char name[16];
    void *owner;
    // Function pointers - we just need to know the name
};

// CUBIC/BIC TCP state structure
// These offsets might need adjustment based on kernel version
struct bictcp {
    u32 cnt;           // increase cwnd by 1 after ACKs
    u32 last_max_cwnd; // last max congestion window
    u32 last_cwnd;     // last cwnd
    u32 last_time;     // time when updated last_cwnd  
    u32 bic_origin_point; // origin of bic function
    u32 bic_K;         // time to origin from beginning
    u32 delay_min;     // min delay (usec)
    u32 epoch_start;   // beginning of epoch
    u32 ack_cnt;       // number of acks
    u32 tcp_cwnd;      // estimated tcp cwnd
    u16 unused;
    u8 sample_cnt;     // samples to decide curr_rtt
    u8 found;          // exit point found?
    u32 round_start;   // beginning of round
    u32 end_seq;       // end_seq of round
    u32 last_ack;      // last ack time
    u32 curr_rtt;      // minimum rtt of current round
};

struct cubic_info {
    u64 ts_ns;
    u32 pid;
    u32 tgid;
    
    // Connection info
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    
    // TCP state
    u32 cwnd;
    u32 ssthresh;
    u32 rtt;
    u32 rtt_min;
    u8 ca_state;
    
    // CUBIC state (if available)
    u32 cnt;
    u32 last_max_cwnd;
    u32 bic_K;
    u32 delay_min;
    u32 tcp_cwnd;
    u8 is_cubic;
    
    char comm[16];
    char ca_name[16];
};

BPF_PERF_OUTPUT(cubic_events);
BPF_HASH(tracked_socks, struct sock*, u8);

// Helper to check if using CUBIC
static inline int is_cubic_cc(struct sock *sk) {
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct tcp_congestion_ops *ca_ops;
    char ca_name[16] = {};
    
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (!ca_ops) return 0;
    
    bpf_probe_read_kernel_str(&ca_name, sizeof(ca_name), &ca_ops->name);
    
    // Check if name contains "cubic" or "bic"
    if (ca_name[0] == 'c' && ca_name[1] == 'u' && ca_name[2] == 'b') {
        return 1;  // cubic
    }
    if (ca_name[0] == 'b' && ca_name[1] == 'i' && ca_name[2] == 'c') {
        return 1;  // bictcp
    }
    
    return 0;
}

// Helper to extract CUBIC state
static inline void extract_cubic_state(struct sock *sk, struct cubic_info *info) {
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct tcp_congestion_ops *ca_ops;
    
    // Get basic TCP info
    bpf_probe_read_kernel(&info->cwnd, sizeof(u32), &tp->snd_cwnd);
    bpf_probe_read_kernel(&info->ssthresh, sizeof(u32), &tp->snd_ssthresh);
    bpf_probe_read_kernel(&info->rtt, sizeof(u32), &tp->srtt_us);
    bpf_probe_read_kernel(&info->rtt_min, sizeof(u32), &tp->rtt_min);
    bpf_probe_read_kernel(&info->ca_state, sizeof(u8), &icsk->icsk_ca_state);
    
    // Get CA name
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&info->ca_name, sizeof(info->ca_name), &ca_ops->name);
    }
    
    // Try to get CUBIC-specific state if using CUBIC
    info->is_cubic = is_cubic_cc(sk);
    if (info->is_cubic) {
        struct bictcp *ca = (struct bictcp *)icsk->icsk_ca_priv;
        if (ca) {
            bpf_probe_read_kernel(&info->cnt, sizeof(u32), &ca->cnt);
            bpf_probe_read_kernel(&info->last_max_cwnd, sizeof(u32), &ca->last_max_cwnd);
            bpf_probe_read_kernel(&info->bic_K, sizeof(u32), &ca->bic_K);
            bpf_probe_read_kernel(&info->delay_min, sizeof(u32), &ca->delay_min);
            bpf_probe_read_kernel(&info->tcp_cwnd, sizeof(u32), &ca->tcp_cwnd);
        }
    }
    
    // Get connection info
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&info->saddr, sizeof(u32), &inet->inet_saddr);
    bpf_probe_read_kernel(&info->daddr, sizeof(u32), &inet->inet_daddr);
    bpf_probe_read_kernel(&info->sport, sizeof(u16), &inet->inet_sport);
    bpf_probe_read_kernel(&info->dport, sizeof(u16), &inet->inet_dport);
}

// Trace tcp_ack - called for every ACK
int trace_tcp_ack(struct pt_regs *ctx, struct sock *sk) {
    // Only track CUBIC connections
    if (!is_cubic_cc(sk)) return 0;
    
    // Rate limit - only sample some ACKs
    if (bpf_get_prandom_u32() % 100 > 1) return 0;  // Sample 1% of ACKs
    
    struct cubic_info info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    info.ts_ns = bpf_ktime_get_ns();
    info.pid = pid_tgid;
    info.tgid = pid_tgid >> 32;
    
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    extract_cubic_state(sk, &info);
    
    cubic_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Trace tcp_slow_start - catches slow start exits
int trace_slow_start(struct pt_regs *ctx, struct tcp_sock *tp, u32 acked) {
    struct sock *sk = (struct sock *)tp;
    
    if (!is_cubic_cc(sk)) return 0;
    
    struct cubic_info info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    info.ts_ns = bpf_ktime_get_ns();
    info.pid = pid_tgid;
    info.tgid = pid_tgid >> 32;
    
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    extract_cubic_state(sk, &info);
    
    cubic_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Trace tcp_cong_avoid_ai - called for congestion avoidance
int trace_cong_avoid_ai(struct pt_regs *ctx, struct tcp_sock *tp, u32 w, u32 acked) {
    struct sock *sk = (struct sock *)tp;
    
    if (!is_cubic_cc(sk)) return 0;
    
    struct cubic_info info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    info.ts_ns = bpf_ktime_get_ns();
    info.pid = pid_tgid;
    info.tgid = pid_tgid >> 32;
    
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    extract_cubic_state(sk, &info);
    
    cubic_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Alternative: trace generic congestion control entry point
int trace_tcp_cong_control(struct pt_regs *ctx, struct sock *sk, u32 ack, u32 acked) {
    if (!is_cubic_cc(sk)) return 0;
    
    // Rate limit
    if (bpf_get_prandom_u32() % 100 > 5) return 0;  // Sample 5%
    
    struct cubic_info info = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    info.ts_ns = bpf_ktime_get_ns();
    info.pid = pid_tgid;
    info.tgid = pid_tgid >> 32;
    
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    extract_cubic_state(sk, &info);
    
    cubic_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}
"""

class CubicInfo(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tgid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("cwnd", ct.c_uint),
        ("ssthresh", ct.c_uint),
        ("rtt", ct.c_uint),
        ("rtt_min", ct.c_uint),
        ("ca_state", ct.c_ubyte),
        ("cnt", ct.c_uint),
        ("last_max_cwnd", ct.c_uint),
        ("bic_K", ct.c_uint),
        ("delay_min", ct.c_uint),
        ("tcp_cwnd", ct.c_uint),
        ("is_cubic", ct.c_ubyte),
        ("comm", ct.c_char * 16),
        ("ca_name", ct.c_char * 16),
    ]

class CubicGenericTracer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.start_time = time.time()
        self.event_count = 0
        self.connections = {}
        
    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(CubicInfo)).contents
        self.event_count += 1
        
        # Track connection
        conn_key = (event.saddr, event.sport, event.daddr, event.dport)
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'first_seen': event.ts_ns,
                'last_seen': event.ts_ns,
                'count': 1,
                'max_cwnd': event.cwnd,
                'min_rtt': event.rtt_min
            }
        else:
            conn = self.connections[conn_key]
            conn['last_seen'] = event.ts_ns
            conn['count'] += 1
            conn['max_cwnd'] = max(conn['max_cwnd'], event.cwnd)
            if event.rtt_min > 0:
                conn['min_rtt'] = min(conn['min_rtt'], event.rtt_min) if conn['min_rtt'] > 0 else event.rtt_min
        
        if self.verbose:
            import socket
            saddr = socket.inet_ntoa(event.saddr.to_bytes(4, 'little'))
            daddr = socket.inet_ntoa(event.daddr.to_bytes(4, 'little'))
            sport = socket.ntohs(event.sport)
            dport = socket.ntohs(event.dport)
            
            ca_state_names = {
                0: "Open",
                1: "Disorder", 
                2: "CWR",
                3: "Recovery",
                4: "Loss"
            }
            ca_state = ca_state_names.get(event.ca_state, f"Unknown({event.ca_state})")
            
            print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                  f"[{event.comm.decode('utf-8', 'replace'):12s}] "
                  f"CA={event.ca_name.decode('utf-8', 'replace'):8s} "
                  f"cwnd={event.cwnd:<5} ss={event.ssthresh:<5} "
                  f"cnt={event.cnt:<4} K={event.bic_K:<6} "
                  f"rtt={event.rtt//1000:<4}ms "
                  f"state={ca_state:8s} "
                  f"{saddr}:{sport} -> {daddr}:{dport}")
    
    def print_summary(self):
        print("\n=== CUBIC Tracking Summary ===")
        print(f"Total runtime: {time.time() - self.start_time:.2f} seconds")
        print(f"Total events captured: {self.event_count}")
        print(f"Unique connections tracked: {len(self.connections)}")
        
        if self.connections:
            print("\nTop connections by packet count:")
            sorted_conns = sorted(self.connections.items(), 
                                key=lambda x: x[1]['count'], reverse=True)
            
            import socket
            for i, (conn_key, stats) in enumerate(sorted_conns[:5]):
                saddr, sport, daddr, dport = conn_key
                saddr_str = socket.inet_ntoa(saddr.to_bytes(4, 'little'))
                daddr_str = socket.inet_ntoa(daddr.to_bytes(4, 'little'))
                sport_h = socket.ntohs(sport)
                dport_h = socket.ntohs(dport)
                duration = (stats['last_seen'] - stats['first_seen']) / 1e9
                
                print(f"  {i+1}. {saddr_str}:{sport_h} -> {daddr_str}:{dport_h}")
                print(f"     Packets: {stats['count']}, Max cwnd: {stats['max_cwnd']}, "
                      f"Min RTT: {stats['min_rtt']//1000}ms, Duration: {duration:.1f}s")
    
    def run(self):
        # Compile BPF program
        self.b = BPF(text=bpf_text)
        
        # Try to attach to various probe points
        attached = []
        
        # List of functions to try
        probes = [
            ("tcp_ack", "trace_tcp_ack"),
            ("tcp_slow_start", "trace_slow_start"),
            ("tcp_cong_avoid_ai", "trace_cong_avoid_ai"),
            ("tcp_cong_control", "trace_tcp_cong_control"),
        ]
        
        for func, probe in probes:
            try:
                self.b.attach_kprobe(event=func, fn_name=probe)
                attached.append(func)
                print(f"✓ Attached to {func}")
            except Exception as e:
                print(f"✗ Could not attach to {func}: {e}")
        
        if not attached:
            print("\nError: Could not attach to any probe points!")
            print("The kernel may not have the expected functions.")
            return
        
        print(f"\nSuccessfully attached to {len(attached)} probe points")
        print("Tracking CUBIC congestion control... Press Ctrl-C to stop")
        print("-" * 60)
        
        # Open perf buffer
        self.b["cubic_events"].open_perf_buffer(self.handle_event)
        
        # Main loop
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching probes...")
            self.print_summary()

def main():
    import argparse
    import os
    
    parser = argparse.ArgumentParser(
        description='Track CUBIC congestion control using generic TCP hooks'
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Print detailed output for each event')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)
    
    tracer = CubicGenericTracer(verbose=args.verbose)
    tracer.run()

if __name__ == "__main__":
    main()