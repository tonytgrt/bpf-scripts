#!/usr/bin/env python3
"""
cubictcp_cong_avoid_tracer.py - Comprehensive TCP CUBIC congestion avoidance tracer
Traces the cubictcp_cong_avoid function and its key decision branches using eBPF

Based on disassembly analysis of cubictcp_cong_avoid from vmlinux
"""

from bcc import BPF
import signal
import sys
import time
import argparse
from datetime import datetime
from collections import defaultdict
import ctypes as ct

# BPF program
bpf_text = """
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/ptrace.h>

// CUBIC state structure offsets (from tcp_cubic.c analysis)
#define BICTCP_CNT_OFFSET        0x510  // ca->cnt at offset 0x510
#define BICTCP_LAST_MAX_CWND     0x514  // ca->last_max_cwnd
#define BICTCP_LAST_CWND         0x518  // ca->last_cwnd  
#define BICTCP_LAST_TIME         0x51c  // ca->last_time
#define BICTCP_ORIGIN_POINT      0x520  // ca->bic_origin_point
#define BICTCP_K                 0x524  // ca->bic_K
#define BICTCP_DELAY_MIN         0x528  // ca->delay_min
#define BICTCP_EPOCH_START       0x52c  // ca->epoch_start
#define BICTCP_ACK_CNT           0x530  // ca->ack_cnt
#define BICTCP_TCP_CWND          0x534  // ca->tcp_cwnd

// TCP sock offsets
#define TCP_CWND_OFFSET          0x6d0  // tcp_sock->snd_cwnd
#define TCP_SSTHRESH_OFFSET      0x6cc  // tcp_sock->snd_ssthresh

// Event types
#define EVENT_ENTRY              1
#define EVENT_SLOW_START         2
#define EVENT_CUBIC_UPDATE       3
#define EVENT_TCP_FRIENDLY       4
#define EVENT_EXIT               5
#define EVENT_CWND_LIMITED       6
#define EVENT_EPOCH_START        7

// Branch decision types  
#define BRANCH_NONE              0
#define BRANCH_BELOW_ORIGIN      1
#define BRANCH_ABOVE_ORIGIN      2
#define BRANCH_TCP_FASTER        3
#define BRANCH_CUBIC_FASTER      4

struct cubic_event {
    u64 ts_ns;
    u32 pid;
    u32 tgid;
    u8 event_type;
    u8 branch_type;
    
    // TCP state
    u32 cwnd;
    u32 ssthresh;
    u32 acked;
    u8 in_slow_start;
    
    // CUBIC state
    u32 cnt;
    u32 last_max_cwnd;
    u32 last_cwnd;
    u32 last_time;
    u32 bic_origin_point;
    u32 bic_K;
    u32 delay_min;
    u32 epoch_start;
    u32 ack_cnt;
    u32 tcp_cwnd;
    
    // Connection info
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    
    char comm[16];
};

BPF_PERF_OUTPUT(cubic_events);
BPF_HASH(flow_state, struct sock *, struct cubic_event);

// Statistics
BPF_HISTOGRAM(cnt_distribution);
BPF_HISTOGRAM(cwnd_distribution);
BPF_ARRAY(slow_start_exits, u64, 1);
BPF_ARRAY(epoch_starts, u64, 1);
BPF_ARRAY(tcp_friendly_activations, u64, 1);

// Helper to extract CUBIC state from socket
static inline void extract_cubic_state(struct sock *sk, struct cubic_event *event) {
    // Read TCP state
    bpf_probe_read_kernel(&event->cwnd, sizeof(u32), 
                          (char *)sk + TCP_CWND_OFFSET);
    bpf_probe_read_kernel(&event->ssthresh, sizeof(u32), 
                          (char *)sk + TCP_SSTHRESH_OFFSET);
    
    // Determine if in slow start
    event->in_slow_start = (event->cwnd < event->ssthresh) ? 1 : 0;
    
    // Read CUBIC state variables
    bpf_probe_read_kernel(&event->cnt, sizeof(u32), 
                          (char *)sk + BICTCP_CNT_OFFSET);
    bpf_probe_read_kernel(&event->last_max_cwnd, sizeof(u32), 
                          (char *)sk + BICTCP_LAST_MAX_CWND);
    bpf_probe_read_kernel(&event->last_cwnd, sizeof(u32), 
                          (char *)sk + BICTCP_LAST_CWND);
    bpf_probe_read_kernel(&event->last_time, sizeof(u32), 
                          (char *)sk + BICTCP_LAST_TIME);
    bpf_probe_read_kernel(&event->bic_origin_point, sizeof(u32), 
                          (char *)sk + BICTCP_ORIGIN_POINT);
    bpf_probe_read_kernel(&event->bic_K, sizeof(u32), 
                          (char *)sk + BICTCP_K);
    bpf_probe_read_kernel(&event->delay_min, sizeof(u32), 
                          (char *)sk + BICTCP_DELAY_MIN);
    bpf_probe_read_kernel(&event->epoch_start, sizeof(u32), 
                          (char *)sk + BICTCP_EPOCH_START);
    bpf_probe_read_kernel(&event->ack_cnt, sizeof(u32), 
                          (char *)sk + BICTCP_ACK_CNT);
    bpf_probe_read_kernel(&event->tcp_cwnd, sizeof(u32), 
                          (char *)sk + BICTCP_TCP_CWND);
}

// Helper to extract connection info
static inline void extract_conn_info(struct sock *sk, struct cubic_event *event) {
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&event->saddr, sizeof(u32), &inet->inet_saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(u32), &inet->inet_daddr);
    bpf_probe_read_kernel(&event->sport, sizeof(u16), &inet->inet_sport);
    bpf_probe_read_kernel(&event->dport, sizeof(u16), &inet->inet_dport);
}

// Main entry point tracer
int trace_cong_avoid_entry(struct pt_regs *ctx, struct sock *sk, u32 ack, u32 acked) {
    struct cubic_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_ENTRY;
    event.acked = acked;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    extract_cubic_state(sk, &event);
    extract_conn_info(sk, &event);
    
    // Update statistics
    cnt_distribution.increment(bpf_log2l(event.cnt));
    cwnd_distribution.increment(bpf_log2l(event.cwnd));
    
    // Save state for later comparison
    flow_state.update(&sk, &event);
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace slow start exit (offset 0x61 from function start)
int trace_slow_start_exit(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct cubic_event *saved = flow_state.lookup(&sk);
    if (!saved) return 0;
    
    struct cubic_event event = *saved;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_SLOW_START;
    
    u32 idx = 0;
    u64 *counter = slow_start_exits.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        slow_start_exits.update(&idx, &val);
    }
    
    // Re-read current state after slow start
    extract_cubic_state(sk, &event);
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace when epoch starts (offset 0xbc from function start)  
int trace_epoch_start(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct cubic_event *saved = flow_state.lookup(&sk);
    if (!saved) return 0;
    
    struct cubic_event event = *saved;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_EPOCH_START;
    
    u32 idx = 0;
    u64 *counter = epoch_starts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        epoch_starts.update(&idx, &val);
    }
    
    extract_cubic_state(sk, &event);
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace TCP friendliness check (offset 0x1c2 from function start)
int trace_tcp_friendly(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct cubic_event *saved = flow_state.lookup(&sk);
    if (!saved) return 0;
    
    struct cubic_event event = *saved;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_TCP_FRIENDLY;
    
    extract_cubic_state(sk, &event);
    
    // Determine if TCP or CUBIC is faster
    if (event.tcp_cwnd > event.cwnd) {
        event.branch_type = BRANCH_TCP_FASTER;
        u32 idx = 0;
        u64 *counter = tcp_friendly_activations.lookup(&idx);
        if (counter) {
            (*counter)++;
        } else {
            u64 val = 1;
            tcp_friendly_activations.update(&idx, &val);
        }
    } else {
        event.branch_type = BRANCH_CUBIC_FASTER;
    }
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace CUBIC phase detection (below/above origin point)
int trace_cubic_phase(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct cubic_event *saved = flow_state.lookup(&sk);
    if (!saved) return 0;
    
    struct cubic_event event = *saved;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_CUBIC_UPDATE;
    
    extract_cubic_state(sk, &event);
    
    // This would need more complex logic to determine actual phase
    // For now, we use bic_K as a proxy
    if (event.last_time < event.bic_K) {
        event.branch_type = BRANCH_BELOW_ORIGIN;
    } else {
        event.branch_type = BRANCH_ABOVE_ORIGIN;
    }
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

class CubicEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tgid", ct.c_uint),
        ("event_type", ct.c_ubyte),
        ("branch_type", ct.c_ubyte),
        ("cwnd", ct.c_uint),
        ("ssthresh", ct.c_uint),
        ("acked", ct.c_uint),
        ("in_slow_start", ct.c_ubyte),
        ("cnt", ct.c_uint),
        ("last_max_cwnd", ct.c_uint),
        ("last_cwnd", ct.c_uint),
        ("last_time", ct.c_uint),
        ("bic_origin_point", ct.c_uint),
        ("bic_K", ct.c_uint),
        ("delay_min", ct.c_uint),
        ("epoch_start", ct.c_uint),
        ("ack_cnt", ct.c_uint),
        ("tcp_cwnd", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("comm", ct.c_char * 16),
    ]

class CubicTracer:
    def __init__(self, verbose=False, trace_branches=False):
        self.verbose = verbose
        self.trace_branches = trace_branches
        self.start_time = time.time()
        self.event_counts = defaultdict(int)
        self.branch_counts = defaultdict(int)
        
        # Event type names
        self.event_names = {
            1: "ENTRY",
            2: "SLOW_START",
            3: "CUBIC_UPDATE", 
            4: "TCP_FRIENDLY",
            5: "EXIT",
            6: "CWND_LIMITED",
            7: "EPOCH_START"
        }
        
        # Branch type names
        self.branch_names = {
            0: "NONE",
            1: "BELOW_ORIGIN",
            2: "ABOVE_ORIGIN",
            3: "TCP_FASTER",
            4: "CUBIC_FASTER"
        }
        
    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(CubicEvent)).contents
        
        self.event_counts[event.event_type] += 1
        self.branch_counts[event.branch_type] += 1
        
        if self.verbose:
            event_name = self.event_names.get(event.event_type, f"UNKNOWN({event.event_type})")
            branch_name = self.branch_names.get(event.branch_type, "")
            
            # Format IP addresses
            import socket
            saddr = socket.inet_ntoa(event.saddr.to_bytes(4, 'little'))
            daddr = socket.inet_ntoa(event.daddr.to_bytes(4, 'little'))
            sport = socket.ntohs(event.sport)
            dport = socket.ntohs(event.dport)
            
            print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                  f"[{event.comm.decode('utf-8', 'replace'):16s}] "
                  f"PID={event.pid:<7} "
                  f"{event_name:12s} {branch_name:12s} "
                  f"cwnd={event.cwnd:<6} ssthresh={event.ssthresh:<6} "
                  f"cnt={event.cnt:<4} K={event.bic_K:<6} "
                  f"tcp_cwnd={event.tcp_cwnd:<6} "
                  f"SS={'Y' if event.in_slow_start else 'N'} "
                  f"{saddr}:{sport} -> {daddr}:{dport}")
    
    def print_summary(self):
        print("\n=== CUBIC Congestion Avoidance Summary ===")
        print(f"Total runtime: {time.time() - self.start_time:.2f} seconds\n")
        
        print("Event counts:")
        for event_type, count in sorted(self.event_counts.items()):
            event_name = self.event_names.get(event_type, f"UNKNOWN({event_type})")
            print(f"  {event_name:20s}: {count:8d}")
        
        print("\nBranch decisions:")
        for branch_type, count in sorted(self.branch_counts.items()):
            if branch_type != 0:  # Skip NONE
                branch_name = self.branch_names.get(branch_type, f"UNKNOWN({branch_type})")
                print(f"  {branch_name:20s}: {count:8d}")
        
        # Print histograms
        print("\nCongestion window distribution (log2):")
        self.b["cwnd_distribution"].print_log2_hist("cwnd")
        
        print("\nCNT value distribution (log2):")
        self.b["cnt_distribution"].print_log2_hist("cnt")
        
        # Print counters
        print("\nKey events:")
        zero = ct.c_int(0)
        slow_start_count = self.b["slow_start_exits"][zero].value if zero in self.b["slow_start_exits"] else 0
        epoch_count = self.b["epoch_starts"][zero].value if zero in self.b["epoch_starts"] else 0
        tcp_friendly_count = self.b["tcp_friendly_activations"][zero].value if zero in self.b["tcp_friendly_activations"] else 0
        
        print(f"  Slow start exits: {slow_start_count}")
        print(f"  Epoch starts: {epoch_count}")
        print(f"  TCP friendly activations: {tcp_friendly_count}")
    
    def run(self):
        # Compile BPF program
        self.b = BPF(text=bpf_text)
        
        # Attach main entry probe
        self.b.attach_kprobe(event="cubictcp_cong_avoid", 
                             fn_name="trace_cong_avoid_entry")
        print("Attached to cubictcp_cong_avoid")
        
        # Attach to specific offsets for branch analysis if requested
        if self.trace_branches:
            try:
                # Slow start exit branch (offset 0x61)
                self.b.attach_kprobe(event="cubictcp_cong_avoid", 
                                    fn_name="trace_slow_start_exit",
                                    offset=0x61)
                print("Attached slow start exit probe at offset 0x61")
                
                # Epoch start (offset 0xbc)
                self.b.attach_kprobe(event="cubictcp_cong_avoid",
                                    fn_name="trace_epoch_start", 
                                    offset=0xbc)
                print("Attached epoch start probe at offset 0xbc")
                
                # TCP friendliness check (offset 0x1c2)
                self.b.attach_kprobe(event="cubictcp_cong_avoid",
                                    fn_name="trace_tcp_friendly",
                                    offset=0x1c2)
                print("Attached TCP friendly probe at offset 0x1c2")
                
            except Exception as e:
                print(f"Warning: Could not attach branch probes: {e}")
                print("Continuing with main probe only...")
        
        # Open perf buffer
        self.b["cubic_events"].open_perf_buffer(self.handle_event)
        
        print("\nTracing TCP CUBIC congestion avoidance... Hit Ctrl-C to end")
        print("-" * 80)
        
        # Main loop
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching probes...")
            self.print_summary()

def main():
    parser = argparse.ArgumentParser(
        description='Trace TCP CUBIC congestion avoidance algorithm',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic tracing
  sudo ./cubictcp_cong_avoid_tracer.py
  
  # Verbose output with all events
  sudo ./cubictcp_cong_avoid_tracer.py -v
  
  # Include branch analysis (requires correct offsets)
  sudo ./cubictcp_cong_avoid_tracer.py -b
  
  # Full analysis
  sudo ./cubictcp_cong_avoid_tracer.py -v -b
        """)
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Print detailed output for each event')
    parser.add_argument('-b', '--branches', action='store_true',
                       help='Trace branch decisions (requires correct kernel offsets)')
    
    args = parser.parse_args()
    
    # Check for root
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)
    
    tracer = CubicTracer(verbose=args.verbose, trace_branches=args.branches)
    tracer.run()

if __name__ == "__main__":
    import os
    main()