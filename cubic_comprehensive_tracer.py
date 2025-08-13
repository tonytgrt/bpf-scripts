#!/usr/bin/env python3
"""
cubic_comprehensive_tracer.py - Comprehensive TCP CUBIC tracer
Tracks all available CUBIC functions and extracts detailed state
"""

from bcc import BPF
import ctypes as ct
import signal
import sys
import time
import argparse
from datetime import datetime
from collections import defaultdict
import socket
import struct

# BPF program
bpf_text = """
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/ptrace.h>

// CUBIC state structure (based on tcp_cubic.c)
struct bictcp {
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
    u16 unused;
    u8 sample_cnt;
    u8 found;
    u32 round_start;
    u32 end_seq;
    u32 last_ack;
    u32 curr_rtt;
};

// Event types for different functions
#define EVENT_CONG_AVOID    1
#define EVENT_INIT          2
#define EVENT_SSTHRESH      3
#define EVENT_STATE_CHANGE  4
#define EVENT_CWND_EVENT    5
#define EVENT_ACKED         6

// TCP CA states
#define TCP_CA_Open         0
#define TCP_CA_Disorder     1
#define TCP_CA_CWR          2
#define TCP_CA_Recovery     3
#define TCP_CA_Loss         4

struct cubic_event {
    u64 ts_ns;
    u32 pid;
    u32 tgid;
    u8 event_type;
    u8 new_state;  // For state change events
    
    // Connection info
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    
    // TCP state
    u32 cwnd;
    u32 ssthresh;
    u32 packets_out;
    u32 sacked_out;
    u32 lost_out;
    u32 retrans_out;
    u32 rtt_us;
    u32 mss_cache;
    
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
    u8 found;
    u32 curr_rtt;
    
    // Additional info
    u32 acked;  // For cong_avoid
    u32 rtt_sample;  // For acked
    
    char comm[16];
};

BPF_PERF_OUTPUT(cubic_events);

// Histograms for analysis
BPF_HISTOGRAM(cwnd_hist);
BPF_HISTOGRAM(cnt_hist);
BPF_HISTOGRAM(rtt_hist);
BPF_HISTOGRAM(acked_hist);

// Counters
BPF_ARRAY(event_counts, u64, 10);

// Helper to extract connection info
static inline void get_conn_info(struct sock *sk, struct cubic_event *event) {
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&event->saddr, sizeof(u32), &inet->inet_saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(u32), &inet->inet_daddr);
    bpf_probe_read_kernel(&event->sport, sizeof(u16), &inet->inet_sport);
    bpf_probe_read_kernel(&event->dport, sizeof(u16), &inet->inet_dport);
}

// Helper to extract TCP state
static inline void get_tcp_state(struct sock *sk, struct cubic_event *event) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    
    bpf_probe_read_kernel(&event->cwnd, sizeof(u32), &tp->snd_cwnd);
    bpf_probe_read_kernel(&event->ssthresh, sizeof(u32), &tp->snd_ssthresh);
    bpf_probe_read_kernel(&event->packets_out, sizeof(u32), &tp->packets_out);
    bpf_probe_read_kernel(&event->sacked_out, sizeof(u32), &tp->sacked_out);
    bpf_probe_read_kernel(&event->lost_out, sizeof(u32), &tp->lost_out);
    bpf_probe_read_kernel(&event->retrans_out, sizeof(u32), &tp->retrans_out);
    bpf_probe_read_kernel(&event->rtt_us, sizeof(u32), &tp->srtt_us);
    bpf_probe_read_kernel(&event->mss_cache, sizeof(u32), &tp->mss_cache);
}

// Helper to extract CUBIC state
static inline void get_cubic_state(struct sock *sk, struct cubic_event *event) {
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct bictcp *ca = (struct bictcp *)icsk->icsk_ca_priv;
    
    if (ca) {
        bpf_probe_read_kernel(&event->cnt, sizeof(u32), &ca->cnt);
        bpf_probe_read_kernel(&event->last_max_cwnd, sizeof(u32), &ca->last_max_cwnd);
        bpf_probe_read_kernel(&event->last_cwnd, sizeof(u32), &ca->last_cwnd);
        bpf_probe_read_kernel(&event->last_time, sizeof(u32), &ca->last_time);
        bpf_probe_read_kernel(&event->bic_origin_point, sizeof(u32), &ca->bic_origin_point);
        bpf_probe_read_kernel(&event->bic_K, sizeof(u32), &ca->bic_K);
        bpf_probe_read_kernel(&event->delay_min, sizeof(u32), &ca->delay_min);
        bpf_probe_read_kernel(&event->epoch_start, sizeof(u32), &ca->epoch_start);
        bpf_probe_read_kernel(&event->ack_cnt, sizeof(u32), &ca->ack_cnt);
        bpf_probe_read_kernel(&event->tcp_cwnd, sizeof(u32), &ca->tcp_cwnd);
        bpf_probe_read_kernel(&event->found, sizeof(u8), &ca->found);
        bpf_probe_read_kernel(&event->curr_rtt, sizeof(u32), &ca->curr_rtt);
    }
}

// Trace cubictcp_cong_avoid
int trace_cong_avoid(struct pt_regs *ctx, struct sock *sk, u32 ack, u32 acked) {
    struct cubic_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.event_type = EVENT_CONG_AVOID;
    event.acked = acked;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    get_conn_info(sk, &event);
    get_tcp_state(sk, &event);
    get_cubic_state(sk, &event);
    
    // Update histograms
    cwnd_hist.increment(bpf_log2l(event.cwnd));
    cnt_hist.increment(bpf_log2l(event.cnt));
    if (acked > 0) {
        acked_hist.increment(bpf_log2l(acked));
    }
    
    // Update counter
    u32 idx = EVENT_CONG_AVOID;
    u64 *counter = event_counts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        event_counts.update(&idx, &val);
    }
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace cubictcp_init
int trace_init(struct pt_regs *ctx, struct sock *sk) {
    struct cubic_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.event_type = EVENT_INIT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    get_conn_info(sk, &event);
    get_tcp_state(sk, &event);
    get_cubic_state(sk, &event);
    
    // Update counter
    u32 idx = EVENT_INIT;
    u64 *counter = event_counts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        event_counts.update(&idx, &val);
    }
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace cubictcp_recalc_ssthresh (loss detection)
int trace_recalc_ssthresh(struct pt_regs *ctx, struct sock *sk) {
    struct cubic_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.event_type = EVENT_SSTHRESH;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    get_conn_info(sk, &event);
    get_tcp_state(sk, &event);
    get_cubic_state(sk, &event);
    
    // Update counter
    u32 idx = EVENT_SSTHRESH;
    u64 *counter = event_counts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        event_counts.update(&idx, &val);
    }
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace cubictcp_state
int trace_state(struct pt_regs *ctx, struct sock *sk, u8 new_state) {
    struct cubic_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.event_type = EVENT_STATE_CHANGE;
    event.new_state = new_state;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    get_conn_info(sk, &event);
    get_tcp_state(sk, &event);
    get_cubic_state(sk, &event);
    
    // Update counter
    u32 idx = EVENT_STATE_CHANGE;
    u64 *counter = event_counts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        event_counts.update(&idx, &val);
    }
    
    cubic_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace cubictcp_cwnd_event
int trace_cwnd_event(struct pt_regs *ctx, struct sock *sk, int event) {
    struct cubic_event ev = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = pid_tgid;
    ev.tgid = pid_tgid >> 32;
    ev.event_type = EVENT_CWND_EVENT;
    
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    get_conn_info(sk, &ev);
    get_tcp_state(sk, &ev);
    get_cubic_state(sk, &ev);
    
    // Update counter
    u32 idx = EVENT_CWND_EVENT;
    u64 *counter = event_counts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        event_counts.update(&idx, &val);
    }
    
    cubic_events.perf_submit(ctx, &ev, sizeof(ev));
    
    return 0;
}

// Trace cubictcp_acked
int trace_acked(struct pt_regs *ctx, struct sock *sk, struct ack_sample *sample) {
    if (!sample) return 0;
    
    struct cubic_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.event_type = EVENT_ACKED;
    
    // Get RTT sample
    s32 rtt_us;
    bpf_probe_read_kernel(&rtt_us, sizeof(s32), &sample->rtt_us);
    if (rtt_us > 0) {
        event.rtt_sample = (u32)rtt_us;
        rtt_hist.increment(bpf_log2l(rtt_us));
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    get_conn_info(sk, &event);
    get_tcp_state(sk, &event);
    get_cubic_state(sk, &event);
    
    // Update counter
    u32 idx = EVENT_ACKED;
    u64 *counter = event_counts.lookup(&idx);
    if (counter) {
        (*counter)++;
    } else {
        u64 val = 1;
        event_counts.update(&idx, &val);
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
        ("new_state", ct.c_ubyte),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("cwnd", ct.c_uint),
        ("ssthresh", ct.c_uint),
        ("packets_out", ct.c_uint),
        ("sacked_out", ct.c_uint),
        ("lost_out", ct.c_uint),
        ("retrans_out", ct.c_uint),
        ("rtt_us", ct.c_uint),
        ("mss_cache", ct.c_uint),
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
        ("found", ct.c_ubyte),
        ("curr_rtt", ct.c_uint),
        ("acked", ct.c_uint),
        ("rtt_sample", ct.c_uint),
        ("comm", ct.c_char * 16),
    ]

class CubicComprehensiveTracer:
    def __init__(self, verbose=False, interval=None):
        self.verbose = verbose
        self.interval = interval
        self.start_time = time.time()
        self.event_counts = defaultdict(int)
        self.connections = {}
        self.last_print_time = time.time()
        
        # Event type names
        self.event_names = {
            1: "CONG_AVOID",
            2: "INIT",
            3: "SSTHRESH",
            4: "STATE_CHANGE",
            5: "CWND_EVENT",
            6: "ACKED"
        }
        
        
    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(CubicEvent)).contents
        
        self.event_counts[event.event_type] += 1
        
        # Track per-connection statistics
        conn_key = (event.saddr, event.sport, event.daddr, event.dport)
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                'events': defaultdict(int),
                'first_seen': event.ts_ns,
                'last_seen': event.ts_ns,
                'max_cwnd': 0,
                'min_rtt': float('inf'),
                'loss_count': 0,
                'slow_start_exits': 0,
                'last_cwnd': 0,
                'last_ssthresh': 0
            }
        
        conn = self.connections[conn_key]
        conn['events'][event.event_type] += 1
        conn['last_seen'] = event.ts_ns
        conn['max_cwnd'] = max(conn['max_cwnd'], event.cwnd)
        
        # Detect slow start exit
        if event.cwnd >= event.ssthresh and conn['last_cwnd'] < conn['last_ssthresh']:
            conn['slow_start_exits'] += 1
        
        conn['last_cwnd'] = event.cwnd
        conn['last_ssthresh'] = event.ssthresh
        
        # Track RTT
        if event.rtt_sample > 0:
            conn['min_rtt'] = min(conn['min_rtt'], event.rtt_sample)
        
        # Count losses
        if event.event_type == 3:  # SSTHRESH
            conn['loss_count'] += 1
        
        if self.verbose:
            self.print_event(event)
        
        # Periodic summary
        if self.interval and time.time() - self.last_print_time >= self.interval:
            self.print_interval_summary()
            self.last_print_time = time.time()
    
    def print_event(self, event):
        event_name = self.event_names.get(event.event_type, f"UNKNOWN({event.event_type})")
        
        # Format addresses
        saddr = socket.inet_ntoa(event.saddr.to_bytes(4, 'little'))
        daddr = socket.inet_ntoa(event.daddr.to_bytes(4, 'little'))
        sport = socket.ntohs(event.sport)
        dport = socket.ntohs(event.dport)
        
        # Format output based on event type
        if event.event_type == 1:  # CONG_AVOID
            in_ss = "SS" if event.cwnd < event.ssthresh else "CA"
            print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                  f"{event_name:12s} "
                  f"[{event.comm.decode('utf-8', 'replace'):12s}] "
                  f"cwnd={event.cwnd:<5} ss={event.ssthresh:<5} "
                  f"cnt={event.cnt:<4} K={event.bic_K:<6} "
                  f"acked={event.acked:<3} {in_ss} "
                  f"{saddr}:{sport} -> {daddr}:{dport}")
                  
        elif event.event_type == 3:  # SSTHRESH (loss)
            print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                  f"{event_name:12s} "
                  f"[{event.comm.decode('utf-8', 'replace'):12s}] "
                  f"LOSS! cwnd={event.cwnd}->{event.ssthresh} "
                  f"last_max={event.last_max_cwnd} "
                  f"{saddr}:{sport} -> {daddr}:{dport}")
                  
        elif event.event_type == 4:  # STATE_CHANGE
            print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                  f"{event_name:12s} "
                  f"[{event.comm.decode('utf-8', 'replace'):12s}] "
                  f"cwnd={event.cwnd} "
                  f"{saddr}:{sport} -> {daddr}:{dport}")
                  
        elif event.event_type == 6:  # ACKED
            if event.rtt_sample > 0:
                print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                      f"{event_name:12s} "
                      f"[{event.comm.decode('utf-8', 'replace'):12s}] "
                      f"RTT={event.rtt_sample}us delay_min={event.delay_min}us "
                      f"found={event.found} "
                      f"{saddr}:{sport} -> {daddr}:{dport}")
        
        else:
            print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
                  f"{event_name:12s} "
                  f"[{event.comm.decode('utf-8', 'replace'):12s}] "
                  f"cwnd={event.cwnd} cnt={event.cnt} "
                  f"{saddr}:{sport} -> {daddr}:{dport}")
    
    def print_interval_summary(self):
        print("\n=== Interval Summary ===")
        print(f"Event counts in last {self.interval}s:")
        for event_type, count in sorted(self.event_counts.items()):
            event_name = self.event_names.get(event_type, f"UNKNOWN({event_type})")
            print(f"  {event_name:15s}: {count:6d}")
        print()
    
    def print_summary(self):
        print("\n" + "=" * 80)
        print("=== TCP CUBIC Comprehensive Summary ===")
        print("=" * 80)
        print(f"Total runtime: {time.time() - self.start_time:.2f} seconds\n")
        
        # Event counts
        print("Event counts:")
        total_events = sum(self.event_counts.values())
        for event_type in sorted(self.event_names.keys()):
            count = self.event_counts.get(event_type, 0)
            event_name = self.event_names[event_type]
            pct = (count / total_events * 100) if total_events > 0 else 0
            print(f"  {event_name:15s}: {count:8d} ({pct:5.1f}%)")
        print(f"  {'TOTAL':15s}: {total_events:8d}")
        
        # BPF counter verification
        print("\nBPF event counters:")
        for i in range(1, 7):
            idx = ct.c_int(i)
            val = self.b["event_counts"][idx].value if idx in self.b["event_counts"] else 0
            event_name = self.event_names.get(i, f"UNKNOWN({i})")
            print(f"  {event_name:15s}: {val:8d}")
        
        # Connection analysis
        if self.connections:
            print(f"\nConnection Analysis ({len(self.connections)} connections):")
            
            # Sort by total events
            sorted_conns = sorted(self.connections.items(),
                                key=lambda x: sum(x[1]['events'].values()),
                                reverse=True)
            
            for i, (conn_key, stats) in enumerate(sorted_conns[:5]):
                saddr, sport, daddr, dport = conn_key
                saddr_str = socket.inet_ntoa(saddr.to_bytes(4, 'little'))
                daddr_str = socket.inet_ntoa(daddr.to_bytes(4, 'little'))
                sport_h = socket.ntohs(sport)
                dport_h = socket.ntohs(dport)
                
                duration = (stats['last_seen'] - stats['first_seen']) / 1e9
                total_events = sum(stats['events'].values())
                
                print(f"\n  Connection #{i+1}: {saddr_str}:{sport_h} -> {daddr_str}:{dport_h}")
                print(f"    Duration: {duration:.1f}s, Total events: {total_events}")
                print(f"    Max cwnd: {stats['max_cwnd']}, Min RTT: {stats['min_rtt']/1000:.1f}ms")
                print(f"    Loss events: {stats['loss_count']}, Slow start exits: {stats['slow_start_exits']}")
                print(f"    Event breakdown:", end="")
                for event_type, count in sorted(stats['events'].items()):
                    event_name = self.event_names.get(event_type, f"UNK({event_type})")
                    print(f" {event_name}={count}", end="")
                print()
        
        # Histograms
        print("\nCongestion window distribution (log2):")
        self.b["cwnd_hist"].print_log2_hist("cwnd")
        
        print("\nCNT value distribution (log2):")
        self.b["cnt_hist"].print_log2_hist("cnt")
        
        print("\nRTT distribution (log2 microseconds):")
        self.b["rtt_hist"].print_log2_hist("rtt_us")
        
        print("\nACKed packets distribution (log2):")
        self.b["acked_hist"].print_log2_hist("acked")
    
    def run(self):
        # Compile BPF program
        self.b = BPF(text=bpf_text)
        
        # Attach to all CUBIC functions
        probes = [
            ("cubictcp_cong_avoid", "trace_cong_avoid"),
            ("cubictcp_init", "trace_init"),
            ("cubictcp_recalc_ssthresh", "trace_recalc_ssthresh"),
            ("cubictcp_state", "trace_state"),
            ("cubictcp_cwnd_event", "trace_cwnd_event"),
            ("cubictcp_acked", "trace_acked"),
        ]
        
        attached = []
        for func, probe in probes:
            try:
                self.b.attach_kprobe(event=func, fn_name=probe)
                attached.append(func)
                print(f"✓ Attached to {func}")
            except Exception as e:
                print(f"✗ Could not attach to {func}: {e}")
        
        if not attached:
            print("\nError: Could not attach to any CUBIC functions!")
            return
        
        print(f"\nSuccessfully attached to {len(attached)} CUBIC functions")
        print("Tracking TCP CUBIC comprehensively... Press Ctrl-C to stop")
        print("-" * 80)
        
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
    import os
    
    parser = argparse.ArgumentParser(
        description='Comprehensive TCP CUBIC tracer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic tracking with summary
  sudo ./cubic_comprehensive_tracer.py
  
  # Verbose output (print each event)
  sudo ./cubic_comprehensive_tracer.py -v
  
  # Periodic summaries every 10 seconds
  sudo ./cubic_comprehensive_tracer.py -i 10
  
  # Verbose with periodic summaries
  sudo ./cubic_comprehensive_tracer.py -v -i 5
        """)
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Print detailed output for each event')
    parser.add_argument('-i', '--interval', type=int, metavar='SEC',
                       help='Print summary every N seconds')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)
    
    tracer = CubicComprehensiveTracer(verbose=args.verbose, interval=args.interval)
    tracer.run()

if __name__ == "__main__":
    main()