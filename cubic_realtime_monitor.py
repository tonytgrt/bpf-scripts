#!/usr/bin/env python3
"""
cubic_realtime_monitor.py - Real-time monitoring of TCP CUBIC metrics
Provides a dashboard-like view of CUBIC congestion control behavior
"""

from bcc import BPF
import ctypes as ct
import time
import sys
import os
import argparse
from datetime import datetime
import socket
import curses
from collections import defaultdict, deque

# BPF program for real-time monitoring
bpf_text = """
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

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

struct monitor_event {
    u64 ts_ns;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    
    // Key metrics
    u32 cwnd;
    u32 ssthresh;
    u32 cnt;
    u32 bic_K;
    u32 tcp_cwnd;
    u32 rtt_us;
    u32 min_rtt_us;
    u32 delay_min;
    u32 last_max_cwnd;
    
    // States
    u8 in_slow_start;
    u8 is_tcp_friendly;
    u8 found;  // HyStart
    
    // Counters
    u32 acked;
    u32 packets_out;
    u32 retrans_out;
    u32 sacked_out;
};

BPF_PERF_OUTPUT(monitor_events);
BPF_ARRAY(global_stats, u64, 10);

// Update global statistics
static inline void update_stats(u32 idx) {
    u64 *val = global_stats.lookup(&idx);
    if (val) {
        (*val)++;
    } else {
        u64 one = 1;
        global_stats.update(&idx, &one);
    }
}

int monitor_cubic(struct pt_regs *ctx, struct sock *sk, u32 ack, u32 acked) {
    struct monitor_event event = {};
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct bictcp *ca = (struct bictcp *)icsk->icsk_ca_priv;
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    if (!ca) return 0;
    
    // Basic info
    event.ts_ns = bpf_ktime_get_ns();
    event.acked = acked;
    
    // Connection info
    bpf_probe_read_kernel(&event.saddr, sizeof(u32), &inet->inet_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(u32), &inet->inet_daddr);
    bpf_probe_read_kernel(&event.sport, sizeof(u16), &inet->inet_sport);
    bpf_probe_read_kernel(&event.dport, sizeof(u16), &inet->inet_dport);
    
    // TCP metrics
    bpf_probe_read_kernel(&event.cwnd, sizeof(u32), &tp->snd_cwnd);
    bpf_probe_read_kernel(&event.ssthresh, sizeof(u32), &tp->snd_ssthresh);
    bpf_probe_read_kernel(&event.rtt_us, sizeof(u32), &tp->srtt_us);
    bpf_probe_read_kernel(&event.min_rtt_us, sizeof(u32), &tp->rtt_min);
    bpf_probe_read_kernel(&event.packets_out, sizeof(u32), &tp->packets_out);
    bpf_probe_read_kernel(&event.retrans_out, sizeof(u32), &tp->retrans_out);
    bpf_probe_read_kernel(&event.sacked_out, sizeof(u32), &tp->sacked_out);
    
    // CUBIC metrics
    bpf_probe_read_kernel(&event.cnt, sizeof(u32), &ca->cnt);
    bpf_probe_read_kernel(&event.bic_K, sizeof(u32), &ca->bic_K);
    bpf_probe_read_kernel(&event.tcp_cwnd, sizeof(u32), &ca->tcp_cwnd);
    bpf_probe_read_kernel(&event.delay_min, sizeof(u32), &ca->delay_min);
    bpf_probe_read_kernel(&event.last_max_cwnd, sizeof(u32), &ca->last_max_cwnd);
    bpf_probe_read_kernel(&event.found, sizeof(u8), &ca->found);
    
    // Determine states
    event.in_slow_start = (event.cwnd < event.ssthresh) ? 1 : 0;
    event.is_tcp_friendly = (event.tcp_cwnd > event.cwnd) ? 1 : 0;
    
    // Update global stats
    update_stats(0);  // Total events
    if (event.in_slow_start) update_stats(1);  // Slow start
    if (event.is_tcp_friendly) update_stats(2);  // TCP friendly
    if (event.found) update_stats(3);  // HyStart triggered
    
    monitor_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

int monitor_loss(struct pt_regs *ctx, struct sock *sk) {
    update_stats(4);  // Loss events
    return 0;
}
"""

class MonitorEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("cwnd", ct.c_uint),
        ("ssthresh", ct.c_uint),
        ("cnt", ct.c_uint),
        ("bic_K", ct.c_uint),
        ("tcp_cwnd", ct.c_uint),
        ("rtt_us", ct.c_uint),
        ("min_rtt_us", ct.c_uint),
        ("delay_min", ct.c_uint),
        ("last_max_cwnd", ct.c_uint),
        ("in_slow_start", ct.c_ubyte),
        ("is_tcp_friendly", ct.c_ubyte),
        ("found", ct.c_ubyte),
        ("acked", ct.c_uint),
        ("packets_out", ct.c_uint),
        ("retrans_out", ct.c_uint),
        ("sacked_out", ct.c_uint),
    ]

class CubicRealtimeMonitor:
    def __init__(self, interval=1, top_n=10):
        self.interval = interval
        self.top_n = top_n
        self.start_time = time.time()
        self.last_update = time.time()
        
        # Connection tracking
        self.connections = defaultdict(lambda: {
            'last_update': 0,
            'cwnd': 0,
            'rtt': 0,
            'cnt': 0,
            'state': '',
            'mode': '',
            'events': 0,
            'acked': 0,
            'retrans': 0,
            'cwnd_history': deque(maxlen=50),
            'rtt_history': deque(maxlen=50),
        })
        
        # Global metrics
        self.global_stats = {
            'total_events': 0,
            'slow_start': 0,
            'tcp_friendly': 0,
            'hystart': 0,
            'losses': 0,
        }
        
    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(MonitorEvent)).contents
        
        # Update global stats
        self.global_stats['total_events'] += 1
        
        # Connection key
        conn_key = (event.saddr, event.daddr, event.sport, event.dport)
        conn = self.connections[conn_key]
        
        # Update connection data
        conn['last_update'] = time.time()
        conn['cwnd'] = event.cwnd
        conn['rtt'] = event.rtt_us / 1000  # Convert to ms
        conn['cnt'] = event.cnt
        conn['events'] += 1
        conn['acked'] += event.acked
        conn['retrans'] = event.retrans_out
        
        # State
        conn['state'] = 'SS' if event.in_slow_start else 'CA'
        conn['mode'] = 'TCP' if event.is_tcp_friendly else 'CUBIC'
        
        # History
        conn['cwnd_history'].append(event.cwnd)
        conn['rtt_history'].append(conn['rtt'])
    
    def display_dashboard(self, stdscr):
        """Display real-time dashboard using curses"""
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(1)    # Non-blocking input
        
        while True:
            # Clear screen
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Header
            runtime = time.time() - self.start_time
            header = f"TCP CUBIC Real-time Monitor | Runtime: {runtime:.1f}s | Press 'q' to quit"
            stdscr.addstr(0, 0, header, curses.A_BOLD)
            stdscr.addstr(1, 0, "=" * min(width-1, 80))
            
            # Global statistics
            row = 3
            stdscr.addstr(row, 0, "Global Statistics:", curses.A_BOLD)
            row += 1
            
            # Get BPF stats
            global_stats = self.b.get_table("global_stats")
            total = global_stats[0].value if 0 in global_stats else 0
            slow_start = global_stats[1].value if 1 in global_stats else 0
            tcp_friendly = global_stats[2].value if 2 in global_stats else 0
            hystart = global_stats[3].value if 3 in global_stats else 0
            losses = global_stats[4].value if 4 in global_stats else 0
            
            if total > 0:
                ss_pct = slow_start / total * 100
                tcp_pct = tcp_friendly / total * 100
                
                stdscr.addstr(row, 2, f"Total Events: {total:,}")
                row += 1
                stdscr.addstr(row, 2, f"Slow Start:   {slow_start:,} ({ss_pct:.1f}%)")
                row += 1
                stdscr.addstr(row, 2, f"TCP Friendly: {tcp_friendly:,} ({tcp_pct:.1f}%)")
                row += 1
                stdscr.addstr(row, 2, f"HyStart:      {hystart:,}")
                row += 1
                stdscr.addstr(row, 2, f"Loss Events:  {losses:,}")
                row += 1
            
            # Active connections
            row += 2
            stdscr.addstr(row, 0, "Active Connections:", curses.A_BOLD)
            row += 1
            
            # Header for connections table
            header_fmt = "{:20s} {:>8s} {:>8s} {:>6s} {:>8s} {:>6s} {:>6s} {:>8s}"
            stdscr.addstr(row, 2, header_fmt.format(
                "Connection", "CWND", "RTT(ms)", "CNT", "State", "Mode", "Acked", "Retrans"
            ))
            row += 1
            stdscr.addstr(row, 2, "-" * min(width-4, 78))
            row += 1
            
            # Sort connections by activity
            active_conns = sorted(self.connections.items(),
                                key=lambda x: x[1]['events'],
                                reverse=True)[:self.top_n]
            
            for conn_key, conn_data in active_conns:
                if row >= height - 2:
                    break
                
                # Check if connection is still active (updated in last 5 seconds)
                if time.time() - conn_data['last_update'] > 5:
                    continue
                
                saddr, daddr, sport, dport = conn_key
                saddr_str = socket.inet_ntoa(saddr.to_bytes(4, 'little'))
                daddr_str = socket.inet_ntoa(daddr.to_bytes(4, 'little'))
                sport_h = socket.ntohs(sport)
                dport_h = socket.ntohs(dport)
                
                conn_str = f"{saddr_str}:{sport_h}"[:20]
                
                # Calculate sparkline for cwnd
                if conn_data['cwnd_history']:
                    spark = self.create_sparkline(list(conn_data['cwnd_history']))
                else:
                    spark = ""
                
                line = "{:20s} {:>8d} {:>8.1f} {:>6d} {:>8s} {:>6s} {:>6d} {:>8d}".format(
                    conn_str,
                    conn_data['cwnd'],
                    conn_data['rtt'],
                    conn_data['cnt'],
                    conn_data['state'],
                    conn_data['mode'],
                    conn_data['acked'],
                    conn_data['retrans']
                )
                
                stdscr.addstr(row, 2, line)
                
                # Add sparkline on the same row if space permits
                if width > 90 and spark:
                    stdscr.addstr(row, 82, spark)
                
                row += 1
            
            # Refresh display
            stdscr.refresh()
            
            # Check for quit command
            key = stdscr.getch()
            if key == ord('q'):
                break
            
            # Poll for new events
            self.b.perf_buffer_poll(timeout=self.interval * 1000)
    
    def create_sparkline(self, data, width=8):
        """Create a simple ASCII sparkline"""
        if not data:
            return ""
        
        chars = "▁▂▃▄▅▆▇█"
        min_val = min(data)
        max_val = max(data)
        
        if max_val == min_val:
            return chars[0] * width
        
        # Sample data if too long
        if len(data) > width:
            step = len(data) // width
            data = data[::step][:width]
        
        sparkline = ""
        for val in data:
            idx = int((val - min_val) / (max_val - min_val) * (len(chars) - 1))
            sparkline += chars[idx]
        
        return sparkline
    
    def run_simple(self):
        """Simple text output without curses"""
        print("TCP CUBIC Real-time Monitor (Simple Mode)")
        print("Press Ctrl-C to stop")
        print("-" * 80)
        
        while True:
            # Poll for events
            self.b.perf_buffer_poll(timeout=self.interval * 1000)
            
            # Print summary every interval
            if time.time() - self.last_update >= self.interval:
                self.print_summary()
                self.last_update = time.time()
    
    def print_summary(self):
        """Print simple text summary"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        runtime = time.time() - self.start_time
        print(f"TCP CUBIC Monitor | Runtime: {runtime:.1f}s")
        print("=" * 80)
        
        # Global stats
        global_stats = self.b.get_table("global_stats")
        total = global_stats[0].value if 0 in global_stats else 0
        
        if total > 0:
            print(f"Total Events: {total:,}")
            print()
        
        # Active connections
        print("Active Connections:")
        print("-" * 80)
        print(f"{'Connection':<30} {'CWND':>8} {'RTT(ms)':>8} {'CNT':>6} {'State':>8} {'Mode':>6}")
        print("-" * 80)
        
        active_conns = sorted(self.connections.items(),
                            key=lambda x: x[1]['events'],
                            reverse=True)[:self.top_n]
        
        for conn_key, conn_data in active_conns:
            if time.time() - conn_data['last_update'] > 5:
                continue
            
            saddr, daddr, sport, dport = conn_key
            saddr_str = socket.inet_ntoa(saddr.to_bytes(4, 'little'))
            sport_h = socket.ntohs(sport)
            dport_h = socket.ntohs(dport)
            
            conn_str = f"{saddr_str}:{sport_h}"
            
            print(f"{conn_str:<30} {conn_data['cwnd']:>8} "
                  f"{conn_data['rtt']:>8.1f} {conn_data['cnt']:>6} "
                  f"{conn_data['state']:>8} {conn_data['mode']:>6}")
    
    def run(self, use_curses=True):
        # Compile BPF program
        self.b = BPF(text=bpf_text)
        
        # Attach probes
        try:
            self.b.attach_kprobe(event="cubictcp_cong_avoid", fn_name="monitor_cubic")
            print("✓ Attached to cubictcp_cong_avoid")
        except Exception as e:
            print(f"✗ Could not attach to cubictcp_cong_avoid: {e}")
            return
        
        try:
            self.b.attach_kprobe(event="cubictcp_recalc_ssthresh", fn_name="monitor_loss")
            print("✓ Attached to cubictcp_recalc_ssthresh")
        except:
            pass
        
        # Open perf buffer
        self.b["monitor_events"].open_perf_buffer(self.handle_event)
        
        # Start monitoring
        if use_curses:
            try:
                curses.wrapper(self.display_dashboard)
            except KeyboardInterrupt:
                pass
        else:
            try:
                self.run_simple()
            except KeyboardInterrupt:
                print("\nStopping monitor...")

def main():
    parser = argparse.ArgumentParser(
        description='Real-time TCP CUBIC monitoring dashboard'
    )
    
    parser.add_argument('-i', '--interval', type=int, default=1,
                       help='Update interval in seconds (default: 1)')
    parser.add_argument('-n', '--top', type=int, default=10,
                       help='Number of top connections to show (default: 10)')
    parser.add_argument('-s', '--simple', action='store_true',
                       help='Use simple text output instead of curses dashboard')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)
    
    monitor = CubicRealtimeMonitor(interval=args.interval, top_n=args.top)
    monitor.run(use_curses=not args.simple)

if __name__ == "__main__":
    main()