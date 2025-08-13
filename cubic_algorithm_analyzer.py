#!/usr/bin/env python3
"""
cubic_algorithm_analyzer.py - Analyze CUBIC algorithm behavior and decisions
Focuses on understanding CUBIC phases, TCP friendliness, and performance
"""

from bcc import BPF
import ctypes as ct
import signal
import sys
import time
import argparse
from datetime import datetime
import socket
import struct
import matplotlib.pyplot as plt
from collections import defaultdict

# BPF program focused on algorithm analysis
bpf_text = """
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/ptrace.h>

// CUBIC state structure
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

// Analysis event
struct cubic_analysis {
    u64 ts_ns;
    u32 pid;
    
    // Connection identifier
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    
    // TCP state
    u32 cwnd;
    u32 ssthresh;
    u32 rtt_us;
    u32 min_rtt_us;
    u32 packets_in_flight;
    
    // CUBIC state
    u32 cnt;
    u32 last_max_cwnd;
    u32 bic_K;
    u32 bic_origin_point;
    u32 epoch_start;
    u32 tcp_cwnd;
    u32 delay_min;
    u8 found;  // HyStart found
    
    // Computed values for analysis
    u32 time_since_epoch;
    u32 time_to_origin;  // K - t or t - K
    u8 is_below_origin;  // 1 if below K, 0 if above
    u8 is_tcp_friendly;  // 1 if tcp_cwnd > cwnd
    u8 in_slow_start;
    u8 is_epoch_start;
    
    // Performance metrics
    u32 acked;
    u32 lost;
    u32 retrans;
};

BPF_PERF_OUTPUT(analysis_events);
BPF_HASH(prev_state, struct sock*, struct bictcp);

// Per-connection analysis state
struct conn_analysis {
    u64 bytes_acked;
    u64 loss_events;
    u64 slow_start_exits;
    u64 epoch_starts;
    u64 tcp_friendly_periods;
    u32 max_cwnd;
    u32 min_rtt;
};
BPF_HASH(conn_stats, u64, struct conn_analysis);  // key is (saddr << 32 | daddr)

// Get connection key
static inline u64 get_conn_key(u32 saddr, u32 daddr) {
    return ((u64)saddr << 32) | daddr;
}

// Analyze CUBIC state in cong_avoid
int analyze_cong_avoid(struct pt_regs *ctx, struct sock *sk, u32 ack, u32 acked) {
    struct cubic_analysis event = {};
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct bictcp *ca = (struct bictcp *)icsk->icsk_ca_priv;
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    if (!ca) return 0;
    
    // Basic info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    event.acked = acked;
    
    // Connection info
    bpf_probe_read_kernel(&event.saddr, sizeof(u32), &inet->inet_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(u32), &inet->inet_daddr);
    bpf_probe_read_kernel(&event.sport, sizeof(u16), &inet->inet_sport);
    bpf_probe_read_kernel(&event.dport, sizeof(u16), &inet->inet_dport);
    
    // TCP state
    bpf_probe_read_kernel(&event.cwnd, sizeof(u32), &tp->snd_cwnd);
    bpf_probe_read_kernel(&event.ssthresh, sizeof(u32), &tp->snd_ssthresh);
    bpf_probe_read_kernel(&event.rtt_us, sizeof(u32), &tp->srtt_us);
    bpf_probe_read_kernel(&event.min_rtt_us, sizeof(u32), &tp->rtt_min);
    bpf_probe_read_kernel(&event.packets_in_flight, sizeof(u32), &tp->packets_out);
    bpf_probe_read_kernel(&event.lost, sizeof(u32), &tp->lost_out);
    bpf_probe_read_kernel(&event.retrans, sizeof(u32), &tp->retrans_out);
    
    // CUBIC state
    bpf_probe_read_kernel(&event.cnt, sizeof(u32), &ca->cnt);
    bpf_probe_read_kernel(&event.last_max_cwnd, sizeof(u32), &ca->last_max_cwnd);
    bpf_probe_read_kernel(&event.bic_K, sizeof(u32), &ca->bic_K);
    bpf_probe_read_kernel(&event.bic_origin_point, sizeof(u32), &ca->bic_origin_point);
    bpf_probe_read_kernel(&event.epoch_start, sizeof(u32), &ca->epoch_start);
    bpf_probe_read_kernel(&event.tcp_cwnd, sizeof(u32), &ca->tcp_cwnd);
    bpf_probe_read_kernel(&event.delay_min, sizeof(u32), &ca->delay_min);
    bpf_probe_read_kernel(&event.found, sizeof(u8), &ca->found);
    
    // Analysis computations
    event.in_slow_start = (event.cwnd < event.ssthresh) ? 1 : 0;
    event.is_tcp_friendly = (event.tcp_cwnd > event.cwnd) ? 1 : 0;
    
    // Check if epoch just started
    struct bictcp *prev = prev_state.lookup(&sk);
    if (prev) {
        event.is_epoch_start = (prev->epoch_start != event.epoch_start) ? 1 : 0;
    }
    
    // Time calculations (simplified - would need jiffies access for accuracy)
    if (event.epoch_start > 0) {
        // This is approximate - real calculation needs jiffies
        event.time_since_epoch = event.ts_ns / 1000000 - event.epoch_start;
        
        // Determine if below or above origin
        if (event.time_since_epoch < event.bic_K) {
            event.is_below_origin = 1;
            event.time_to_origin = event.bic_K - event.time_since_epoch;
        } else {
            event.is_below_origin = 0;
            event.time_to_origin = event.time_since_epoch - event.bic_K;
        }
    }
    
    // Update connection statistics
    u64 conn_key = get_conn_key(event.saddr, event.daddr);
    struct conn_analysis *stats = conn_stats.lookup(&conn_key);
    if (stats) {
        stats->bytes_acked += acked * 1448;  // Approximate with typical MSS
        if (event.is_epoch_start) stats->epoch_starts++;
        if (event.is_tcp_friendly) stats->tcp_friendly_periods++;
        if (event.cwnd > stats->max_cwnd) stats->max_cwnd = event.cwnd;
        if (event.min_rtt_us > 0 && event.min_rtt_us < stats->min_rtt) {
            stats->min_rtt = event.min_rtt_us;
        }
        
        // Detect slow start exit
        if (prev && prev->epoch_start == event.epoch_start) {
            if (event.cwnd >= event.ssthresh && prev->last_cwnd < prev->last_max_cwnd) {
                stats->slow_start_exits++;
            }
        }
    } else {
        struct conn_analysis new_stats = {
            .bytes_acked = acked * 1448,
            .max_cwnd = event.cwnd,
            .min_rtt = event.min_rtt_us,
        };
        conn_stats.update(&conn_key, &new_stats);
    }
    
    // Save current state for next comparison
    prev_state.update(&sk, ca);
    
    analysis_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Analyze loss events
int analyze_ssthresh(struct pt_regs *ctx, struct sock *sk) {
    struct cubic_analysis event = {};
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    struct bictcp *ca = (struct bictcp *)icsk->icsk_ca_priv;
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    if (!ca) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.ts_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid;
    
    // Mark this as a loss event
    event.lost = 1;
    
    // Get connection info
    bpf_probe_read_kernel(&event.saddr, sizeof(u32), &inet->inet_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(u32), &inet->inet_daddr);
    
    // Update loss statistics
    u64 conn_key = get_conn_key(event.saddr, event.daddr);
    struct conn_analysis *stats = conn_stats.lookup(&conn_key);
    if (stats) {
        stats->loss_events++;
    }
    
    // Get full state for analysis
    bpf_probe_read_kernel(&event.cwnd, sizeof(u32), &tp->snd_cwnd);
    bpf_probe_read_kernel(&event.ssthresh, sizeof(u32), &tp->snd_ssthresh);
    bpf_probe_read_kernel(&event.last_max_cwnd, sizeof(u32), &ca->last_max_cwnd);
    
    analysis_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

class CubicAnalysis(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("cwnd", ct.c_uint),
        ("ssthresh", ct.c_uint),
        ("rtt_us", ct.c_uint),
        ("min_rtt_us", ct.c_uint),
        ("packets_in_flight", ct.c_uint),
        ("cnt", ct.c_uint),
        ("last_max_cwnd", ct.c_uint),
        ("bic_K", ct.c_uint),
        ("bic_origin_point", ct.c_uint),
        ("epoch_start", ct.c_uint),
        ("tcp_cwnd", ct.c_uint),
        ("delay_min", ct.c_uint),
        ("found", ct.c_ubyte),
        ("time_since_epoch", ct.c_uint),
        ("time_to_origin", ct.c_uint),
        ("is_below_origin", ct.c_ubyte),
        ("is_tcp_friendly", ct.c_ubyte),
        ("in_slow_start", ct.c_ubyte),
        ("is_epoch_start", ct.c_ubyte),
        ("acked", ct.c_uint),
        ("lost", ct.c_uint),
        ("retrans", ct.c_uint),
    ]

class CubicAlgorithmAnalyzer:
    def __init__(self, verbose=False, plot=False):
        self.verbose = verbose
        self.plot = plot
        self.start_time = time.time()
        
        # Analysis data
        self.connections = defaultdict(lambda: {
            'cwnd_history': [],
            'rtt_history': [],
            'cnt_history': [],
            'tcp_cwnd_history': [],
            'timestamps': [],
            'phases': [],  # below/above origin
            'tcp_friendly_periods': 0,
            'slow_start_periods': 0,
            'epoch_starts': 0,
            'loss_events': 0,
            'total_acked': 0
        })
        
        # Global statistics
        self.phase_counts = {'below_origin': 0, 'above_origin': 0}
        self.tcp_friendly_count = 0
        self.slow_start_count = 0
        self.total_events = 0
        
    def handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(CubicAnalysis)).contents
        self.total_events += 1
        
        # Connection key
        conn_key = (event.saddr, event.daddr, event.sport, event.dport)
        conn = self.connections[conn_key]
        
        # Record time series data
        relative_time = (event.ts_ns - (self.start_time * 1e9)) / 1e9
        conn['timestamps'].append(relative_time)
        conn['cwnd_history'].append(event.cwnd)
        conn['rtt_history'].append(event.rtt_us / 1000)  # Convert to ms
        conn['cnt_history'].append(event.cnt)
        conn['tcp_cwnd_history'].append(event.tcp_cwnd)
        
        # Track phases
        if event.is_below_origin:
            conn['phases'].append('below')
            self.phase_counts['below_origin'] += 1
        else:
            conn['phases'].append('above')
            self.phase_counts['above_origin'] += 1
        
        # Track algorithm decisions
        if event.is_tcp_friendly:
            self.tcp_friendly_count += 1
            conn['tcp_friendly_periods'] += 1
        
        if event.in_slow_start:
            self.slow_start_count += 1
            conn['slow_start_periods'] += 1
        
        if event.is_epoch_start:
            conn['epoch_starts'] += 1
        
        if event.lost > 0:
            conn['loss_events'] += 1
        
        conn['total_acked'] += event.acked
        
        if self.verbose:
            self.print_event(event, relative_time)
    
    def print_event(self, event, relative_time):
        saddr = socket.inet_ntoa(event.saddr.to_bytes(4, 'little'))
        daddr = socket.inet_ntoa(event.daddr.to_bytes(4, 'little'))
        sport = socket.ntohs(event.sport)
        dport = socket.ntohs(event.dport)
        
        phase = "BELOW" if event.is_below_origin else "ABOVE"
        mode = "TCP" if event.is_tcp_friendly else "CUBIC"
        state = "SS" if event.in_slow_start else "CA"
        
        print(f"[{relative_time:8.3f}] {state} {phase:5s} {mode:5s} "
              f"cwnd={event.cwnd:<5} cnt={event.cnt:<4} K={event.bic_K:<6} "
              f"tcp_cwnd={event.tcp_cwnd:<5} "
              f"rtt={event.rtt_us/1000:.1f}ms "
              f"{saddr}:{sport}->{daddr}:{dport}")
        
        if event.is_epoch_start:
            print(f"            *** EPOCH START ***")
        
        if event.lost > 0:
            print(f"            *** LOSS EVENT *** cwnd={event.cwnd} -> ssthresh={event.ssthresh}")
    
    def analyze_cubic_behavior(self):
        print("\n" + "=" * 80)
        print("=== CUBIC Algorithm Behavior Analysis ===")
        print("=" * 80)
        
        runtime = time.time() - self.start_time
        print(f"\nRuntime: {runtime:.2f} seconds")
        print(f"Total events: {self.total_events}")
        print(f"Connections analyzed: {len(self.connections)}")
        
        # Phase analysis
        print("\n### CUBIC Phase Distribution ###")
        total_phase = sum(self.phase_counts.values())
        if total_phase > 0:
            below_pct = self.phase_counts['below_origin'] / total_phase * 100
            above_pct = self.phase_counts['above_origin'] / total_phase * 100
            print(f"  Below origin (concave): {self.phase_counts['below_origin']:8d} ({below_pct:5.1f}%)")
            print(f"  Above origin (convex):  {self.phase_counts['above_origin']:8d} ({above_pct:5.1f}%)")
        
        # Mode analysis
        print("\n### TCP Friendliness Analysis ###")
        if self.total_events > 0:
            tcp_pct = self.tcp_friendly_count / self.total_events * 100
            cubic_pct = 100 - tcp_pct
            print(f"  TCP-friendly mode:  {self.tcp_friendly_count:8d} ({tcp_pct:5.1f}%)")
            print(f"  CUBIC mode:         {self.total_events - self.tcp_friendly_count:8d} ({cubic_pct:5.1f}%)")
        
        # State analysis
        print("\n### Congestion Control State ###")
        if self.total_events > 0:
            ss_pct = self.slow_start_count / self.total_events * 100
            ca_pct = 100 - ss_pct
            print(f"  Slow start:         {self.slow_start_count:8d} ({ss_pct:5.1f}%)")
            print(f"  Congestion avoid:   {self.total_events - self.slow_start_count:8d} ({ca_pct:5.1f}%)")
        
        # Per-connection analysis
        print("\n### Per-Connection Analysis ###")
        for i, (conn_key, conn_data) in enumerate(list(self.connections.items())[:5]):
            saddr, daddr, sport, dport = conn_key
            saddr_str = socket.inet_ntoa(saddr.to_bytes(4, 'little'))
            daddr_str = socket.inet_ntoa(daddr.to_bytes(4, 'little'))
            sport_h = socket.ntohs(sport)
            dport_h = socket.ntohs(dport)
            
            print(f"\nConnection {i+1}: {saddr_str}:{sport_h} -> {daddr_str}:{dport_h}")
            
            if conn_data['cwnd_history']:
                max_cwnd = max(conn_data['cwnd_history'])
                avg_cwnd = sum(conn_data['cwnd_history']) / len(conn_data['cwnd_history'])
                min_rtt = min(conn_data['rtt_history']) if conn_data['rtt_history'] else 0
                
                print(f"  Samples: {len(conn_data['cwnd_history'])}")
                print(f"  Max cwnd: {max_cwnd}, Avg cwnd: {avg_cwnd:.1f}")
                print(f"  Min RTT: {min_rtt:.1f}ms")
                print(f"  Epoch starts: {conn_data['epoch_starts']}")
                print(f"  Loss events: {conn_data['loss_events']}")
                print(f"  TCP-friendly periods: {conn_data['tcp_friendly_periods']}")
                print(f"  Total acked: {conn_data['total_acked']} packets")
    
    def plot_analysis(self):
        if not self.plot or not self.connections:
            return
        
        print("\n### Generating plots ###")
        
        # Select top connections for plotting
        top_conns = sorted(self.connections.items(), 
                          key=lambda x: len(x[1]['cwnd_history']), 
                          reverse=True)[:3]
        
        if not top_conns:
            print("No data to plot")
            return
        
        fig, axes = plt.subplots(3, 1, figsize=(12, 10))
        
        for conn_key, conn_data in top_conns:
            if not conn_data['timestamps']:
                continue
            
            saddr, daddr, sport, dport = conn_key
            label = f"{socket.inet_ntoa(saddr.to_bytes(4, 'little'))}:{socket.ntohs(sport)}"
            
            # Plot cwnd evolution
            axes[0].plot(conn_data['timestamps'], conn_data['cwnd_history'], 
                        label=f"cwnd {label}", alpha=0.7)
            axes[0].plot(conn_data['timestamps'], conn_data['tcp_cwnd_history'],
                        label=f"tcp_cwnd {label}", alpha=0.7, linestyle='--')
            
            # Plot cnt evolution
            axes[1].plot(conn_data['timestamps'], conn_data['cnt_history'],
                        label=f"cnt {label}", alpha=0.7)
            
            # Plot RTT evolution
            axes[2].plot(conn_data['timestamps'], conn_data['rtt_history'],
                        label=f"RTT {label}", alpha=0.7)
        
        axes[0].set_ylabel('Congestion Window')
        axes[0].set_title('CUBIC vs TCP-friendly cwnd Evolution')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        axes[1].set_ylabel('CNT (increment counter)')
        axes[1].set_title('CUBIC CNT Evolution')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        axes[2].set_ylabel('RTT (ms)')
        axes[2].set_xlabel('Time (seconds)')
        axes[2].set_title('RTT Evolution')
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('cubic_analysis.png')
        print("Plots saved to cubic_analysis.png")
        plt.show()
    
    def print_summary_stats(self):
        # Get connection statistics from BPF
        conn_stats = self.b.get_table("conn_stats")
        
        print("\n### BPF Connection Statistics ###")
        for key, stats in conn_stats.items():
            saddr = (key.value >> 32) & 0xFFFFFFFF
            daddr = key.value & 0xFFFFFFFF
            
            saddr_str = socket.inet_ntoa(saddr.to_bytes(4, 'little'))
            daddr_str = socket.inet_ntoa(daddr.to_bytes(4, 'little'))
            
            print(f"\n{saddr_str} -> {daddr_str}:")
            print(f"  Bytes acked: {stats.bytes_acked:,}")
            print(f"  Loss events: {stats.loss_events}")
            print(f"  Slow start exits: {stats.slow_start_exits}")
            print(f"  Epoch starts: {stats.epoch_starts}")
            print(f"  TCP friendly periods: {stats.tcp_friendly_periods}")
            print(f"  Max cwnd: {stats.max_cwnd}")
            print(f"  Min RTT: {stats.min_rtt/1000:.1f}ms" if stats.min_rtt else "  Min RTT: N/A")
    
    def run(self):
        # Compile BPF program
        self.b = BPF(text=bpf_text)
        
        # Attach probes
        probes = [
            ("cubictcp_cong_avoid", "analyze_cong_avoid"),
            ("cubictcp_recalc_ssthresh", "analyze_ssthresh"),
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
        
        print(f"\nAnalyzing CUBIC algorithm behavior... Press Ctrl-C to stop")
        print("-" * 80)
        
        # Open perf buffer
        self.b["analysis_events"].open_perf_buffer(self.handle_event)
        
        # Main loop
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n\nStopping analysis...")
            self.analyze_cubic_behavior()
            self.print_summary_stats()
            if self.plot:
                self.plot_analysis()

def main():
    import os
    
    parser = argparse.ArgumentParser(
        description='Analyze TCP CUBIC algorithm behavior and decisions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool analyzes CUBIC algorithm behavior including:
- Phase detection (below/above origin point K)
- TCP friendliness activation
- Slow start vs congestion avoidance
- Loss events and recovery
- Performance metrics

Examples:
  # Basic analysis with summary
  sudo ./cubic_algorithm_analyzer.py
  
  # Verbose output (print each event)
  sudo ./cubic_algorithm_analyzer.py -v
  
  # Generate plots of cwnd/RTT evolution
  sudo ./cubic_algorithm_analyzer.py -p
  
  # Full analysis with plots
  sudo ./cubic_algorithm_analyzer.py -v -p
        """)
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Print detailed output for each event')
    parser.add_argument('-p', '--plot', action='store_true',
                       help='Generate plots of CUBIC behavior')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)
    
    # Check if matplotlib is available for plotting
    if args.plot:
        try:
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
        except ImportError:
            print("Warning: matplotlib not installed, plotting disabled")
            print("Install with: pip install matplotlib")
            args.plot = False
    
    analyzer = CubicAlgorithmAnalyzer(verbose=args.verbose, plot=args.plot)
    analyzer.run()

if __name__ == "__main__":
    main()