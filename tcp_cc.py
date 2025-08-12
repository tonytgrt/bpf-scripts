#!/usr/bin/env python3
"""
TCP Congestion Control Algorithm Tracker
Tracks which TCP congestion control algorithms are being used by processes
"""

import socket
import struct
import time
from datetime import datetime
from collections import defaultdict
from bcc import BPF

# eBPF program
bpf_text = """
#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>

#define TCP_CA_NAME_MAX 16
#define TASK_COMM_LEN 16

// Event types
#define EVENT_ASSIGN_CC     1
#define EVENT_INIT_CC       2
#define EVENT_SET_CC        3
#define EVENT_REINIT_CC     4
#define EVENT_CLEANUP_CC    5

struct cc_event {
    u32 pid;
    u32 tgid;
    u64 ts_ns;
    u8 event_type;
    char ca_name[TCP_CA_NAME_MAX];
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// Struct wrapper for ca_name to use in BPF_HASH
struct ca_name_key {
    char name[TCP_CA_NAME_MAX];
};

BPF_PERF_OUTPUT(cc_events);
BPF_HASH(socket_tracking, struct sock*, struct cc_event);

// Helper to extract connection info from socket
static inline void get_conn_info(struct sock *sk, struct cc_event *event) {
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    bpf_probe_read_kernel(&event->saddr, sizeof(event->saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&event->daddr, sizeof(event->daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&event->sport, sizeof(event->sport), &inet->inet_sport);
    bpf_probe_read_kernel(&event->dport, sizeof(event->dport), &inet->inet_dport);
}

// Trace tcp_assign_congestion_control
int trace_assign_cc(struct pt_regs *ctx, struct sock *sk) {
    struct cc_event event = {};
    struct inet_connection_sock *icsk;
    struct tcp_congestion_ops *ca_ops;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_ASSIGN_CC;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get congestion control name
    icsk = (struct inet_connection_sock *)sk;
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca_ops->name);
    }
    
    get_conn_info(sk, &event);
    
    // Store for tracking
    socket_tracking.update(&sk, &event);
    
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace tcp_init_congestion_control
int trace_init_cc(struct pt_regs *ctx, struct sock *sk) {
    struct cc_event event = {};
    struct inet_connection_sock *icsk;
    struct tcp_congestion_ops *ca_ops;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_INIT_CC;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get congestion control name
    icsk = (struct inet_connection_sock *)sk;
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca_ops->name);
    }
    
    get_conn_info(sk, &event);
    
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace tcp_set_congestion_control
int trace_set_cc(struct pt_regs *ctx, struct sock *sk, const char *name) {
    struct cc_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_SET_CC;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get the new congestion control name being set
    bpf_probe_read_user_str(&event.ca_name, sizeof(event.ca_name), name);
    
    get_conn_info(sk, &event);
    
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace tcp_reinit_congestion_control (internal function)
int trace_reinit_cc(struct pt_regs *ctx, struct sock *sk, struct tcp_congestion_ops *ca) {
    struct cc_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_REINIT_CC;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get the new congestion control name
    if (ca) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca->name);
    }
    
    get_conn_info(sk, &event);
    
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace tcp_cleanup_congestion_control
int trace_cleanup_cc(struct pt_regs *ctx, struct sock *sk) {
    struct cc_event event = {};
    struct inet_connection_sock *icsk;
    struct tcp_congestion_ops *ca_ops;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_CLEANUP_CC;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get congestion control name before cleanup
    icsk = (struct inet_connection_sock *)sk;
    bpf_probe_read_kernel(&ca_ops, sizeof(ca_ops), &icsk->icsk_ca_ops);
    if (ca_ops) {
        bpf_probe_read_kernel_str(&event.ca_name, sizeof(event.ca_name), &ca_ops->name);
    }
    
    get_conn_info(sk, &event);
    
    // Remove from tracking
    socket_tracking.delete(&sk);
    
    cc_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Trace common congestion control functions for monitoring
int trace_reno_cong_avoid(struct pt_regs *ctx) {
    return 0;  // Can be extended to track Reno-specific events
}

int trace_slow_start(struct pt_regs *ctx) {
    return 0;  // Can be extended to track slow start events
}
"""

class CongestionControlTracker:
    def __init__(self):
        self.bpf = BPF(text=bpf_text)
        self.event_names = {
            1: "ASSIGN",
            2: "INIT",
            3: "SET",
            4: "REINIT",
            5: "CLEANUP"
        }
        self.cc_stats = defaultdict(int)
        self.process_cc = defaultdict(set)
        self.connection_cc = {}
        
    def attach_probes(self):
        """Attach kprobes to congestion control functions"""
        # Core congestion control management functions
        functions = [
            ("tcp_assign_congestion_control", "trace_assign_cc"),
            ("tcp_init_congestion_control", "trace_init_cc"),
            ("tcp_set_congestion_control", "trace_set_cc"),
            ("tcp_cleanup_congestion_control", "trace_cleanup_cc"),
        ]
        
        # Try to attach tcp_reinit_congestion_control (might be static/inline in some kernels)
        try:
            self.bpf.attach_kprobe(event="tcp_reinit_congestion_control", 
                                   fn_name="trace_reinit_cc")
            print("✓ Attached probe to tcp_reinit_congestion_control")
        except Exception as e:
            print(f"⚠ Could not attach to tcp_reinit_congestion_control (may be inlined): {e}")
        
        for kernel_fn, bpf_fn in functions:
            try:
                self.bpf.attach_kprobe(event=kernel_fn, fn_name=bpf_fn)
                print(f"✓ Attached probe to {kernel_fn}")
            except Exception as e:
                print(f"✗ Failed to attach to {kernel_fn}: {e}")
                
        # Open perf buffer
        self.bpf["cc_events"].open_perf_buffer(self.handle_event)
        print("\n" + "="*60)
        print("TCP Congestion Control Tracker Started")
        print("="*60 + "\n")
        
    def int_to_ip(self, addr):
        """Convert integer IP to string format"""
        return socket.inet_ntoa(struct.pack("!I", addr))
    
    def handle_event(self, cpu, data, size):
        """Process congestion control events"""
        event = self.bpf["cc_events"].event(data)
        
        # Convert IPs and ports
        saddr = self.int_to_ip(event.saddr) if event.saddr else "0.0.0.0"
        daddr = self.int_to_ip(event.daddr) if event.daddr else "0.0.0.0"
        sport = socket.ntohs(event.sport) if event.sport else 0
        dport = socket.ntohs(event.dport) if event.dport else 0
        
        # Decode strings
        ca_name = event.ca_name.decode('utf-8', 'ignore').rstrip('\x00')
        comm = event.comm.decode('utf-8', 'ignore').rstrip('\x00')
        event_type = self.event_names.get(event.event_type, f"UNKNOWN_{event.event_type}")
        
        # Update statistics
        if ca_name:
            self.cc_stats[ca_name] += 1
            self.process_cc[comm].add(ca_name)
            
            conn_key = f"{saddr}:{sport}->{daddr}:{dport}"
            if conn_key != "0.0.0.0:0->0.0.0.0:0":
                self.connection_cc[conn_key] = ca_name
        
        # Format timestamp
        ts_sec = event.ts_ns / 1e9
        ts_str = datetime.fromtimestamp(ts_sec).strftime('%H:%M:%S.%f')[:-3]
        
        # Print event
        print(f"[{ts_str}] {event_type:<8} PID={event.pid:<7} {comm:<16} "
              f"CC={ca_name:<10} {saddr}:{sport} -> {daddr}:{dport}")
    
    def print_statistics(self):
        """Print accumulated statistics"""
        print("\n" + "="*60)
        print("CONGESTION CONTROL STATISTICS")
        print("="*60)
        
        print("\n📊 Algorithm Usage Count:")
        for cc_name, count in sorted(self.cc_stats.items(), key=lambda x: -x[1]):
            print(f"  {cc_name:<15} : {count:>6} events")
        
        print("\n🔧 Processes and Their CC Algorithms:")
        for comm, cc_set in sorted(self.process_cc.items()):
            cc_list = ", ".join(sorted(cc_set))
            print(f"  {comm:<20} : {cc_list}")
        
        if self.connection_cc:
            print("\n🔗 Active Connections (last known CC):")
            for conn, cc in list(self.connection_cc.items())[:10]:  # Show first 10
                print(f"  {conn:<40} : {cc}")
            if len(self.connection_cc) > 10:
                print(f"  ... and {len(self.connection_cc) - 10} more connections")
    
    def run(self, duration=None):
        """Run the tracker"""
        try:
            if duration:
                print(f"Running for {duration} seconds...")
                end_time = time.time() + duration
                while time.time() < end_time:
                    self.bpf.perf_buffer_poll(timeout=100)
            else:
                print("Running... Press Ctrl+C to stop")
                while True:
                    self.bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            pass
        finally:
            self.print_statistics()
            self.cleanup()
    
    def cleanup(self):
        """Clean up BPF resources"""
        print("\n🧹 Cleaning up...")
        self.bpf.cleanup()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Track TCP Congestion Control algorithms in use by processes'
    )
    parser.add_argument(
        '-d', '--duration',
        type=int,
        help='Duration to run in seconds (default: run until Ctrl+C)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output'
    )
    
    args = parser.parse_args()
    
    # Check for root privileges
    import os
    if os.geteuid() != 0:
        print("❌ This script must be run as root (for eBPF)")
        exit(1)
    
    # Create and run tracker
    tracker = CongestionControlTracker()
    tracker.attach_probes()
    tracker.run(duration=args.duration)


if __name__ == "__main__":
    main()