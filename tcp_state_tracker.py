#!/usr/bin/env python3
"""
TCP State Process Tracker
Tracks various branches and state transitions in tcp_rcv_state_process
"""

from bcc import BPF
import ctypes as ct
import socket
import struct
import time
from datetime import datetime
import argparse

# BPF program
bpf_text = """
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/tcp_states.h>

// Structure to hold state transition information
struct state_info {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 old_state;
    u8 new_state;
    u64 timestamp;
    u32 event_type;  // 0=transition, 1=error, 2=special
};

// Structure for statistics
struct state_stats {
    u64 total_calls;
    u64 listen_state;
    u64 syn_sent_state;
    u64 syn_recv_to_established;
    u64 fin_wait1_to_fin_wait2;
    u64 to_time_wait;
    u64 to_last_ack;
    u64 challenge_acks;
    u64 resets;
    u64 fast_open_checks;
    u64 ack_processing;
    u64 data_queued;
    u64 checksum_errors;
    u64 abort_on_data;
};

// Maps
BPF_HASH(stats_map, u32, struct state_stats);
BPF_PERF_OUTPUT(state_events);
BPF_HASH(state_distribution, u8, u64);

// Helper to get socket state
static u8 get_sk_state(struct sock *sk) {
    u8 state = 0;
    bpf_probe_read(&state, sizeof(state), &sk->sk_state);
    return state;
}

// Main entry - track overall statistics
int trace_tcp_rcv_state_process(struct pt_regs *ctx, struct sock *sk) {
    u32 key = 0;
    struct state_stats *stats, zero_stats = {};
    
    stats = stats_map.lookup_or_try_init(&key, &zero_stats);
    if (stats) {
        __sync_fetch_and_add(&stats->total_calls, 1);
    }
    
    // Track state distribution
    u8 state = get_sk_state(sk);
    u64 *count = state_distribution.lookup(&state);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init_count = 1;
        state_distribution.update(&state, &init_count);
    }
    
    return 0;
}

// Track LISTEN state processing (offset 0x12d)
int trace_listen_state(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->listen_state, 1);
    }
    return 0;
}

// Track SYN_SENT state processing (offset 0x52)
int trace_syn_sent_state(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->syn_sent_state, 1);
    }
    return 0;
}

// Track SYN_RECV to ESTABLISHED transition (offset 0x301)
int trace_syn_recv_to_established(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->syn_recv_to_established, 1);
    }
    
    struct state_info info = {};
    info.old_state = TCP_SYN_RECV;
    info.new_state = TCP_ESTABLISHED;
    info.timestamp = bpf_ktime_get_ns();
    info.event_type = 0; // transition
    
    state_events.perf_submit(ctx, &info, sizeof(info));
    return 0;
}

// Track FIN_WAIT1 to FIN_WAIT2 transition (offset 0xe7d)
int trace_fin_wait1_to_fin_wait2(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->fin_wait1_to_fin_wait2, 1);
    }
    
    struct state_info info = {};
    info.old_state = TCP_FIN_WAIT1;
    info.new_state = TCP_FIN_WAIT2;
    info.timestamp = bpf_ktime_get_ns();
    info.event_type = 0; // transition
    
    state_events.perf_submit(ctx, &info, sizeof(info));
    return 0;
}

// Track transition to TIME_WAIT (offset 0x769)
int trace_to_time_wait(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->to_time_wait, 1);
    }
    
    struct state_info info = {};
    info.new_state = TCP_TIME_WAIT;
    info.timestamp = bpf_ktime_get_ns();
    info.event_type = 0; // transition
    
    state_events.perf_submit(ctx, &info, sizeof(info));
    return 0;
}

// Track LAST_ACK processing (offset 0xb3d)
int trace_last_ack(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->to_last_ack, 1);
    }
    return 0;
}

// Track challenge ACK sending (offset 0x714)
int trace_challenge_ack(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->challenge_acks, 1);
    }
    
    struct state_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.event_type = 1; // error
    
    state_events.perf_submit(ctx, &info, sizeof(info));
    return 0;
}

// Track connection resets (offset 0x8fc)
int trace_reset(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->resets, 1);
    }
    
    struct state_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.event_type = 1; // error
    
    state_events.perf_submit(ctx, &info, sizeof(info));
    return 0;
}

// Track Fast Open handling (offset 0x67f)
int trace_fast_open(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->fast_open_checks, 1);
    }
    return 0;
}

// Track ACK processing (offset 0x4f3)
int trace_ack_processing(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->ack_processing, 1);
    }
    return 0;
}

// Track data queuing (offset 0x5be)
int trace_data_queue(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->data_queued, 1);
    }
    return 0;
}

// Track abort on data (offset 0xfd9)
int trace_abort_on_data(struct pt_regs *ctx) {
    u32 key = 0;
    struct state_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->abort_on_data, 1);
    }
    
    struct state_info info = {};
    info.timestamp = bpf_ktime_get_ns();
    info.event_type = 1; // error
    
    state_events.perf_submit(ctx, &info, sizeof(info));
    return 0;
}
"""

# TCP state names
TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV"
}

# Event types
EVENT_TYPES = {
    0: "TRANSITION",
    1: "ERROR",
    2: "SPECIAL"
}

# Define the state info structure
class StateInfo(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("old_state", ct.c_uint8),
        ("new_state", ct.c_uint8),
        ("timestamp", ct.c_uint64),
        ("event_type", ct.c_uint32)
    ]

# Define the stats structure
class StateStats(ct.Structure):
    _fields_ = [
        ("total_calls", ct.c_uint64),
        ("listen_state", ct.c_uint64),
        ("syn_sent_state", ct.c_uint64),
        ("syn_recv_to_established", ct.c_uint64),
        ("fin_wait1_to_fin_wait2", ct.c_uint64),
        ("to_time_wait", ct.c_uint64),
        ("to_last_ack", ct.c_uint64),
        ("challenge_acks", ct.c_uint64),
        ("resets", ct.c_uint64),
        ("fast_open_checks", ct.c_uint64),
        ("ack_processing", ct.c_uint64),
        ("data_queued", ct.c_uint64),
        ("checksum_errors", ct.c_uint64),
        ("abort_on_data", ct.c_uint64)
    ]

def print_state_event(cpu, data, size):
    """Print state event information"""
    event = ct.cast(data, ct.POINTER(StateInfo)).contents
    
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    event_type = EVENT_TYPES.get(event.event_type, "UNKNOWN")
    
    if event.event_type == 0:  # Transition
        old_state = TCP_STATES.get(event.old_state, f"STATE_{event.old_state}")
        new_state = TCP_STATES.get(event.new_state, f"STATE_{event.new_state}")
        print(f"[{timestamp}] TRANSITION: {old_state} → {new_state}")
    elif event.event_type == 1:  # Error
        print(f"[{timestamp}] ERROR/ACTION: ", end="")
        if event.old_state == 0 and event.new_state == 0:
            print("Challenge ACK / Reset / Abort")
    else:
        print(f"[{timestamp}] {event_type}")

def print_stats(b):
    """Print accumulated statistics"""
    stats_map = b["stats_map"]
    state_distribution = b["state_distribution"]
    
    print("\n" + "="*70)
    print("TCP State Process Statistics")
    print("="*70)
    
    # Get stats
    key = ct.c_uint32(0)
    try:
        stats = stats_map[key]
    except KeyError:
        print("No statistics collected yet...")
        return
    
    if stats.total_calls > 0:
        print(f"Total function calls: {stats.total_calls:,}")
        
        print(f"\nState Processing:")
        print(f"  LISTEN state:              {stats.listen_state:>10,} ({stats.listen_state/stats.total_calls*100:6.2f}%)")
        print(f"  SYN_SENT state:            {stats.syn_sent_state:>10,} ({stats.syn_sent_state/stats.total_calls*100:6.2f}%)")
        
        print(f"\nState Transitions:")
        print(f"  SYN_RECV → ESTABLISHED:    {stats.syn_recv_to_established:>10,}")
        print(f"  FIN_WAIT1 → FIN_WAIT2:     {stats.fin_wait1_to_fin_wait2:>10,}")
        print(f"  → TIME_WAIT:               {stats.to_time_wait:>10,}")
        print(f"  → LAST_ACK:                {stats.to_last_ack:>10,}")
        
        print(f"\nProcessing Events:")
        print(f"  ACK processing:            {stats.ack_processing:>10,} ({stats.ack_processing/stats.total_calls*100:6.2f}%)")
        print(f"  Data queued:               {stats.data_queued:>10,} ({stats.data_queued/stats.total_calls*100:6.2f}%)")
        print(f"  Fast Open checks:          {stats.fast_open_checks:>10,} ({stats.fast_open_checks/stats.total_calls*100:6.2f}%)")
        
        print(f"\nError/Attack Handling:")
        print(f"  Challenge ACKs sent:       {stats.challenge_acks:>10,}")
        print(f"  Connection resets:         {stats.resets:>10,}")
        print(f"  Abort on data:             {stats.abort_on_data:>10,}")
    
    # Print state distribution
    if state_distribution:
        print(f"\nState Distribution:")
        for state, count in sorted(state_distribution.items()):
            state_name = TCP_STATES.get(state.value, f"STATE_{state.value}")
            percentage = count.value / stats.total_calls * 100 if stats.total_calls > 0 else 0
            print(f"  {state_name:15}: {count.value:>10,} ({percentage:6.2f}%)")

def main():
    parser = argparse.ArgumentParser(description='Track TCP state processing function branches')
    parser.add_argument('-i', '--interval', type=int, default=5,
                        help='Statistics display interval in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show state transition events in real-time')
    parser.add_argument('--skip-offsets', action='store_true',
                        help='Skip offset-based probes (use only main function entry)')
    args = parser.parse_args()
    
    # Initialize BPF
    b = BPF(text=bpf_text)
    
    # Attach kprobes to tcp_rcv_state_process function at specific offsets
    # Main function entry
    b.attach_kprobe(event="tcp_rcv_state_process", fn_name="trace_tcp_rcv_state_process")
    print("✓ Attached trace_tcp_rcv_state_process at function entry")
    
    if not args.skip_offsets:
        # Branch offsets (from the disassembly analysis)
        offsets = {
            "trace_listen_state": 0x12d,              # LISTEN state handler
            "trace_syn_sent_state": 0x52,             # SYN_SENT check
            "trace_syn_recv_to_established": 0x301,   # SYN_RECV → ESTABLISHED
            "trace_fin_wait1_to_fin_wait2": 0xe7d,    # FIN_WAIT1 → FIN_WAIT2
            "trace_to_time_wait": 0x769,              # → TIME_WAIT
            "trace_last_ack": 0xb3d,                  # LAST_ACK processing
            "trace_challenge_ack": 0x714,             # Challenge ACK
            "trace_reset": 0x8fc,                     # Connection reset
            "trace_fast_open": 0x67f,                 # Fast Open handling
            "trace_ack_processing": 0x4f3,            # ACK processing
            "trace_data_queue": 0x5be,                # Data queuing
            "trace_abort_on_data": 0xfd9             # Abort on data
        }
        
        # Attach kprobes at offsets
        for fn_name, offset in offsets.items():
            try:
                b.attach_kprobe(event="tcp_rcv_state_process", fn_name=fn_name, event_off=offset)
                print(f"✓ Attached {fn_name} at offset 0x{offset:x}")
            except Exception as e:
                print(f"✗ Failed to attach {fn_name} at offset 0x{offset:x}: {e}")
                print(f"  (This might be due to kernel version differences)")
    
    # Open perf buffer if verbose mode
    if args.verbose:
        b["state_events"].open_perf_buffer(print_state_event)
    
    print(f"\nTracing TCP state processing... Press Ctrl+C to exit")
    print(f"Statistics will be displayed every {args.interval} seconds\n")
    
    # Main loop
    last_print = time.time()
    try:
        while True:
            # Process events if verbose
            if args.verbose:
                b.perf_buffer_poll(timeout=100)
            else:
                time.sleep(0.1)
            
            # Print statistics periodically
            if time.time() - last_print >= args.interval:
                print_stats(b)
                last_print = time.time()
            
    except KeyboardInterrupt:
        print("\n\nFinal Statistics:")
        print_stats(b)
        print("\nDetaching probes...")

if __name__ == "__main__":
    main()