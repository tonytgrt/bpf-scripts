#!/usr/bin/env python3
"""
TCP v4 Receive Function Tracker (Combined Version)
Tracks various branches in tcp_v4_rcv using kprobes at specific offsets
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
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <net/sock.h>

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

// Main entry - track overall statistics
int trace_tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    u32 key = 0;
    struct tcp_stats *stats, zero_stats = {};
    
    stats = stats_map.lookup_or_try_init(&key, &zero_stats);
    if (stats) {
        __sync_fetch_and_add(&stats->total_packets, 1);
    }
    
    return 0;
}

// Track "not for host" branch
int trace_not_for_host(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->not_for_host, 1);
    }
    
    struct packet_info info = {};
    info.drop_reason = 2; // SKB_DROP_REASON_NOT_SPECIFIED
    info.timestamp = bpf_ktime_get_ns();
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Track "no socket found" branch
int trace_no_socket(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->no_socket, 1);
    }
    
    struct packet_info info = {};
    info.drop_reason = 3; // SKB_DROP_REASON_NO_SOCKET
    info.timestamp = bpf_ktime_get_ns();
    
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    // Track drop reason
    u32 reason = 3;
    u64 *count = drop_reasons.lookup(&reason);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init_count = 1;
        drop_reasons.update(&reason, &init_count);
    }
    
    return 0;
}

// Track TIME_WAIT state
int trace_time_wait(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->time_wait, 1);
    }
    
    return 0;
}

// Track checksum error
int trace_checksum_error(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->checksum_error, 1);
    }
    
    struct packet_info info = {};
    info.drop_reason = 5; // SKB_DROP_REASON_TCP_CSUM
    info.timestamp = bpf_ktime_get_ns();
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    // Track drop reason
    u32 reason = 5;
    u64 *count = drop_reasons.lookup(&reason);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init_count = 1;
        drop_reasons.update(&reason, &init_count);
    }
    
    return 0;
}

// Track LISTEN state processing
int trace_listen_state(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->listen_state, 1);
    }
    
    return 0;
}

// Track socket busy/backlog
int trace_socket_busy(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->socket_busy, 1);
    }
    
    return 0;
}

// Track XFRM policy drop
int trace_xfrm_policy_drop(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->xfrm_policy_drop, 1);
    }
    
    struct packet_info info = {};
    info.drop_reason = 14; // SKB_DROP_REASON_XFRM_POLICY
    info.timestamp = bpf_ktime_get_ns();
    packet_events.perf_submit(ctx, &info, sizeof(info));
    
    return 0;
}

// Track NEW_SYN_RECV state
int trace_new_syn_recv(struct pt_regs *ctx) {
    u32 key = 0;
    struct tcp_stats *stats = stats_map.lookup(&key);
    if (stats) {
        __sync_fetch_and_add(&stats->new_syn_recv, 1);
    }
    
    return 0;
}
"""

# Drop reason mappings
DROP_REASONS = {
    2: "NOT_SPECIFIED",
    3: "NO_SOCKET",
    4: "PKT_TOO_SMALL",
    5: "TCP_CSUM",
    6: "SOCKET_FILTER",
    14: "XFRM_POLICY",
    70: "TCP_MINTTL"
}

# Define the packet info structure
class PacketInfo(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("timestamp", ct.c_uint64),
        ("drop_reason", ct.c_uint32)
    ]

# Define the stats structure
class TcpStats(ct.Structure):
    _fields_ = [
        ("total_packets", ct.c_uint64),
        ("not_for_host", ct.c_uint64),
        ("no_socket", ct.c_uint64),
        ("time_wait", ct.c_uint64),
        ("checksum_error", ct.c_uint64),
        ("listen_state", ct.c_uint64),
        ("socket_busy", ct.c_uint64),
        ("xfrm_policy_drop", ct.c_uint64),
        ("new_syn_recv", ct.c_uint64)
    ]

def int_to_ip(addr):
    """Convert integer IP to string format"""
    return socket.inet_ntoa(struct.pack("!I", addr))

def print_packet_event(cpu, data, size):
    """Print packet event information"""
    event = ct.cast(data, ct.POINTER(PacketInfo)).contents
    
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    drop_reason = DROP_REASONS.get(event.drop_reason, f"UNKNOWN({event.drop_reason})")
    
    print(f"[{timestamp}] DROP - Reason: {drop_reason}")

def print_stats(b):
    """Print accumulated statistics"""
    stats_map = b["stats_map"]
    drop_reasons = b["drop_reasons"]
    
    print("\n" + "="*70)
    print("TCP v4 Receive Statistics")
    print("="*70)
    
    # Get stats
    key = ct.c_uint32(0)
    try:
        stats = stats_map[key]
    except KeyError:
        print("No statistics collected yet...")
        return
    
    if stats.total_packets > 0:
        print(f"Total packets processed: {stats.total_packets:,}")
        print(f"\nBranch Statistics:")
        print(f"  Not for host:       {stats.not_for_host:>10,} ({stats.not_for_host/stats.total_packets*100:6.2f}%)")
        print(f"  No socket found:    {stats.no_socket:>10,} ({stats.no_socket/stats.total_packets*100:6.2f}%)")
        print(f"  TIME_WAIT state:    {stats.time_wait:>10,} ({stats.time_wait/stats.total_packets*100:6.2f}%)")
        print(f"  Checksum errors:    {stats.checksum_error:>10,} ({stats.checksum_error/stats.total_packets*100:6.2f}%)")
        print(f"  LISTEN state:       {stats.listen_state:>10,} ({stats.listen_state/stats.total_packets*100:6.2f}%)")
        print(f"  Socket busy:        {stats.socket_busy:>10,} ({stats.socket_busy/stats.total_packets*100:6.2f}%)")
        print(f"  XFRM policy drops:  {stats.xfrm_policy_drop:>10,} ({stats.xfrm_policy_drop/stats.total_packets*100:6.2f}%)")
        print(f"  NEW_SYN_RECV:       {stats.new_syn_recv:>10,} ({stats.new_syn_recv/stats.total_packets*100:6.2f}%)")
    
    # Print drop reasons summary
    if drop_reasons:
        print(f"\nDrop Reasons Summary:")
        for reason, count in drop_reasons.items():
            reason_name = DROP_REASONS.get(reason.value, f"UNKNOWN({reason.value})")
            print(f"  {reason_name}: {count.value:,}")

def main():
    parser = argparse.ArgumentParser(description='Track TCP v4 receive function branches')
    parser.add_argument('-i', '--interval', type=int, default=5,
                        help='Statistics display interval in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show packet drop events in real-time')
    parser.add_argument('--skip-offsets', action='store_true',
                        help='Skip offset-based probes (use only main function entry)')
    args = parser.parse_args()
    
    # Initialize BPF
    b = BPF(text=bpf_text)
    
    # Attach kprobes to tcp_v4_rcv function at specific offsets
    # Main function entry
    b.attach_kprobe(event="tcp_v4_rcv", fn_name="trace_tcp_v4_rcv")
    print("✓ Attached trace_tcp_v4_rcv at function entry")
    
    if not args.skip_offsets:
        # Branch offsets (from the disassembly analysis)
        # Note: These offsets are based on the provided disassembly
        # and may need adjustment for different kernel versions
        offsets = {
            "trace_not_for_host": 0x73,      # Not for host check
            "trace_no_socket": 0x722,         # No socket found
            "trace_time_wait": 0x279,         # TIME_WAIT state
            "trace_checksum_error": 0x2e8,    # Checksum error
            "trace_listen_state": 0xedf,      # LISTEN state
            "trace_socket_busy": 0xec2,       # Socket busy
            "trace_xfrm_policy_drop": 0x8e5,  # XFRM policy drop
            "trace_new_syn_recv": 0x5db       # NEW_SYN_RECV state
        }
        
        # Attach kprobes at offsets
        for fn_name, offset in offsets.items():
            try:
                # For offset-based probes, we use the function name with offset
                b.attach_kprobe(event="tcp_v4_rcv", fn_name=fn_name, event_off=offset)
                print(f"✓ Attached {fn_name} at offset 0x{offset:x}")
            except Exception as e:
                print(f"✗ Failed to attach {fn_name} at offset 0x{offset:x}: {e}")
                print(f"  (This might be due to kernel version differences)")
    
    # Open perf buffer if verbose mode
    if args.verbose:
        b["packet_events"].open_perf_buffer(print_packet_event)
    
    print(f"\nTracing TCP v4 receive function... Press Ctrl+C to exit")
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