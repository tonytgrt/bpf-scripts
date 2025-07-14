#!/usr/bin/env python3
"""
TCP v4 Receive Function Tracker
Tracks various branches in tcp_v4_rcv using kprobes at specific offsets
"""

from bcc import BPF
import ctypes as ct
import socket
import struct
import time
from datetime import datetime
import argparse

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
    
    # Only print if we have valid IP addresses
    if event.saddr != 0 or event.daddr != 0:
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        src_ip = int_to_ip(event.saddr)
        dst_ip = int_to_ip(event.daddr)
        drop_reason = DROP_REASONS.get(event.drop_reason, f"UNKNOWN({event.drop_reason})")
        
        print(f"[{timestamp}] DROP: {src_ip}:{event.sport} -> {dst_ip}:{event.dport} "
              f"Reason: {drop_reason}")

def print_stats(b):
    """Print accumulated statistics"""
    stats_map = b["stats_map"]
    drop_reasons = b["drop_reasons"]
    
    print("\n" + "="*60)
    print("TCP v4 Receive Statistics")
    print("="*60)
    
    # Get stats
    key = ct.c_uint32(0)
    stats = stats_map[key]
    
    if stats.total_packets > 0:
        print(f"Total packets processed: {stats.total_packets:,}")
        print(f"\nBranch Statistics:")
        print(f"  Not for host:       {stats.not_for_host:,} ({stats.not_for_host/stats.total_packets*100:.2f}%)")
        print(f"  No socket found:    {stats.no_socket:,} ({stats.no_socket/stats.total_packets*100:.2f}%)")
        print(f"  TIME_WAIT state:    {stats.time_wait:,} ({stats.time_wait/stats.total_packets*100:.2f}%)")
        print(f"  Checksum errors:    {stats.checksum_error:,} ({stats.checksum_error/stats.total_packets*100:.2f}%)")
        print(f"  LISTEN state:       {stats.listen_state:,} ({stats.listen_state/stats.total_packets*100:.2f}%)")
        print(f"  Socket busy:        {stats.socket_busy:,} ({stats.socket_busy/stats.total_packets*100:.2f}%)")
        print(f"  XFRM policy drops:  {stats.xfrm_policy_drop:,} ({stats.xfrm_policy_drop/stats.total_packets*100:.2f}%)")
        print(f"  NEW_SYN_RECV:       {stats.new_syn_recv:,} ({stats.new_syn_recv/stats.total_packets*100:.2f}%)")
    
    # Print drop reasons summary
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
    args = parser.parse_args()
    
    # Load BPF program
    with open('tcp_v4_rcv_tracker.c', 'r') as f:
        bpf_text = f.read()
    
    # Initialize BPF
    b = BPF(text=bpf_text)
    
    # Attach kprobes to tcp_v4_rcv function at specific offsets
    # Main function entry
    b.attach_kprobe(event="tcp_v4_rcv", fn_name="trace_tcp_v4_rcv")
    
    # Attach to specific offsets within tcp_v4_rcv
    # Note: These offsets need to be adjusted based on your kernel version
    tcp_v4_rcv_addr = b.ksym("tcp_v4_rcv")
    
    # Branch offsets (from the disassembly analysis)
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
            b.attach_kprobe(event_re=f"tcp_v4_rcv", fn_name=fn_name, event_offset=offset)
            print(f"✓ Attached {fn_name} at offset 0x{offset:x}")
        except Exception as e:
            print(f"✗ Failed to attach {fn_name} at offset 0x{offset:x}: {e}")
    
    # Open perf buffer if verbose mode
    if args.verbose:
        b["packet_events"].open_perf_buffer(print_packet_event)
    
    print(f"\nTracing TCP v4 receive function... Press Ctrl+C to exit")
    print(f"Statistics will be displayed every {args.interval} seconds\n")
    
    # Main loop
    try:
        while True:
            # Process events if verbose
            if args.verbose:
                b.perf_buffer_poll(timeout=100)
            
            # Print statistics periodically
            time.sleep(args.interval)
            print_stats(b)
            
    except KeyboardInterrupt:
        print("\n\nFinal Statistics:")
        print_stats(b)
        print("\nDetaching probes...")

if __name__ == "__main__":
    main()