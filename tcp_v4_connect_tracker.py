#!/usr/bin/env python3
"""
eBPF tracker for tcp_v4_connect branches
Tracks important decision points during TCP connection establishment
"""

from bcc import BPF
import time
from collections import defaultdict
import socket
import struct

# BPF program
bpf_text = """
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/inet_sock.h>

// Branch types for tcp_v4_connect
#define CONNECT_ENTRY           0
#define CONNECT_INVALID_ADDRLEN 1
#define CONNECT_WRONG_FAMILY    2
#define CONNECT_SRC_ROUTE_OPT   3
#define CONNECT_ROUTE_ERROR     4
#define CONNECT_MULTICAST_BCAST 5
#define CONNECT_NO_SRC_ADDR     6
#define CONNECT_TS_RESET        7
#define CONNECT_REPAIR_MODE     8
#define CONNECT_HASH_ERROR      9
#define CONNECT_FASTOPEN_DEFER  10
#define CONNECT_TCP_CONNECT_ERR 11
#define CONNECT_ENETUNREACH     12
#define CONNECT_NEW_SPORT       13
#define CONNECT_SUCCESS         14
#define CONNECT_WRITE_SEQ_INIT  15

struct connect_event {
    u32 pid;
    u32 tgid;
    u64 ts_ns;
    u8 branch_type;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    int error_code;
    char comm[16];
};

BPF_PERF_OUTPUT(connect_events);

// Main entry point
int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr) {
    struct connect_event event = {};
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_ENTRY;
    
    // Try to get destination address
    bpf_probe_read(&event.daddr, sizeof(event.daddr), &sin->sin_addr.s_addr);
    bpf_probe_read(&event.dport, sizeof(event.dport), &sin->sin_port);
    
    // Get source address from socket
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read(&event.saddr, sizeof(event.saddr), &inet->inet_saddr);
    bpf_probe_read(&event.sport, sizeof(event.sport), &inet->inet_sport);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Invalid address length check (offset 0x35)
int trace_invalid_addrlen(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_INVALID_ADDRLEN;
    event.error_code = -22; // -EINVAL
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Wrong address family (offset 0x42)
int trace_wrong_family(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_WRONG_FAMILY;
    event.error_code = -97; // -EAFNOSUPPORT
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Source routing option branch (offset 0x57)
int trace_src_route_opt(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_SRC_ROUTE_OPT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Route lookup error (offset 0x184)
int trace_route_error(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_ROUTE_ERROR;
    
    // Try to capture error code from rax
    event.error_code = PT_REGS_RC(ctx);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Multicast/broadcast check (offset 0x19a)
int trace_multicast_bcast(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_MULTICAST_BCAST;
    event.error_code = -101; // -ENETUNREACH
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// No source address branch (offset 0x1cc)
int trace_no_src_addr(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_NO_SRC_ADDR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Timestamp reset branch (offset 0x1f4)
int trace_ts_reset(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_TS_RESET;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// TCP repair mode check (offset 0x206)
int trace_repair_mode(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_REPAIR_MODE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// inet_hash_connect error (offset 0x283)
int trace_hash_error(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_HASH_ERROR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Fast open defer (offset 0x3b1)
int trace_fastopen_defer(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_FASTOPEN_DEFER;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// tcp_connect error (offset 0x43a)
int trace_tcp_connect_err(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_TCP_CONNECT_ERR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// ENETUNREACH specific handling (offset 0x477)
int trace_enetunreach(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_ENETUNREACH;
    event.error_code = -101; // -ENETUNREACH
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// New source port selection (offset 0x337)
int trace_new_sport(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_NEW_SPORT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Write sequence initialization (offset 0x372)
int trace_write_seq_init(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_WRITE_SEQ_INIT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Success path - connection established
int trace_success(struct pt_regs *ctx) {
    struct connect_event event = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid;
    event.tgid = pid_tgid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    event.branch_type = CONNECT_SUCCESS;
    event.error_code = 0;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Branch names for display
BRANCH_NAMES = {
    0: "ENTRY",
    1: "INVALID_ADDRLEN",
    2: "WRONG_FAMILY",
    3: "SRC_ROUTE_OPT",
    4: "ROUTE_ERROR",
    5: "MULTICAST_BCAST",
    6: "NO_SRC_ADDR",
    7: "TS_RESET",
    8: "REPAIR_MODE",
    9: "HASH_ERROR",
    10: "FASTOPEN_DEFER",
    11: "TCP_CONNECT_ERR",
    12: "ENETUNREACH",
    13: "NEW_SPORT",
    14: "SUCCESS",
    15: "WRITE_SEQ_INIT"
}

# Offsets based on the disassembly (adjust for your kernel)
BRANCH_OFFSETS = {
    "trace_invalid_addrlen": 0x35,      # jbe to error for addr_len check
    "trace_wrong_family": 0x42,         # jne for AF_INET check
    "trace_src_route_opt": 0x57,        # jne for source routing
    "trace_route_error": 0x184,         # ja for IS_ERR(rt)
    "trace_multicast_bcast": 0x19a,     # jne for multicast/broadcast
    "trace_no_src_addr": 0x1cc,         # je for !inet->inet_saddr
    "trace_ts_reset": 0x1f4,            # je for timestamp reset
    "trace_repair_mode": 0x206,         # jne for repair mode skip
    "trace_hash_error": 0x283,          # je for hash connect success
    "trace_new_sport": 0x337,           # jne for new sport needed
    "trace_write_seq_init": 0x372,      # je for write_seq init
    "trace_fastopen_defer": 0x3b1,      # jne for fastopen defer
    "trace_tcp_connect_err": 0x43a,     # je for tcp_connect success
    "trace_enetunreach": 0x477,         # jne for ENETUNREACH
}

def print_event(cpu, data, size):
    event = b["connect_events"].event(data)
    
    # Convert addresses to readable format
    saddr = socket.inet_ntoa(struct.pack('I', event.saddr)) if event.saddr else "0.0.0.0"
    daddr = socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0"
    sport = socket.ntohs(event.sport) if event.sport else 0
    dport = socket.ntohs(event.dport) if event.dport else 0
    
    branch_name = BRANCH_NAMES.get(event.branch_type, f"UNKNOWN_{event.branch_type}")
    
    print(f"{event.ts_ns/1e9:.6f} [{event.pid:6d}] {event.comm.decode('utf-8', 'ignore'):16s} "
          f"{branch_name:20s} {saddr}:{sport:5d} -> {daddr}:{dport:5d} "
          f"err={event.error_code:4d}")

def main():
    print("Tracking tcp_v4_connect branches...")
    print("TIME(s)      PID     COMM             BRANCH               SRC                  DST                  ERROR")
    print("-" * 120)
    
    global b
    b = BPF(text=bpf_text)
    
    # Attach main entry probe
    b.attach_kprobe(event=b"tcp_v4_connect", fn_name=b"trace_tcp_v4_connect")
    
    # Attach offset-based probes for branches
    for fn_name, offset in BRANCH_OFFSETS.items():
        try:
            b.attach_kprobe(
                event=b"tcp_v4_connect",
                fn_name=fn_name.encode(),
                event_off=offset
            )
            print(f"✓ Attached {fn_name} at offset 0x{offset:x}")
        except Exception as e:
            print(f"✗ Failed to attach {fn_name} at offset 0x{offset:x}: {e}")
    
    # Open perf buffer
    b["connect_events"].open_perf_buffer(print_event)
    
    # Poll for events
    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\nDetaching probes...")
        
    # Print statistics
    print("\n=== Branch Hit Statistics ===")
    # Could add more detailed statistics collection here

if __name__ == "__main__":
    main()