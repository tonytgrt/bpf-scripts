#!/usr/bin/env python3
"""
TCP Connection Failure Analyzer
Tracks failure paths in tcp_v4_connect to identify connection issues
"""

from bcc import BPF
import time
import socket
import struct
from collections import defaultdict
from datetime import datetime

# BPF program focusing on failure scenarios
bpf_text = """
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/inet_sock.h>

// Failure types
enum failure_type {
    FAIL_NONE = 0,
    FAIL_INVALID_ADDR,      // Invalid address parameters
    FAIL_ROUTE_LOOKUP,      // Route lookup failed
    FAIL_MULTICAST,         // Multicast/broadcast destination
    FAIL_SRC_BIND,          // Source address binding failed
    FAIL_PORT_EXHAUSTED,    // No available ports
    FAIL_CONNECT,           // tcp_connect failed
    FAIL_MEMORY,            // Memory allocation failed
    FAIL_PERMISSION,        // Permission denied
    FAIL_NETWORK_DOWN,      // Network unreachable
};

struct failure_event {
    u32 pid;
    u32 tgid;
    u64 ts_ns;
    u8 failure_type;
    int error_code;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[16];
    char details[64];  // Additional failure details
};

BPF_PERF_OUTPUT(failure_events);
BPF_HASH(connect_tracking, u32, struct failure_event);

// Track connection attempts
int trace_connect_start(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event event = {};
    
    event.pid = tid;
    event.tgid = tid >> 32;
    event.ts_ns = bpf_ktime_get_ns();
    
    // Capture destination
    if (addr_len >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
        bpf_probe_read(&event.daddr, sizeof(event.daddr), &sin->sin_addr.s_addr);
        bpf_probe_read(&event.dport, sizeof(event.dport), &sin->sin_port);
        
        // Check address family
        u16 family;
        bpf_probe_read(&family, sizeof(family), &sin->sin_family);
        if (family != AF_INET) {
            event.failure_type = FAIL_INVALID_ADDR;
            bpf_probe_read_str(event.details, sizeof(event.details), "Wrong address family");
        }
    } else {
        event.failure_type = FAIL_INVALID_ADDR;
        bpf_probe_read_str(event.details, sizeof(event.details), "Address too short");
    }
    
    // Capture source if available
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read(&event.saddr, sizeof(event.saddr), &inet->inet_saddr);
    bpf_probe_read(&event.sport, sizeof(event.sport), &inet->inet_sport);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    connect_tracking.update(&tid, &event);
    
    return 0;
}

// Invalid address length (offset 0x4f0)
int trace_invalid_addrlen(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_INVALID_ADDR;
        event->error_code = -22; // EINVAL
        bpf_probe_read_str(event->details, sizeof(event->details), 
                          "Address length < sizeof(sockaddr_in)");
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// Wrong address family (offset 0x4e6)
int trace_wrong_family(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_INVALID_ADDR;
        event->error_code = -97; // EAFNOSUPPORT
        bpf_probe_read_str(event->details, sizeof(event->details), 
                          "Address family != AF_INET");
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// Route lookup failure (offset 0x46c)
int trace_route_failure(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_ROUTE_LOOKUP;
        event->error_code = PT_REGS_RC(ctx);  // Get actual error
        
        if (event->error_code == -101) {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Network unreachable - no route to host");
        } else if (event->error_code == -13) {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Permission denied - check firewall/policy");
        } else {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Route lookup failed");
        }
        
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// Multicast/broadcast destination (offset 0x4fa)
int trace_multicast_fail(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_MULTICAST;
        event->error_code = -101; // ENETUNREACH
        bpf_probe_read_str(event->details, sizeof(event->details), 
                          "TCP cannot connect to multicast/broadcast address");
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// Source address binding failure (offset 0x417)
int trace_src_bind_fail(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_SRC_BIND;
        event->error_code = PT_REGS_RC(ctx);
        
        if (event->error_code == -98) {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Address already in use");
        } else if (event->error_code == -99) {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Cannot assign requested address");
        } else {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Source address binding failed");
        }
        
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// Port allocation failure (offset 0x289)
int trace_port_alloc_fail(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        // Check if this is the failure path after inet_hash_connect
        int err = PT_REGS_PARM1(ctx);  // Error code in first param
        if (err != 0) {
            event->failure_type = FAIL_PORT_EXHAUSTED;
            event->error_code = err;
            
            if (err == -98) {
                bpf_probe_read_str(event->details, sizeof(event->details), 
                                  "All ephemeral ports exhausted");
            } else {
                bpf_probe_read_str(event->details, sizeof(event->details), 
                                  "Port allocation failed");
            }
            
            failure_events.perf_submit(ctx, event, sizeof(*event));
        }
    }
    return 0;
}

// TCP connect failure (offset 0x440)
int trace_tcp_connect_fail(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_CONNECT;
        event->error_code = PT_REGS_RC(ctx);
        
        if (event->error_code == -12) {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Out of memory - cannot allocate SKB");
        } else {
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "tcp_connect failed to send SYN");
        }
        
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// ENETUNREACH specific handling (offset 0x48d)
int trace_network_unreachable(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct failure_event *event = connect_tracking.lookup(&tid);
    
    if (event) {
        event->failure_type = FAIL_NETWORK_DOWN;
        event->error_code = -101; // ENETUNREACH
        bpf_probe_read_str(event->details, sizeof(event->details), 
                          "Network is unreachable - IPSTATS_MIB_OUTNOROUTES");
        failure_events.perf_submit(ctx, event, sizeof(*event));
    }
    return 0;
}

// Return probe - cleanup and catch any missed failures
int trace_connect_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    int retval = PT_REGS_RC(ctx);
    
    if (retval < 0) {
        struct failure_event *event = connect_tracking.lookup(&tid);
        if (event && event->failure_type == FAIL_NONE) {
            // Caught an untracked failure
            event->failure_type = FAIL_CONNECT;
            event->error_code = retval;
            bpf_probe_read_str(event->details, sizeof(event->details), 
                              "Unspecified connection failure");
            failure_events.perf_submit(ctx, event, sizeof(*event));
        }
    }
    
    connect_tracking.delete(&tid);
    return 0;
}
"""

# Failure type names
FAILURE_NAMES = {
    0: "NONE",
    1: "INVALID_ADDR",
    2: "ROUTE_LOOKUP",
    3: "MULTICAST",
    4: "SRC_BIND",
    5: "PORT_EXHAUSTED",
    6: "CONNECT",
    7: "MEMORY",
    8: "PERMISSION",
    9: "NETWORK_DOWN",
}

# Error code to name mapping
ERROR_NAMES = {
    -12: "ENOMEM",
    -13: "EACCES",
    -22: "EINVAL",
    -97: "EAFNOSUPPORT",
    -98: "EADDRINUSE",
    -99: "EADDRNOTAVAIL",
    -101: "ENETUNREACH",
    -105: "ENOBUFS",
    -110: "ETIMEDOUT",
    -111: "ECONNREFUSED",
}

# Failure tracking offsets
FAILURE_OFFSETS = {
    "trace_invalid_addrlen": 0x4f0,
    "trace_wrong_family": 0x4e6,
    "trace_route_failure": 0x46c,
    "trace_multicast_fail": 0x4fa,
    "trace_src_bind_fail": 0x417,
    "trace_port_alloc_fail": 0x289,
    "trace_tcp_connect_fail": 0x440,
    "trace_network_unreachable": 0x48d,
}

class ConnectionFailureAnalyzer:
    def __init__(self):
        self.b = BPF(text=bpf_text)
        self.failures_by_type = defaultdict(int)
        self.failures_by_error = defaultdict(int)
        self.failures_by_dest = defaultdict(lambda: defaultdict(int))
        self.failure_details = []
        self.start_time = time.time()
        
    def attach_probes(self):
        # Attach entry and return probes
        self.b.attach_kprobe(event=b"tcp_v4_connect", fn_name=b"trace_connect_start")
        self.b.attach_kretprobe(event=b"tcp_v4_connect", fn_name=b"trace_connect_return")
        
        # Attach failure detection probes
        print("Attaching failure detection probes...")
        for fn_name, offset in FAILURE_OFFSETS.items():
            try:
                self.b.attach_kprobe(
                    event=b"tcp_v4_connect",
                    fn_name=fn_name.encode(),
                    event_off=offset
                )
                print(f"  ✓ {fn_name:25s} at offset 0x{offset:04x}")
            except Exception as e:
                print(f"  ✗ {fn_name:25s} at offset 0x{offset:04x}: {e}")
        
        # Open perf buffer
        self.b["failure_events"].open_perf_buffer(self.handle_failure)
        
    def handle_failure(self, cpu, data, size):
        event = self.b["failure_events"].event(data)
        
        # Update statistics
        failure_name = FAILURE_NAMES.get(event.failure_type, f"UNKNOWN_{event.failure_type}")
        error_name = ERROR_NAMES.get(event.error_code, f"ERR_{event.error_code}")
        
        self.failures_by_type[failure_name] += 1
        self.failures_by_error[error_name] += 1
        
        # Track by destination
        if event.daddr:
            daddr = socket.inet_ntoa(struct.pack('I', event.daddr))
            self.failures_by_dest[daddr][failure_name] += 1
        
        # Store detailed record
        self.failure_details.append({
            'timestamp': event.ts_ns,
            'pid': event.pid,
            'comm': event.comm.decode('utf-8', 'ignore'),
            'type': failure_name,
            'error': error_name,
            'daddr': socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0",
            'dport': socket.ntohs(event.dport) if event.dport else 0,
            'details': event.details.decode('utf-8', 'ignore').rstrip('\x00')
        })
        
        # Print real-time failure
        elapsed = time.time() - self.start_time
        print(f"{elapsed:8.3f} [{event.pid:6d}] {event.comm.decode('utf-8', 'ignore'):16s} "
              f"FAIL: {failure_name:15s} {error_name:12s} "
              f"-> {self.failure_details[-1]['daddr']}:{self.failure_details[-1]['dport']:5d} "
              f"| {self.failure_details[-1]['details']}")
        
    def print_analysis(self):
        print("\n" + "="*100)
        print("TCP Connection Failure Analysis Report")
        print("="*100)
        
        runtime = time.time() - self.start_time
        total_failures = sum(self.failures_by_type.values())
        
        print(f"\nSummary: {total_failures} failures in {runtime:.1f} seconds")
        print(f"Failure rate: {total_failures/runtime:.2f} failures/sec")
        
        # Failure type distribution
        print("\n[Failure Type Distribution]")
        for fail_type, count in sorted(self.failures_by_type.items(), 
                                      key=lambda x: x[1], reverse=True):
            pct = (count / total_failures) * 100 if total_failures > 0 else 0
            print(f"  {fail_type:15s}: {count:6d} ({pct:5.1f}%)")
        
        # Error code distribution
        print("\n[Error Code Distribution]")
        for error, count in sorted(self.failures_by_error.items(), 
                                  key=lambda x: x[1], reverse=True):
            pct = (count / total_failures) * 100 if total_failures > 0 else 0
            print(f"  {error:15s}: {count:6d} ({pct:5.1f}%)")
        
        # Top failing destinations
        print("\n[Top 10 Failing Destinations]")
        dest_totals = [(dest, sum(failures.values())) 
                      for dest, failures in self.failures_by_dest.items()]
        for dest, total in sorted(dest_totals, key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {dest:20s}: {total:6d} failures")
            # Show failure breakdown for this destination
            for fail_type, count in self.failures_by_dest[dest].items():
                print(f"    └─ {fail_type:15s}: {count:4d}")
        
        # Recent failure examples
        print("\n[Recent Failure Examples]")
        for failure in self.failure_details[-5:]:
            print(f"  PID {failure['pid']:6d} ({failure['comm']:10s}): "
                  f"{failure['type']:15s} -> {failure['daddr']}:{failure['dport']} "
                  f"[{failure['details']}]")
        
        # Recommendations
        print("\n[Diagnostic Recommendations]")
        if self.failures_by_type.get('PORT_EXHAUSTED', 0) > 10:
            print("  ⚠ High port exhaustion rate - consider:")
            print("    - Increase ip_local_port_range: sysctl -w net.ipv4.ip_local_port_range='10000 65535'")
            print("    - Reduce TIME_WAIT: sysctl -w net.ipv4.tcp_tw_reuse=1")
        
        if self.failures_by_type.get('ROUTE_LOOKUP', 0) > 10:
            print("  ⚠ Routing issues detected - check:")
            print("    - Default gateway: ip route show default")
            print("    - Routing table: ip route list")
            print("    - Network interfaces: ip link show")
        
        if self.failures_by_type.get('SRC_BIND', 0) > 10:
            print("  ⚠ Source binding failures - verify:")
            print("    - Port conflicts: ss -tunap | grep LISTEN")
            print("    - IP address configuration: ip addr show")
        
    def run(self):
        print("="*100)
        print("TCP Connection Failure Analyzer")
        print("Tracking connection failures in tcp_v4_connect...")
        print("="*100)
        print("TIME(s)   PID     COMM             FAILURE         ERROR        DESTINATION          DETAILS")
        print("-"*100)
        
        try:
            while True:
                self.b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            self.print_analysis()

def main():
    analyzer = ConnectionFailureAnalyzer()
    analyzer.attach_probes()
    analyzer.run()

if __name__ == "__main__":
    main()