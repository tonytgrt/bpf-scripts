#!/usr/bin/env python3
"""
Critical path tracker for tcp_v4_connect
Focuses on performance-critical branches and error paths
"""

from bcc import BPF
import time
import socket
import struct
from collections import defaultdict

# BPF program
bpf_text = """
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

// Critical decision points in tcp_v4_connect
enum tcp_connect_path {
    PATH_ENTRY = 0,
    PATH_ROUTE_LOOKUP,      // Route lookup path
    PATH_ROUTE_CACHED,      // Using cached route
    PATH_SOURCE_BIND,       // Source address binding
    PATH_PORT_ALLOC,        // Port allocation
    PATH_FASTOPEN,          // Fast open path
    PATH_REGULAR_SYN,       // Regular SYN path
    PATH_ERROR,             // Error path taken
    PATH_SUCCESS,           // Success completion
};

struct path_event {
    u32 pid;
    u64 ts_ns;
    u64 latency_ns;         // For measuring path latency
    u8 path_type;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    int retval;
    char comm[16];
};

// Per-thread tracking for latency measurement
BPF_HASH(start_times, u32, u64);
BPF_PERF_OUTPUT(path_events);

// Track path counts for statistics
BPF_ARRAY(path_stats, u64, 16);

// Entry point - start timing
int trace_entry(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    
    start_times.update(&tid, &ts);
    
    struct path_event event = {};
    event.pid = tid;
    event.ts_ns = ts;
    event.path_type = PATH_ENTRY;
    
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    bpf_probe_read(&event.daddr, sizeof(event.daddr), &sin->sin_addr.s_addr);
    bpf_probe_read(&event.dport, sizeof(event.dport), &sin->sin_port);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    // Update stats
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Route lookup paths
// First route lookup (offset 0x17c - after ip_route_connect call)
int trace_route_lookup(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.path_type = PATH_ROUTE_LOOKUP;
    
    // Check if route lookup succeeded (rax contains result)
    void *rt = (void *)PT_REGS_RC(ctx);
    event.retval = IS_ERR(rt) ? PTR_ERR(rt) : 0;
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Source address binding path (offset 0x3fe)
int trace_source_bind(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.path_type = PATH_SOURCE_BIND;
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Port allocation via inet_hash_connect (offset 0x27e)
int trace_port_alloc(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.path_type = PATH_PORT_ALLOC;
    event.retval = PT_REGS_RC(ctx);  // Get return value
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Fast open path (offset 0x3af)
int trace_fastopen(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.path_type = PATH_FASTOPEN;
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Regular SYN sending via tcp_connect (offset 0x42d)
int trace_regular_syn(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.path_type = PATH_REGULAR_SYN;
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Error path - failure label (offset 0x289)
int trace_error_path(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.path_type = PATH_ERROR;
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}

// Return probe - capture final result and cleanup
int trace_return(struct pt_regs *ctx) {
    struct path_event event = {};
    u32 tid = bpf_get_current_pid_tgid();
    
    event.pid = tid;
    event.ts_ns = bpf_ktime_get_ns();
    event.retval = PT_REGS_RC(ctx);
    event.path_type = (event.retval == 0) ? PATH_SUCCESS : PATH_ERROR;
    
    u64 *start = start_times.lookup(&tid);
    if (start) {
        event.latency_ns = event.ts_ns - *start;
        start_times.delete(&tid);
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    path_events.perf_submit(ctx, &event, sizeof(event));
    
    u64 *count = path_stats.lookup_or_init(&event.path_type, &(u64){0});
    if (count) (*count)++;
    
    return 0;
}
"""

# Path names for display
PATH_NAMES = {
    0: "ENTRY",
    1: "ROUTE_LOOKUP",
    2: "ROUTE_CACHED",
    3: "SOURCE_BIND",
    4: "PORT_ALLOC",
    5: "FASTOPEN",
    6: "REGULAR_SYN",
    7: "ERROR",
    8: "SUCCESS"
}

# Critical offsets from disassembly
CRITICAL_OFFSETS = {
    "trace_route_lookup": 0x17c,     # After ip_route_connect
    "trace_source_bind": 0x3fe,      # inet_bhash2_update_saddr path
    "trace_port_alloc": 0x27e,       # After inet_hash_connect
    "trace_fastopen": 0x3af,         # tcp_fastopen_defer_connect check
    "trace_regular_syn": 0x42d,      # tcp_connect call
    "trace_error_path": 0x289,       # failure label
}

class ConnectPathTracker:
    def __init__(self):
        self.b = BPF(text=bpf_text)
        self.path_latencies = defaultdict(list)
        self.error_counts = defaultdict(int)
        self.start_time = time.time()
        
    def attach_probes(self):
        # Attach entry and return probes
        self.b.attach_kprobe(event=b"tcp_v4_connect", fn_name=b"trace_entry")
        self.b.attach_kretprobe(event=b"tcp_v4_connect", fn_name=b"trace_return")
        
        # Attach critical path probes
        attached = []
        failed = []
        
        for fn_name, offset in CRITICAL_OFFSETS.items():
            try:
                self.b.attach_kprobe(
                    event=b"tcp_v4_connect",
                    fn_name=fn_name.encode(),
                    event_off=offset
                )
                attached.append((fn_name, offset))
            except Exception as e:
                failed.append((fn_name, offset, str(e)))
        
        print(f"Successfully attached {len(attached)} probes:")
        for name, offset in attached:
            print(f"  ✓ {name:20s} at offset 0x{offset:04x}")
        
        if failed:
            print(f"\nFailed to attach {len(failed)} probes:")
            for name, offset, error in failed:
                print(f"  ✗ {name:20s} at offset 0x{offset:04x}: {error}")
        
        # Open perf buffer
        self.b["path_events"].open_perf_buffer(self.handle_event)
        
    def handle_event(self, cpu, data, size):
        event = self.b["path_events"].event(data)
        
        path_name = PATH_NAMES.get(event.path_type, f"UNKNOWN_{event.path_type}")
        
        # Store latency data
        if event.latency_ns > 0:
            self.path_latencies[path_name].append(event.latency_ns)
        
        # Track errors
        if event.retval != 0:
            self.error_counts[event.retval] += 1
        
        # Format output
        if event.daddr:
            daddr = socket.inet_ntoa(struct.pack('I', event.daddr))
            dport = socket.ntohs(event.dport)
        else:
            daddr = "0.0.0.0"
            dport = 0
        
        latency_str = f"{event.latency_ns/1000:.1f}μs" if event.latency_ns else "-"
        
        print(f"{time.time() - self.start_time:8.3f} [{event.pid:6d}] "
              f"{event.comm.decode('utf-8', 'ignore'):16s} "
              f"{path_name:15s} -> {daddr}:{dport:5d} "
              f"lat={latency_str:10s} ret={event.retval:4d}")
    
    def print_statistics(self):
        print("\n" + "="*80)
        print("TCP Connect Path Statistics")
        print("="*80)
        
        # Get path counts from BPF
        path_stats = self.b["path_stats"]
        print("\nPath Hit Counts:")
        for i in range(9):
            count = path_stats[i].value
            if count > 0:
                path_name = PATH_NAMES.get(i, f"UNKNOWN_{i}")
                print(f"  {path_name:15s}: {count:8d}")
        
        # Print latency statistics
        print("\nPath Latencies (μs):")
        for path, latencies in sorted(self.path_latencies.items()):
            if latencies:
                avg_lat = sum(latencies) / len(latencies) / 1000
                min_lat = min(latencies) / 1000
                max_lat = max(latencies) / 1000
                p99_lat = sorted(latencies)[int(len(latencies) * 0.99)] / 1000 if len(latencies) > 1 else max_lat
                
                print(f"  {path:15s}: avg={avg_lat:6.1f} min={min_lat:6.1f} "
                      f"max={max_lat:6.1f} p99={p99_lat:6.1f} (n={len(latencies)})")
        
        # Print error distribution
        if self.error_counts:
            print("\nError Distribution:")
            for error, count in sorted(self.error_counts.items()):
                error_name = {
                    -22: "EINVAL",
                    -97: "EAFNOSUPPORT",
                    -101: "ENETUNREACH",
                    -98: "EADDRINUSE",
                    -99: "EADDRNOTAVAIL",
                }.get(error, f"ERROR_{error}")
                print(f"  {error_name:15s}: {count:8d}")
    
    def run(self):
        print("Tracking critical paths in tcp_v4_connect...")
        print("TIME(s)   PID     COMM             PATH            DESTINATION         LATENCY    RET")
        print("-" * 90)
        
        try:
            while True:
                self.b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            self.print_statistics()

def main():
    tracker = ConnectPathTracker()
    tracker.attach_probes()
    tracker.run()

if __name__ == "__main__":
    main()