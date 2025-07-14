#!/usr/bin/env python3
"""
bpf_fork_tracer.py - Track process creation events using eBPF
Similar structure to bpf_file_open_tracer.py but tracks fork/clone syscalls
"""

from bcc import BPF
import signal
import sys
from datetime import datetime

# BPF program that tracks process creation
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Structure to store process creation data
struct proc_data {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
};

// Hash to count total forks
BPF_HASH(fork_count, u32, u64);

// Hash to count forks per process name
BPF_HASH(comm_count, char[16], u64);

// Hash to track parent-child relationships
BPF_HASH(parent_child, u32, struct proc_data);

int trace_fork(struct pt_regs *ctx) {
    // Get current process info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct proc_data data = {};
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    data.pid = pid;
    data.uid = uid;
    
    // Get parent PID
    struct task_struct *parent_task;
    bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &task->real_parent);
    bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &parent_task->tgid);
    
    // Get command name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Update total fork count
    u32 key = 0;
    u64 *count = fork_count.lookup(&key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        fork_count.update(&key, &init_val);
    }
    
    // Update per-command count
    u64 *comm_cnt = comm_count.lookup(&data.comm);
    if (comm_cnt) {
        (*comm_cnt)++;
    } else {
        u64 init_val = 1;
        comm_count.update(&data.comm, &init_val);
    }
    
    // Store parent-child relationship
    parent_child.update(&pid, &data);
    
    return 0;
}
"""

def signal_handler(sig, frame):
    print("\n\nStopping fork tracer...")
    sys.exit(0)

def main():
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Compile BPF program
    b = BPF(text=bpf_text)
    
    # Attach to fork-related syscalls
    # Note: Different kernels might use different syscall names
    syscalls_to_trace = [
        "__x64_sys_fork",
        "__x64_sys_vfork", 
        "__x64_sys_clone",
        "__x64_sys_clone3"
    ]
    
    attached = 0
    for syscall in syscalls_to_trace:
        try:
            b.attach_kprobe(event=syscall, fn_name="trace_fork")
            print(f"Attached to {syscall}")
            attached += 1
        except:
            # Some syscalls might not exist on all systems
            pass
    
    if attached == 0:
        print("Error: Could not attach to any fork syscalls")
        sys.exit(1)
    
    print(f"\nTracing process creation... Press Ctrl-C to stop.\n")
    print("Timestamp            Total Forks")
    print("-" * 35)
    
    # Main loop - print stats every second
    last_count = 0
    try:
        while True:
            # Get total fork count
            fork_count = b["fork_count"]
            key = 0
            try:
                total = fork_count[key].value
                if total != last_count:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"{timestamp}  {total:>10}")
                    last_count = total
            except KeyError:
                pass
            
            # Sleep for a bit to reduce CPU usage
            b.kprobe_poll(timeout=1000)
            
    except KeyboardInterrupt:
        pass
    
    # Print final statistics
    print("\n" + "="*50)
    print("FINAL STATISTICS")
    print("="*50)
    
    # Total forks
    fork_count = b["fork_count"]
    try:
        total = fork_count[0].value
        print(f"\nTotal process creations: {total}")
    except:
        print("\nNo process creations detected")
    
    # Per-command statistics
    print("\nProcess creations by command:")
    print("-" * 35)
    print(f"{'Command':<20} {'Count':>10}")
    print("-" * 35)
    
    comm_count = b["comm_count"]
    sorted_comms = []
    
    for k, v in comm_count.items():
        comm = k.value.decode('utf-8', 'replace')
        count = v.value
        sorted_comms.append((comm, count))
    
    # Sort by count (descending)
    sorted_comms.sort(key=lambda x: x[1], reverse=True)
    
    for comm, count in sorted_comms[:20]:  # Top 20
        print(f"{comm:<20} {count:>10}")
    
    if len(sorted_comms) > 20:
        print(f"\n... and {len(sorted_comms) - 20} more commands")

if __name__ == "__main__":
    main()