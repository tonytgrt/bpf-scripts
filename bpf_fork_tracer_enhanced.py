#!/usr/bin/env python3
"""
bpf_fork_tracer_enhanced.py - Enhanced process creation tracker with real-time events
Shows both counting and real-time process creation events
"""

from bcc import BPF
import signal
import sys
from datetime import datetime

# Enhanced BPF program with perf events
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Structure for perf event data
struct fork_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 ts;
    char comm[16];
    char parent_comm[16];
};

// Perf event for real-time tracking
BPF_PERF_OUTPUT(fork_events);

// Hash to count total forks
BPF_HASH(fork_count, u32, u64);

int trace_fork_return(struct pt_regs *ctx) {
    // Get return value (new PID)
    u32 ret = PT_REGS_RC(ctx);
    
    // ret == 0 means we're in the child process
    // ret > 0 means we're in the parent process and ret is the child PID
    // ret < 0 means error
    
    if (ret <= 0) {
        return 0;
    }
    
    struct fork_event event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Fill event data
    event.pid = ret;  // Child PID
    event.ppid = bpf_get_current_pid_tgid() >> 32;  // Parent PID
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    
    // Get parent command
    bpf_get_current_comm(&event.parent_comm, sizeof(event.parent_comm));
    
    // Note: We can't get child comm yet as it might not be set
    
    // Update total fork count
    u32 key = 0;
    u64 *count = fork_count.lookup(&key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        fork_count.update(&key, &init_val);
    }
    
    // Submit perf event
    fork_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Trace exec to get the actual command name of new processes
int trace_exec(struct pt_regs *ctx, 
    struct filename *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp) {
    
    struct fork_event event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    
    // Get new command name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get parent info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task;
    bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &task->real_parent);
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent_task->tgid);
    
    // Mark this as an exec event by setting parent_comm to "EXEC"
    __builtin_memcpy(&event.parent_comm, "EXEC", 5);
    
    fork_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

class ForkTracer:
    def __init__(self):
        self.start_time = datetime.now()
        self.total_forks = 0
        self.exec_pids = set()
        
    def handle_fork_event(self, cpu, data, size):
        event = self.b["fork_events"].event(data)
        
        # Check if this is an exec event
        if event.parent_comm.decode('utf-8', 'replace').startswith('EXEC'):
            self.exec_pids.add(event.pid)
            print(f"{datetime.now().strftime('%H:%M:%S')} "
                  f"EXEC  PID={event.pid:<7} "
                  f"UID={event.uid:<6} "
                  f"CMD={event.comm.decode('utf-8', 'replace'):<16}")
        else:
            self.total_forks += 1
            print(f"{datetime.now().strftime('%H:%M:%S')} "
                  f"FORK  PID={event.pid:<7} "
                  f"PPID={event.ppid:<7} "
                  f"UID={event.uid:<6} "
                  f"PARENT={event.parent_comm.decode('utf-8', 'replace'):<16}")
    
    def run(self):
        # Compile BPF program
        self.b = BPF(text=bpf_text)
        
        # Attach to fork/clone return probes (to get child PID)
        syscalls_to_trace = [
            "__x64_sys_fork",
            "__x64_sys_vfork", 
            "__x64_sys_clone",
            "__x64_sys_clone3"
        ]
        
        attached = 0
        for syscall in syscalls_to_trace:
            try:
                self.b.attach_kretprobe(event=syscall, fn_name="trace_fork_return")
                print(f"Attached to {syscall}")
                attached += 1
            except:
                pass
        
        # Also trace exec to get actual command names
        try:
            self.b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_exec")
            print("Attached to execve")
        except:
            print("Warning: Could not attach to execve")
        
        if attached == 0:
            print("Error: Could not attach to any fork syscalls")
            sys.exit(1)
        
        # Open perf buffer
        self.b["fork_events"].open_perf_buffer(self.handle_fork_event)
        
        print(f"\nTracing process creation... Press Ctrl-C to stop.\n")
        print("Time     Event PID      PPID     UID    Command/Parent")
        print("-" * 70)
        
        # Main loop
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            self.print_summary()
    
    def print_summary(self):
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        
        # Get total from BPF counter
        fork_count = self.b["fork_count"]
        try:
            bpf_total = fork_count[0].value
        except:
            bpf_total = 0
        
        runtime = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\nTotal process creations: {bpf_total}")
        print(f"Exec calls tracked: {len(self.exec_pids)}")
        print(f"Runtime: {runtime:.1f} seconds")
        if runtime > 0:
            print(f"Fork rate: {bpf_total/runtime:.2f} forks/second")

def main():
    tracer = ForkTracer()
    tracer.run()

if __name__ == "__main__":
    main()