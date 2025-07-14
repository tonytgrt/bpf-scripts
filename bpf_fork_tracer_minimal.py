#!/usr/bin/env python3
"""
bpf_fork_tracer_minimal.py - Minimal fork tracer matching bpf_file_open_tracer.py structure
"""

from bcc import BPF

b = BPF(text="""
BPF_HASH(counter, u64, u64);

int count_calls(struct pt_regs *ctx) {
    u64 key = 0;
    u64 *val = counter.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        u64 init_val = 1;
        counter.update(&key, &init_val);
    }
    return 0;
}
""")

# Attach to fork system call
b.attach_kprobe(event="__x64_sys_fork", fn_name="count_calls")

# Also attach to clone which is used more often than fork
b.attach_kprobe(event="__x64_sys_clone", fn_name="count_calls")

print("Tracing process creation... Ctrl-C to end.")
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\nResults:")
    counter = b["counter"]
    for k, v in counter.items():
        print(f"Process creation syscalls: {v.value} times")