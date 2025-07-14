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

c = BPF(text="""
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

offset = 0x5db

b.attach_kprobe(event="tcp_v4_rcv", fn_name="count_calls")
c.attach_kprobe(event="tcp_v4_rcv", fn_name="count_calls", event_off=offset)

print("Tracing... Ctrl-C to end.")
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\nResults:")
    counter = b["counter"]
    for k, v in counter.items():
        print(f"Function called {v.value} times")
    counter = c["counter"]
    for k, v in counter.items():
        print(f"Function called {v.value} times with offset {offset:#x}")