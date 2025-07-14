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

b.attach_kprobe(event="dummy_test", fn_name="count_calls")

print("Tracing... Ctrl-C to end.")
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\nResults:")
    counter = b["counter"]
    for k, v in counter.items():
        print(f"Function called {v.value} times")