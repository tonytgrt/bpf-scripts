#!/usr/bin/env python3
"""
analyze_function_offset.py - Analyze function disassembly to understand kprobe offsets
Shows what instruction is at a specific offset in a kernel function
"""

import subprocess
import sys
import re
import argparse

def get_function_address(func_name):
    """Get function address from /proc/kallsyms"""
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == func_name:
                    return int(parts[0], 16)
    except:
        print("Error reading /proc/kallsyms (need root?)")
    return None

def get_function_disassembly(func_name):
    """Get disassembly of a kernel function using objdump"""
    # First, find the kernel image
    kernel_paths = [
        "/boot/vmlinux",
        f"/boot/vmlinux-{subprocess.check_output(['uname', '-r']).decode().strip()}",
        "/proc/kcore"  # Live kernel memory
    ]
    
    kernel_path = None
    for path in kernel_paths:
        try:
            if subprocess.run(['file', path], capture_output=True).returncode == 0:
                kernel_path = path
                break
        except:
            continue
    
    if not kernel_path:
        print("Could not find kernel image")
        return None
    
    # Get function address
    func_addr = get_function_address(func_name)
    if not func_addr:
        print(f"Could not find address for {func_name}")
        return None
    
    print(f"Function {func_name} at address: 0x{func_addr:x}")
    
    # Disassemble using objdump
    try:
        # For /proc/kcore, we need different approach
        if kernel_path == "/proc/kcore":
            cmd = ['gdb', '-batch',
                   '-ex', f'x/40i 0x{func_addr:x}',
                   kernel_path]
        else:
            cmd = ['objdump', '-d', '--start-address', f'0x{func_addr:x}',
                   '--stop-address', f'0x{func_addr + 200:x}', kernel_path]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error disassembling: {e}")
        return None

def analyze_offset(disasm, offset):
    """Analyze what instruction is at a specific offset"""
    if not disasm:
        return
    
    print(f"\nAnalyzing offset 0x{offset:x}:")
    print("-" * 60)
    
    # Parse disassembly output
    instructions = []
    current_offset = 0
    
    for line in disasm.split('\n'):
        # Match instruction lines (various formats)
        # Format 1: address: bytes instruction
        match = re.match(r'\s*[0-9a-f]+:\s+([0-9a-f ]+)\s+(\S+.*)', line)
        if not match:
            # Format 2: gdb format
            match = re.match(r'0x[0-9a-f]+\s+<[^>]+\+(\d+)>:\s+(.+)', line)
            if match:
                inst_offset = int(match.group(1))
                instruction = match.group(2)
                instructions.append((inst_offset, instruction))
        else:
            hex_bytes = match.group(1).strip()
            instruction = match.group(2)
            byte_count = len(hex_bytes.split())
            instructions.append((current_offset, f"{hex_bytes:<20} {instruction}"))
            current_offset += byte_count
    
    # Find instruction at offset
    found = False
    for i, (inst_offset, inst) in enumerate(instructions[:20]):  # First 20 instructions
        marker = ">>> " if inst_offset == offset else "    "
        print(f"{marker}+0x{inst_offset:02x}: {inst}")
        
        if inst_offset == offset:
            found = True
            print(f"\nAt offset 0x{offset:x}:")
            print(f"  Instruction: {inst}")
            print(f"  This is instruction #{i} in the function")
            
            # Analyze the instruction
            if 'push' in inst or 'mov' in inst and '%rsp' in inst:
                print("  Type: Stack frame setup")
            elif 'call' in inst:
                print("  Type: Function call")
            elif 'test' in inst or 'cmp' in inst:
                print("  Type: Comparison")
            elif 'je' in inst or 'jne' in inst or 'jmp' in inst:
                print("  Type: Branch/Jump")
            elif 'ret' in inst:
                print("  Type: Return")
    
    if not found and instructions:
        print(f"\nOffset 0x{offset:x} is beyond the instructions shown")
        print(f"Last instruction was at offset 0x{instructions[-1][0]:x}")

def show_common_patterns():
    """Show common function prologue patterns"""
    print("\nCommon x86_64 Function Prologue Patterns:")
    print("-" * 60)
    print("Offset  Typical Instruction     Purpose")
    print("-" * 60)
    print("0x00    push %rbp              Save old base pointer")
    print("0x01    mov %rsp,%rbp          Set up new base pointer")
    print("0x04    push %rbx              Save callee-saved registers")
    print("0x05    sub $0xNN,%rsp         Allocate stack space")
    print("\nNote: Actual offsets depend on compiler and optimization level")

def create_offset_bpf_program(func_name, offset):
    """Create a BPF program that traces at a specific offset"""
    return f"""
from bcc import BPF

# BPF program that traces at offset 0x{offset:x} in {func_name}
bpf_text = '''
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

struct data_t {{
    u64 timestamp;
    u32 pid;
    u64 instruction_pointer;
}};

int trace_at_offset(struct pt_regs *ctx) {{
    struct data_t data = {{}};
    
    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.instruction_pointer = PT_REGS_IP(ctx);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}}
'''

b = BPF(text=bpf_text)

# Attach at specific offset
b.attach_kprobe(event="{func_name}", fn_name="trace_at_offset", event_off=0x{offset:x})

print("Tracing {func_name}+0x{offset:x}... Press Ctrl-C to stop")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID {{event.pid}} hit {func_name}+0x{offset:x} at {{event.timestamp}}")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
"""

def main():
    parser = argparse.ArgumentParser(
        description='Analyze kernel function offsets for kprobe attachment'
    )
    parser.add_argument('function', help='Kernel function name')
    parser.add_argument('--offset', type=lambda x: int(x, 0), default=0x4,
                       help='Offset to analyze (default: 0x4)')
    parser.add_argument('--show-bpf', action='store_true',
                       help='Show example BPF program for this offset')
    
    args = parser.parse_args()
    
    print(f"Analyzing function: {args.function}")
    print("=" * 60)
    
    # Get and analyze disassembly
    disasm = get_function_disassembly(args.function)
    if disasm:
        analyze_offset(disasm, args.offset)
    else:
        print("\nCould not get disassembly. Trying alternative method...")
        show_common_patterns()
    
    if args.show_bpf:
        print("\n\nExample BPF Program:")
        print("=" * 60)
        print(create_offset_bpf_program(args.function, args.offset))

if __name__ == "__main__":
    main()