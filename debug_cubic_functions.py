#!/usr/bin/env python3
"""
debug_cubic_functions.py - Debug which CUBIC functions are available for tracing
"""

import subprocess
import sys
import os

def check_kallsyms():
    """Check /proc/kallsyms for CUBIC functions"""
    print("=== Checking /proc/kallsyms for CUBIC functions ===\n")
    
    try:
        with open('/proc/kallsyms', 'r') as f:
            cubic_funcs = []
            for line in f:
                if 'cubic' in line.lower() or 'bictcp' in line.lower():
                    cubic_funcs.append(line.strip())
            
            if cubic_funcs:
                print(f"Found {len(cubic_funcs)} CUBIC-related symbols:")
                for func in cubic_funcs:
                    print(f"  {func}")
            else:
                print("No CUBIC functions found in kallsyms")
    except Exception as e:
        print(f"Error reading kallsyms: {e}")
    
    print()

def check_available_filter_functions():
    """Check available_filter_functions for traceable CUBIC functions"""
    print("=== Checking available_filter_functions ===\n")
    
    path = '/sys/kernel/debug/tracing/available_filter_functions'
    try:
        with open(path, 'r') as f:
            cubic_funcs = []
            tcp_funcs = []
            for line in f:
                if 'cubic' in line.lower():
                    cubic_funcs.append(line.strip())
                elif 'tcp_cong' in line.lower() or 'bictcp' in line.lower():
                    tcp_funcs.append(line.strip())
            
            if cubic_funcs:
                print(f"Found {len(cubic_funcs)} traceable CUBIC functions:")
                for func in cubic_funcs:
                    print(f"  {func}")
            else:
                print("No directly traceable CUBIC functions found")
            
            if tcp_funcs:
                print(f"\nFound {len(tcp_funcs)} related TCP congestion control functions:")
                for func in tcp_funcs[:10]:  # Show first 10
                    print(f"  {func}")
                if len(tcp_funcs) > 10:
                    print(f"  ... and {len(tcp_funcs) - 10} more")
    except Exception as e:
        print(f"Error reading available_filter_functions: {e}")
        print("You may need to run as root or mount debugfs")
    
    print()

def check_loaded_modules():
    """Check if tcp_cubic is a module"""
    print("=== Checking loaded modules ===\n")
    
    try:
        result = subprocess.run(['lsmod'], capture_output=True, text=True)
        if 'tcp_cubic' in result.stdout:
            print("tcp_cubic is loaded as a module")
            # Get more info
            subprocess.run(['modinfo', 'tcp_cubic'])
        else:
            print("tcp_cubic is not a loadable module (likely built into kernel)")
    except Exception as e:
        print(f"Error checking modules: {e}")
    
    print()

def check_tcp_congestion_control():
    """Check current TCP congestion control settings"""
    print("=== TCP Congestion Control Settings ===\n")
    
    try:
        with open('/proc/sys/net/ipv4/tcp_congestion_control', 'r') as f:
            current = f.read().strip()
            print(f"Current congestion control: {current}")
        
        with open('/proc/sys/net/ipv4/tcp_available_congestion_control', 'r') as f:
            available = f.read().strip()
            print(f"Available algorithms: {available}")
        
        with open('/proc/sys/net/ipv4/tcp_allowed_congestion_control', 'r') as f:
            allowed = f.read().strip()
            print(f"Allowed algorithms: {allowed}")
    except Exception as e:
        print(f"Error reading TCP settings: {e}")
    
    print()

def suggest_alternative_probes():
    """Suggest alternative probe points"""
    print("=== Alternative Probe Points ===\n")
    
    print("Since cubictcp_cong_avoid might not be directly traceable, try these alternatives:")
    print()
    print("1. Generic TCP congestion control hooks:")
    print("   - tcp_cong_avoid_ai (called by CUBIC)")
    print("   - tcp_slow_start (called during slow start)")
    print("   - tcp_ack (processes all ACKs)")
    print("   - tcp_rcv_established (main TCP receive path)")
    print()
    print("2. Struct ops approach (if available):")
    print("   - Trace tcp_congestion_ops->cong_avoid calls")
    print()
    print("3. Use kretprobe on functions that call cong_avoid:")
    print("   - tcp_ack_update_rtt")
    print("   - tcp_cong_control")
    print()

def test_simple_probe():
    """Test a simple BPF probe to verify BPF is working"""
    print("=== Testing Simple BPF Probe ===\n")
    
    from bcc import BPF
    
    # Try to attach to tcp_slow_start which should always exist
    test_prog = """
    int test_probe(struct pt_regs *ctx) {
        bpf_trace_printk("TCP slow start called\\n");
        return 0;
    }
    """
    
    try:
        b = BPF(text=test_prog)
        b.attach_kprobe(event="tcp_slow_start", fn_name="test_probe")
        print("✓ Successfully attached to tcp_slow_start")
        print("  BPF is working correctly")
        b.cleanup()
    except Exception as e:
        print(f"✗ Failed to attach simple probe: {e}")
        print("  There may be a BPF/kernel issue")
    
    print()

def check_struct_ops():
    """Check if we can access struct ops for CUBIC"""
    print("=== Checking BTF and Struct Ops Support ===\n")
    
    try:
        # Check for BTF support
        if os.path.exists('/sys/kernel/btf/vmlinux'):
            print("✓ BTF is available")
            
            # Try to find tcp_congestion_ops in BTF
            result = subprocess.run(['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
                                  capture_output=True, text=True)
            if 'tcp_congestion_ops' in result.stdout:
                print("✓ tcp_congestion_ops found in BTF")
                print("  You can use fentry/fexit probes or struct_ops programs")
            else:
                print("✗ tcp_congestion_ops not found in BTF")
        else:
            print("✗ BTF not available")
            print("  fentry/fexit probes won't work")
    except FileNotFoundError:
        print("✗ bpftool not found, can't check BTF details")
    except Exception as e:
        print(f"Error checking BTF: {e}")
    
    print()

def main():
    print("=" * 60)
    print("CUBIC Function Debugging Tool")
    print("=" * 60)
    print()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Not running as root. Some checks may fail.\n")
    
    # Run all checks
    check_tcp_congestion_control()
    check_kallsyms()
    check_available_filter_functions()
    check_loaded_modules()
    check_struct_ops()
    test_simple_probe()
    suggest_alternative_probes()
    
    print("=" * 60)
    print("Debugging complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()