#!/usr/bin/env python3
"""
offset_finder.py - Simple and reliable offset finder for kernel branches
"""

import subprocess
import re

def find_offset():
    # Run gdb to get disassembly
    cmd = ['sudo', 'gdb', '-batch', '-ex', 'disas handle_mm_fault', '/proc/kcore']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error: Could not run gdb. Make sure to run with sudo.")
            return None
            
        lines = result.stdout.split('\n')
        
        print("Searching for FAULT_FLAG_USER test pattern...")
        print("-" * 60)
        
        # Find test $0x10 pattern
        for i, line in enumerate(lines):
            if 'test' in line and '$0x10' in line:
                print(f"\nFound test instruction:")
                print(f"  {line.strip()}")
                
                # Look for jump after test
                for j in range(i+1, min(i+5, len(lines))):
                    if j < len(lines) and ('je' in lines[j] or 'jz' in lines[j]):
                        print(f"  {lines[j].strip()}")
                        
                        # Get next instruction (branch start)
                        if j+1 < len(lines):
                            next_line = lines[j+1].strip()
                            print(f"  {next_line} <-- BRANCH STARTS HERE")
                            
                            # Extract offset
                            match = re.search(r'<handle_mm_fault\+(\d+)>', next_line)
                            if match:
                                offset = int(match.group(1))
                                print(f"\n✓ Branch offset: 0x{offset:x}")
                                
                                # Verify by looking ahead
                                print("\nVerifying (looking for mem_cgroup calls)...")
                                for k in range(j+1, min(j+30, len(lines))):
                                    if 'mem_cgroup' in lines[k]:
                                        print(f"  ✓ Found: {lines[k].strip()}")
                                
                                return offset
                        break
        
        print("\nCould not find pattern. Showing relevant lines:")
        for line in lines:
            if any(x in line for x in ['test', '$0x10', 'mem_cgroup', 'je ', 'jz ']):
                print(line.strip())
                
    except Exception as e:
        print(f"Error: {e}")
    
    return None

if __name__ == "__main__":
    print("Finding mem_cgroup_exit_user_fault branch offset")
    print("=" * 60)
    
    offset = find_offset()
    
    if offset:
        print(f"\n" + "=" * 60)
        print(f"SUCCESS! Use this offset: 0x{offset:x}")
        print(f"\nExample usage:")
        print(f"""
b.attach_kprobe(event="handle_mm_fault",
                fn_name="trace_mem_cgroup_branch", 
                event_off=0x{offset:x})
""")
    else:
        print("\nCould not find offset automatically.")
        print("\nTry running this command manually:")
        print("sudo gdb -batch -ex 'disas handle_mm_fault' /proc/kcore | grep -B2 -A5 'test.*0x10'")