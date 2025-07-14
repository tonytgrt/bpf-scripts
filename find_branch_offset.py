#!/usr/bin/env python3
"""
find_branch_offset.py - Find offsets for tracing specific branches in kernel functions
Analyzes disassembly to locate conditional branches and their target offsets
"""

import subprocess
import re
import sys
import argparse
from pathlib import Path

class KernelFunctionAnalyzer:
    def __init__(self, function_name):
        self.function_name = function_name
        self.function_address = None
        self.disassembly = []
        self.branches = []
        self.calls = []
        
    def get_function_address(self):
        """Get function address from kallsyms"""
        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2] == self.function_name:
                        self.function_address = int(parts[0], 16)
                        return True
        except Exception as e:
            print(f"Error reading kallsyms: {e}")
        return False
    
    def get_kernel_image(self):
        """Find the kernel image file"""
        import glob
        
        uname = subprocess.check_output(['uname', '-r']).decode().strip()
        paths = [
            f"/boot/vmlinux-{uname}",
            "/boot/vmlinux",
            f"/usr/lib/debug/boot/vmlinux-{uname}",
            f"/usr/lib/debug/lib/modules/{uname}/vmlinux",
            "/sys/kernel/btf/vmlinux",  # BTF info location
        ]
        
        for path in paths:
            if Path(path).exists():
                return path
        
        # Try to extract from vmlinuz
        vmlinuz = f"/boot/vmlinuz-{uname}"
        if Path(vmlinuz).exists():
            print(f"Found compressed kernel at {vmlinuz}, trying to extract...")
            
            # Find extract-vmlinux script
            extract_scripts = glob.glob("/usr/src/linux-headers-*/scripts/extract-vmlinux")
            if not extract_scripts:
                extract_scripts = glob.glob("/usr/lib/linux-*/scripts/extract-vmlinux")
            
            if extract_scripts:
                extract_script = extract_scripts[0]
                extract_path = "/tmp/vmlinux"
                
                try:
                    # Make script executable
                    subprocess.run(['chmod', '+x', extract_script], check=True)
                    # Extract vmlinux
                    result = subprocess.run([extract_script, vmlinuz], 
                                          capture_output=True)
                    if result.returncode == 0 and result.stdout:
                        # Write extracted kernel
                        with open(extract_path, 'wb') as f:
                            f.write(result.stdout)
                        if Path(extract_path).exists() and Path(extract_path).stat().st_size > 0:
                            print(f"Successfully extracted vmlinux to {extract_path}")
                            return extract_path
                except Exception as e:
                    print(f"Failed to extract: {e}")
        
        return None
    
    def disassemble_function(self):
        """Disassemble the function"""
        kernel_image = self.get_kernel_image()
        
        if not kernel_image:
            print("Could not find kernel image. Using /proc/kcore fallback...")
            return self.disassemble_from_kcore()
        
        try:
            # Use objdump to get function disassembly
            cmd = ['objdump', '-d', '--no-show-raw-insn', 
                   f'--start-address=0x{self.function_address:x}',
                   kernel_image]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return self.disassemble_from_kcore()
            
            return self.parse_objdump_output(result.stdout)
            
        except Exception as e:
            print(f"Error with objdump: {e}")
            return self.disassemble_from_kcore()
    
    def disassemble_from_kcore(self):
        """Fallback: disassemble from /proc/kcore using gdb"""
        try:
            cmd = ['gdb', '-batch',
                   '-ex', f'x/200i 0x{self.function_address:x}',
                   '/proc/kcore']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return self.parse_gdb_output(result.stdout)
            
        except Exception as e:
            print(f"Error with gdb: {e}")
            return False
    
    def parse_objdump_output(self, output):
        """Parse objdump output"""
        lines = output.split('\n')
        in_function = False
        current_offset = 0
        
        for line in lines:
            if self.function_name in line and '<' in line and '>' in line:
                in_function = True
                continue
                
            if in_function:
                # Match instruction lines
                match = re.match(r'\s*([0-9a-f]+):\s+(.+)', line)
                if match:
                    addr = int(match.group(1), 16)
                    instruction = match.group(2).strip()
                    offset = addr - self.function_address
                    
                    self.disassembly.append({
                        'offset': offset,
                        'address': addr,
                        'instruction': instruction,
                        'raw_line': line
                    })
                    
                    # Stop at next function
                    if offset > 0x1000:  # Reasonable function size limit
                        break
        
        return len(self.disassembly) > 0
    
    def parse_gdb_output(self, output):
        """Parse gdb output"""
        lines = output.split('\n')
        
        for line in lines:
            # Match GDB format: 0xaddr <func+offset>: instruction
            match = re.match(r'0x([0-9a-f]+)\s+<[^>]+\+(\d+)>:\s+(.+)', line)
            if match:
                addr = int(match.group(1), 16)
                offset = int(match.group(2))
                instruction = match.group(3).strip()
                
                self.disassembly.append({
                    'offset': offset,
                    'address': addr,
                    'instruction': instruction,
                    'raw_line': line
                })
        
        return len(self.disassembly) > 0
    
    def analyze_branches(self):
        """Find all conditional branches and their targets"""
        for i, inst in enumerate(self.disassembly):
            instr = inst['instruction']
            
            # Identify conditional jumps
            if any(instr.startswith(jmp) for jmp in ['je ', 'jne ', 'jz ', 'jnz ', 
                                                      'jl ', 'jle ', 'jg ', 'jge ',
                                                      'ja ', 'jae ', 'jb ', 'jbe ',
                                                      'js ', 'jns ', 'test ']):
                
                # Extract jump target
                target_match = re.search(r'(0x[0-9a-f]+)', instr)
                if target_match:
                    target_addr = int(target_match.group(1), 16)
                    target_offset = target_addr - self.function_address
                    
                    # Find the test/cmp instruction before the jump
                    test_inst = None
                    for j in range(max(0, i-3), i):
                        if 'test' in self.disassembly[j]['instruction'] or \
                           'cmp' in self.disassembly[j]['instruction']:
                            test_inst = self.disassembly[j]
                            break
                    
                    self.branches.append({
                        'offset': inst['offset'],
                        'instruction': instr,
                        'target_offset': target_offset,
                        'test_instruction': test_inst,
                        'index': i
                    })
            
            # Identify function calls
            elif instr.startswith('call'):
                call_target = re.search(r'<([^>]+)>', instr)
                if call_target:
                    self.calls.append({
                        'offset': inst['offset'],
                        'function': call_target.group(1),
                        'index': i
                    })
    
    def find_call_after_branch(self, branch_offset, function_name):
        """Find a specific function call after a branch"""
        # Find instructions after the branch target
        for inst in self.disassembly:
            if inst['offset'] >= branch_offset:
                if function_name in inst['instruction']:
                    return inst['offset']
        return None
    
    def find_branch_for_flag(self, flag_name):
        """Find branches that test specific flags"""
        results = []
        
        # Common patterns for flag testing
        flag_patterns = {
            'FAULT_FLAG_USER': [r'test.*\$0x10', r'and.*\$0x10'],  # bit 4
            'FAULT_FLAG_WRITE': [r'test.*\$0x1', r'and.*\$0x1'],   # bit 0
            'VM_FAULT_OOM': [r'test.*\$0x.*', r'and.*\$0x.*'],     # various
        }
        
        patterns = flag_patterns.get(flag_name, [f'.*{flag_name}.*'])
        
        for i, inst in enumerate(self.disassembly):
            for pattern in patterns:
                if re.search(pattern, inst['instruction']):
                    # Look for conditional jump after this test
                    for j in range(i+1, min(i+5, len(self.disassembly))):
                        next_inst = self.disassembly[j]
                        if any(next_inst['instruction'].startswith(jmp) 
                               for jmp in ['je', 'jne', 'jz', 'jnz']):
                            results.append({
                                'test_offset': inst['offset'],
                                'test_instruction': inst['instruction'],
                                'jump_offset': next_inst['offset'],
                                'jump_instruction': next_inst['instruction'],
                                'branch_taken_offset': self.get_jump_target(next_inst)
                            })
                            break
        
        return results
    
    def get_jump_target(self, jump_inst):
        """Extract jump target offset from instruction"""
        match = re.search(r'(0x[0-9a-f]+)', jump_inst['instruction'])
        if match:
            target_addr = int(match.group(1), 16)
            return target_addr - self.function_address
        return None
    
    def print_analysis(self):
        """Print analysis results"""
        print(f"\nAnalysis of {self.function_name}")
        print("=" * 80)
        print(f"Function address: 0x{self.function_address:x}")
        print(f"Instructions analyzed: {len(self.disassembly)}")
        
        print(f"\nConditional Branches Found: {len(self.branches)}")
        print("-" * 80)
        
        for branch in self.branches[:10]:  # Show first 10
            print(f"Offset 0x{branch['offset']:x}: {branch['instruction']}")
            if branch['test_instruction']:
                print(f"  Test: {branch['test_instruction']['instruction']}")
            print(f"  Target: offset 0x{branch['target_offset']:x}")
            print()
        
        print(f"\nFunction Calls Found: {len(self.calls)}")
        print("-" * 80)
        
        for call in self.calls[:10]:  # Show first 10
            print(f"Offset 0x{call['offset']:x}: call {call['function']}")
    
    def find_specific_branch(self, search_pattern):
        """Find branches related to specific code patterns"""
        print(f"\nSearching for branches related to: {search_pattern}")
        print("-" * 80)
        
        results = []
        
        # Search for function calls matching pattern
        for call in self.calls:
            if search_pattern.lower() in call['function'].lower():
                # Find the branch that leads to this call
                for branch in self.branches:
                    if branch['target_offset'] <= call['offset'] < branch['target_offset'] + 50:
                        results.append({
                            'branch': branch,
                            'call': call,
                            'probe_offset': call['offset']
                        })
        
        return results

def find_mem_cgroup_branch_offset():
    """Find the specific offset for mem_cgroup_exit_user_fault branch"""
    print("\nFinding offset for: if (flags & FAULT_FLAG_USER) { mem_cgroup_exit_user_fault(); }")
    print("=" * 80)
    
    analyzer = KernelFunctionAnalyzer('handle_mm_fault')
    
    if not analyzer.get_function_address():
        print("Could not find handle_mm_fault")
        return
    
    print(f"Found handle_mm_fault at 0x{analyzer.function_address:x}")
    
    if not analyzer.disassemble_function():
        print("Could not disassemble function")
        return
    
    analyzer.analyze_branches()
    
    # Find FAULT_FLAG_USER test (bit 4, value 0x10)
    print("\nLooking for FAULT_FLAG_USER test (flags & 0x10)...")
    
    for i, inst in enumerate(analyzer.disassembly):
        # Look for test of bit 4 (0x10)
        if 'test' in inst['instruction'] and '$0x10' in inst['instruction']:
            print(f"\nFound flag test at offset 0x{inst['offset']:x}:")
            print(f"  {inst['instruction']}")
            
            # Find the conditional jump after test
            for j in range(i+1, min(i+5, len(analyzer.disassembly))):
                next_inst = analyzer.disassembly[j]
                if next_inst['instruction'].startswith('je') or \
                   next_inst['instruction'].startswith('jz'):
                    print(f"  {next_inst['instruction']}")
                    
                    # Get branch target
                    target = analyzer.get_jump_target(next_inst)
                    if target:
                        print(f"\nBranch taken goes to offset: 0x{target:x}")
                        
                        # Look for mem_cgroup_exit_user_fault call
                        for k in range(len(analyzer.disassembly)):
                            check_inst = analyzer.disassembly[k]
                            if check_inst['offset'] >= target and \
                               'mem_cgroup_exit_user_fault' in check_inst['instruction']:
                                print(f"\nFound mem_cgroup_exit_user_fault at offset 0x{check_inst['offset']:x}")
                                print(f"\n>>> ATTACH PROBE AT OFFSET: 0x{target:x}")
                                print(f">>> This is the first instruction inside the if block")
                                
                                # Show surrounding context
                                print("\nContext:")
                                start_idx = max(0, k-5)
                                end_idx = min(len(analyzer.disassembly), k+5)
                                for ctx_idx in range(start_idx, end_idx):
                                    ctx_inst = analyzer.disassembly[ctx_idx]
                                    marker = ">>>" if ctx_idx == k else "   "
                                    print(f"{marker} 0x{ctx_inst['offset']:03x}: {ctx_inst['instruction']}")
                                
                                return target
    
    print("\nCould not find the specific branch")
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Find branch offsets in kernel functions for conditional tracing'
    )
    parser.add_argument('function', nargs='?', default='handle_mm_fault',
                       help='Kernel function to analyze')
    parser.add_argument('--pattern', help='Search for branches related to this pattern')
    parser.add_argument('--flag', help='Find branches testing this flag')
    parser.add_argument('--call', help='Find branches leading to this function call')
    parser.add_argument('--mem-cgroup', action='store_true',
                       help='Find mem_cgroup_exit_user_fault branch specifically')
    
    args = parser.parse_args()
    
    if args.mem_cgroup:
        offset = find_mem_cgroup_branch_offset()
        if offset:
            print(f"\n\nBPF code to trace this branch:")
            print("-" * 60)
            print(f"""
from bcc import BPF

b = BPF(text='''
int trace_mem_cgroup_branch(struct pt_regs *ctx) {{
    bpf_trace_printk("mem_cgroup_exit_user_fault branch taken\\n");
    return 0;
}}
''')

b.attach_kprobe(event="handle_mm_fault", 
                fn_name="trace_mem_cgroup_branch",
                event_off=0x{offset:x})

print("Tracing mem_cgroup branch in handle_mm_fault...")
""")
        return
    
    # General analysis
    analyzer = KernelFunctionAnalyzer(args.function)
    
    if not analyzer.get_function_address():
        print(f"Could not find function: {args.function}")
        return
    
    if not analyzer.disassemble_function():
        print("Could not disassemble function")
        return
    
    analyzer.analyze_branches()
    
    if args.pattern:
        results = analyzer.find_specific_branch(args.pattern)
        for r in results:
            print(f"\nBranch at 0x{r['branch']['offset']:x} leads to {r['call']['function']}")
            print(f"Attach probe at: 0x{r['probe_offset']:x}")
    
    elif args.flag:
        results = analyzer.find_branch_for_flag(args.flag)
        for r in results:
            print(f"\nFlag test at 0x{r['test_offset']:x}: {r['test_instruction']}")
            print(f"Jump at 0x{r['jump_offset']:x}: {r['jump_instruction']}")
            if r['branch_taken_offset']:
                print(f"Branch taken goes to: 0x{r['branch_taken_offset']:x}")
    
    elif args.call:
        # Find specific call
        for call in analyzer.calls:
            if args.call in call['function']:
                print(f"\nFound {call['function']} at offset 0x{call['offset']:x}")
                print(f"Attach probe at: 0x{call['offset']:x}")
    
    else:
        analyzer.print_analysis()

if __name__ == "__main__":
    main()