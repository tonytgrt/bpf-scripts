#!/bin/bash
# alternative_disasm.sh - Alternative ways to disassemble when gdb fails

echo "Alternative Methods to Disassemble handle_mm_fault"
echo "================================================="

# Get address
ADDR=$(sudo grep " handle_mm_fault$" /proc/kallsyms | awk '{print $1}')
echo "handle_mm_fault address: 0x$ADDR"

echo -e "\n1. Using eu-objdump (if available):"
if command -v eu-objdump &> /dev/null; then
    sudo eu-objdump -d --start=0x$ADDR --stop=$((0x$ADDR+0x100)) /proc/kcore 2>/dev/null | head -50
else
    echo "   eu-objdump not found (install with: sudo apt install elfutils)"
fi

echo -e "\n2. Using llvm-objdump (if available):"
if command -v llvm-objdump &> /dev/null; then
    sudo llvm-objdump -d --start-address=0x$ADDR --stop-address=$((0x$ADDR+0x100)) /proc/kcore 2>/dev/null | head -50
else
    echo "   llvm-objdump not found (install with: sudo apt install llvm)"
fi

echo -e "\n3. Using radare2 (if available):"
if command -v r2 &> /dev/null; then
    echo "pD 100 @ 0x$ADDR" | sudo r2 -q /proc/kcore 2>/dev/null | grep -A10 -B10 "test.*0x10"
else
    echo "   radare2 not found (install with: sudo apt install radare2)"
fi

echo -e "\n4. Using capstone disassembler (Python):"
cat << 'EOF' > /tmp/disasm.py
#!/usr/bin/env python3
import sys
try:
    from capstone import *
    
    # Read address from command line
    addr = int(sys.argv[1], 16)
    
    # Read bytes from /proc/kcore
    with open('/proc/kcore', 'rb') as f:
        f.seek(addr)
        code = f.read(256)
    
    # Disassemble
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, addr):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        if 'test' in i.mnemonic and '0x10' in i.op_str:
            print("    ^^^ Found FAULT_FLAG_USER test!")
            
except ImportError:
    print("capstone not installed (pip install capstone)")
except Exception as e:
    print(f"Error: {e}")
EOF

if python3 -c "import capstone" 2>/dev/null; then
    sudo python3 /tmp/disasm.py 0x$ADDR 2>/dev/null | head -50
else
    echo "   capstone not installed (install with: pip install capstone)"
fi

echo -e "\n5. Direct byte reading and pattern matching:"
echo "Looking for 'test \$0x10' instruction pattern (bytes: f6 ?? 10 or f7 ?? 10 00 00 00)..."
sudo hexdump -C -s 0x$ADDR -n 256 /proc/kcore | grep -E "f6 .. 10|f7 .. 10 00 00 00"

echo -e "\n6. Using the crash utility (most reliable if available):"
if command -v crash &> /dev/null; then
    echo "dis handle_mm_fault 100" | sudo crash -s /proc/kcore 2>/dev/null | grep -A5 -B5 "test.*0x10"
else
    echo "   crash not installed (install with: sudo apt install crash)"
    echo "   This is often the most reliable method!"
fi