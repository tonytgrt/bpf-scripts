"""
File opener script to trigger BPF hooks for testing kernel-level file open tracking.
This script opens files repeatedly to generate syscalls that your BPF program can monitor.
"""

import os
import time
import tempfile
import argparse
import random
import string
from pathlib import Path

def generate_random_filename(length=10):
    """Generate a random filename"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def create_temp_files(count=10, temp_dir=None):
    """Create temporary files for testing"""
    if temp_dir is None:
        temp_dir = tempfile.gettempdir()
    
    temp_files = []
    for i in range(count):
        filename = os.path.join(temp_dir, f"bpf_test_{generate_random_filename()}.txt")
        with open(filename, 'w') as f:
            f.write(f"Test file {i}\nGenerated for BPF testing\n")
        temp_files.append(filename)
    
    return temp_files

def open_files_repeatedly(files, iterations=100, delay=0.01):
    """Open files repeatedly to trigger syscalls"""
    print(f"Opening {len(files)} files {iterations} times each...")
    print(f"Total expected syscalls: {len(files) * iterations}")
    
    for iteration in range(iterations):
        for file_path in files:
            try:
                # Open and immediately close the file
                with open(file_path, 'r') as f:
                    # Optionally read a bit to ensure the file is actually accessed
                    f.read(1)
                
                # Small delay to make the syscalls more observable
                if delay > 0:
                    time.sleep(delay)
                    
            except Exception as e:
                print(f"Error opening {file_path}: {e}")
        
        # Progress indicator
        if (iteration + 1) % 10 == 0:
            print(f"Completed {iteration + 1}/{iterations} iterations")

def open_various_system_files(count=50):
    """Open various system files that are commonly available"""
    system_files = [
        '/proc/version',
        '/proc/cpuinfo',
        '/proc/meminfo',
        '/proc/uptime',
        '/proc/loadavg',
        '/etc/hostname',
        '/etc/os-release',
        '/sys/class/net/lo/operstate',
        '/proc/self/stat',
        '/proc/self/status'
    ]
    
    # Filter to only existing files
    available_files = [f for f in system_files if os.path.exists(f)]
    
    print(f"Opening {len(available_files)} system files {count} times each...")
    
    for i in range(count):
        for file_path in available_files:
            try:
                with open(file_path, 'r') as f:
                    f.read(10)  # Read a small amount
                time.sleep(0.005)  # Very small delay
            except Exception as e:
                print(f"Error opening {file_path}: {e}")
        
        if (i + 1) % 10 == 0:
            print(f"Completed {i + 1}/{count} system file iterations")

def cleanup_temp_files(files):
    """Clean up temporary files"""
    print(f"Cleaning up {len(files)} temporary files...")
    for file_path in files:
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Generate file open syscalls for BPF testing')
    parser.add_argument('--temp-files', type=int, default=5, 
                       help='Number of temporary files to create (default: 5)')
    parser.add_argument('--iterations', type=int, default=50,
                       help='Number of times to open each file (default: 50)')
    parser.add_argument('--delay', type=float, default=0.01,
                       help='Delay between file opens in seconds (default: 0.01)')
    parser.add_argument('--system-files', action='store_true',
                       help='Also open system files like /proc/version')
    parser.add_argument('--system-iterations', type=int, default=20,
                       help='Number of iterations for system files (default: 20)')
    parser.add_argument('--no-cleanup', action='store_true',
                       help='Don\'t clean up temporary files after testing')
    
    args = parser.parse_args()
    
    print("=== BPF File Open Generator ===")
    print("This script will generate file open syscalls for your BPF program to monitor.")
    print("Make sure your BPF program is running before starting this script.\n")
    
    temp_files = []
    
    try:
        # Create and open temporary files
        if args.temp_files > 0:
            print("1. Creating temporary files...")
            temp_files = create_temp_files(args.temp_files)
            print(f"Created {len(temp_files)} temporary files")
            
            print("\n2. Opening temporary files repeatedly...")
            open_files_repeatedly(temp_files, args.iterations, args.delay)
        
        # Open system files if requested
        if args.system_files:
            print("\n3. Opening system files...")
            open_various_system_files(args.system_iterations)
        
        print(f"\n=== Complete! ===")
        expected_total = len(temp_files) * args.iterations
        if args.system_files:
            # Rough estimate for system files
            expected_total += args.system_iterations * 10  # Approximate number of available system files
        
        print(f"Expected total file opens: ~{expected_total}")
        print("Check your BPF program output for the actual count.")
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    
    finally:
        # Cleanup temporary files
        if temp_files and not args.no_cleanup:
            print("\n4. Cleaning up...")
            cleanup_temp_files(temp_files)
        elif temp_files and args.no_cleanup:
            print(f"\nTemporary files left in place:")
            for f in temp_files:
                print(f"  {f}")

if __name__ == "__main__":
    main()