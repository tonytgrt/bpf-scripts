#!/usr/bin/env python3
"""
fork_stress_test.py - Stress test companion for bpf_fork_tracer_enhanced.py
Generates high volumes of process creation events with various patterns
"""

import os
import sys
import time
import subprocess
import random
import argparse
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

def fork_burst(count=100, delay=0):
    """Create a burst of forks"""
    print(f"Fork burst: {count} processes...")
    start = time.time()
    
    for i in range(count):
        pid = os.fork()
        if pid == 0:
            # Child - exit immediately
            os._exit(0)
        else:
            # Parent - collect zombies periodically
            if i % 10 == 0:
                while True:
                    try:
                        os.waitpid(-1, os.WNOHANG)
                    except:
                        break
            if delay > 0:
                time.sleep(delay)
    
    # Final cleanup
    while True:
        try:
            os.waitpid(-1, 0)
        except:
            break
    
    elapsed = time.time() - start
    print(f"  Created {count} processes in {elapsed:.2f}s ({count/elapsed:.1f} forks/sec)")

def random_commands(duration=5):
    """Execute random commands for specified duration"""
    commands = [
        ["true"],
        ["false"],
        ["echo", "test"],
        ["printf", "hello"],
        ["cat", "/dev/null"],
        ["touch", "/tmp/test_$$"],
        ["rm", "-f", "/tmp/test_$$"],
        ["basename", "/usr/bin/test"],
        ["dirname", "/usr/bin/test"],
        ["date", "+%s"],
        ["sleep", "0.01"],
        ["env", "TEST=1", "true"],
        ["nice", "true"],
        ["timeout", "1", "true"]
    ]
    
    print(f"Random command execution for {duration} seconds...")
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        cmd = random.choice(commands)
        try:
            subprocess.run(cmd, capture_output=True, timeout=0.5)
            count += 1
        except:
            pass
    
    print(f"  Executed {count} commands in {duration}s ({count/duration:.1f} commands/sec)")

def parallel_workers(num_workers=10, iterations=50):
    """Use process pool to create many workers"""
    print(f"Parallel workers: {num_workers} workers, {iterations} tasks each...")
    
    def worker_task(n):
        # Each task creates a subprocess
        result = subprocess.run(["echo", f"Worker task {n}"], 
                              capture_output=True, text=True)
        return n
    
    start = time.time()
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        # Submit all tasks
        futures = []
        for i in range(num_workers * iterations):
            future = executor.submit(worker_task, i)
            futures.append(future)
        
        # Wait for completion
        completed = 0
        for future in futures:
            future.result()
            completed += 1
    
    elapsed = time.time() - start
    total_processes = num_workers + (num_workers * iterations)
    print(f"  Created ~{total_processes} processes in {elapsed:.2f}s")

def fork_chain(length=10):
    """Create a chain of processes, each forking the next"""
    print(f"Fork chain: {length} processes in sequence...")
    
    def create_chain(remaining):
        if remaining <= 0:
            return
        
        pid = os.fork()
        if pid == 0:
            # Child continues the chain
            create_chain(remaining - 1)
            time.sleep(0.01)
            os._exit(0)
        else:
            # Parent waits
            os.waitpid(pid, 0)
    
    start = time.time()
    create_chain(length)
    elapsed = time.time() - start
    print(f"  Chain of {length} processes completed in {elapsed:.2f}s")

def mixed_workload(duration=10):
    """Mix of different process creation patterns"""
    print(f"Mixed workload for {duration} seconds...")
    
    start = time.time()
    counts = {"forks": 0, "subprocesses": 0, "chains": 0}
    
    while time.time() - start < duration:
        choice = random.randint(0, 2)
        
        if choice == 0:
            # Quick fork
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            else:
                os.waitpid(pid, 0)
                counts["forks"] += 1
        
        elif choice == 1:
            # Subprocess
            subprocess.run(["true"], capture_output=True)
            counts["subprocesses"] += 1
        
        else:
            # Mini chain
            for i in range(3):
                pid = os.fork()
                if pid == 0:
                    if i < 2:
                        continue
                    os._exit(0)
                else:
                    os.waitpid(pid, 0)
                    break
            counts["chains"] += 1
        
        # Small random delay
        time.sleep(random.uniform(0, 0.01))
    
    print(f"  Completed: {counts}")

def benchmark_mode():
    """Run a comprehensive benchmark"""
    print("\n" + "="*60)
    print("FORK TRACER BENCHMARK MODE")
    print("="*60)
    
    tests = [
        ("Sequential Fork Test", lambda: fork_burst(1000, 0)),
        ("Subprocess Test", lambda: random_commands(5)),
        ("Parallel Process Pool", lambda: parallel_workers(20, 100)),
        ("Deep Fork Chain", lambda: fork_chain(50)),
        ("Mixed Workload", lambda: mixed_workload(10))
    ]
    
    total_start = time.time()
    
    for name, test_func in tests:
        print(f"\n{name}")
        print("-" * 40)
        test_func()
        time.sleep(1)  # Brief pause between tests
    
    total_elapsed = time.time() - total_start
    print(f"\nTotal benchmark time: {total_elapsed:.2f} seconds")

def main():
    parser = argparse.ArgumentParser(
        description='Stress test for BPF fork tracer - generates high volumes of process events'
    )
    parser.add_argument('--mode', choices=['burst', 'random', 'parallel', 'chain', 'mixed', 'benchmark'],
                       default='benchmark', help='Test mode to run')
    parser.add_argument('--duration', type=int, default=10,
                       help='Duration for timed tests (seconds)')
    parser.add_argument('--count', type=int, default=1000,
                       help='Number of processes for count-based tests')
    parser.add_argument('--workers', type=int, default=10,
                       help='Number of parallel workers')
    parser.add_argument('--continuous', action='store_true',
                       help='Run continuously until interrupted')
    
    args = parser.parse_args()
    
    print("Fork Stress Test - High Volume Process Creation")
    print("Run bpf_fork_tracer_enhanced.py to monitor these events")
    print("Press Ctrl-C to stop\n")
    
    time.sleep(2)
    
    try:
        while True:
            if args.mode == 'burst':
                fork_burst(args.count, 0)
            elif args.mode == 'random':
                random_commands(args.duration)
            elif args.mode == 'parallel':
                parallel_workers(args.workers, args.count // args.workers)
            elif args.mode == 'chain':
                fork_chain(args.count)
            elif args.mode == 'mixed':
                mixed_workload(args.duration)
            elif args.mode == 'benchmark':
                benchmark_mode()
            
            if not args.continuous:
                break
            
            print("\nWaiting 2 seconds before next iteration...\n")
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\nStopped by user")

if __name__ == "__main__":
    main()