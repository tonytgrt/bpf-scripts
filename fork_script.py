#!/usr/bin/env python3
"""
fork_script.py - Comprehensive test script for bpf_fork_tracer_enhanced.py
Tests all fork tracking capabilities including fork, clone, exec, and process hierarchies
"""

import os
import sys
import time
import subprocess
import multiprocessing
import threading
import signal
import argparse
from pathlib import Path

# Global flag for clean shutdown
running = True

def signal_handler(sig, frame):
    global running
    running = False
    print("\nStopping fork test script...")
    sys.exit(0)

def simple_fork_test(count=5, delay=0.1):
    """Test basic fork() system call"""
    print(f"\n1. Testing fork() - Creating {count} processes using os.fork()")
    
    for i in range(count):
        pid = os.fork()
        if pid == 0:
            # Child process
            time.sleep(0.01)  # Brief pause to ensure tracking
            os._exit(0)  # Exit immediately
        else:
            # Parent process
            os.waitpid(pid, 0)  # Wait for child to complete
            print(f"   Created child PID: {pid}")
            time.sleep(delay)

def subprocess_test(commands=None, count=3):
    """Test subprocess creation (uses clone internally)"""
    if commands is None:
        commands = [
            ["echo", "Hello from subprocess"],
            ["date"],
            ["sleep", "0.1"],
            ["pwd"],
            ["hostname"]
        ]
    
    print(f"\n2. Testing subprocess (clone) - Running {len(commands)} different commands")
    
    for i in range(count):
        for cmd in commands:
            try:
                # This will trigger clone() and execve()
                result = subprocess.run(cmd, capture_output=True, text=True)
                print(f"   Executed: {' '.join(cmd)}")
                time.sleep(0.05)
            except Exception as e:
                print(f"   Error running {cmd}: {e}")

def exec_test():
    """Test execve() by replacing current process image"""
    print("\n3. Testing execve() - Process replacement")
    
    # Fork first, then exec in child
    for i in range(3):
        pid = os.fork()
        if pid == 0:
            # Child process - replace ourselves with different commands
            commands = [
                ["/bin/ls", "-la", "/dev/null"],
                ["/bin/cat", "/proc/version"],
                ["/usr/bin/env"]
            ]
            try:
                cmd = commands[i % len(commands)]
                print(f"   Child {os.getpid()} executing: {' '.join(cmd)}")
                os.execv(cmd[0], cmd)
            except Exception as e:
                print(f"   Exec failed: {e}")
                os._exit(1)
        else:
            # Parent - wait for child
            os.waitpid(pid, 0)
            time.sleep(0.1)

def multiprocessing_test(num_processes=4):
    """Test multiprocessing module (uses clone with specific flags)"""
    print(f"\n4. Testing multiprocessing - Creating {num_processes} worker processes")
    
    def worker(name, duration):
        """Simple worker function"""
        print(f"   Worker {name} (PID: {os.getpid()}) started")
        time.sleep(duration)
        # Create a grandchild to test PPID tracking
        if name == "Worker-1":
            subprocess.run(["echo", f"Grandchild of {name}"], capture_output=True)
    
    processes = []
    for i in range(num_processes):
        p = multiprocessing.Process(target=worker, args=(f"Worker-{i}", 0.2))
        p.start()
        processes.append(p)
        time.sleep(0.05)
    
    # Wait for all processes
    for p in processes:
        p.join()

def thread_exec_test(num_threads=3):
    """Test threading with subprocess calls (threads share PID but subprocesses don't)"""
    print(f"\n5. Testing threads with subprocess - {num_threads} threads creating processes")
    
    def thread_worker(thread_id):
        """Thread that creates subprocesses"""
        for i in range(2):
            cmd = ["echo", f"Thread-{thread_id} iteration-{i}"]
            subprocess.run(cmd, capture_output=True)
            time.sleep(0.1)
    
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=thread_worker, args=(i,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

def fork_bomb_test(levels=3, children_per_level=2):
    """Create a process tree to test parent-child tracking"""
    print(f"\n6. Testing process tree - {levels} levels, {children_per_level} children per level")
    
    def create_tree(level, max_level):
        if level >= max_level:
            return
        
        for i in range(children_per_level):
            pid = os.fork()
            if pid == 0:
                # Child process
                time.sleep(0.05)
                # Create next level
                create_tree(level + 1, max_level)
                os._exit(0)
            else:
                # Parent - don't wait, let them run concurrently
                pass
        
        # Parent waits for all children at this level
        for i in range(children_per_level):
            try:
                os.wait()
            except:
                pass
    
    create_tree(0, levels)

def rapid_fork_test(duration=2, delay=0.001):
    """Create forks rapidly to test high-frequency tracking"""
    print(f"\n7. Testing rapid forking - Running for {duration} seconds")
    
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        pid = os.fork()
        if pid == 0:
            # Child - exit immediately
            os._exit(0)
        else:
            # Parent
            os.waitpid(pid, 0)
            count += 1
            if delay > 0:
                time.sleep(delay)
    
    print(f"   Created {count} processes in {duration} seconds ({count/duration:.1f} forks/sec)")

def shell_command_test():
    """Test shell command execution which involves multiple forks/execs"""
    print("\n8. Testing shell command execution (sh -c)")
    
    commands = [
        "ls | grep py | wc -l",
        "echo 'Hello' && echo 'World'",
        "for i in 1 2 3; do echo $i; done",
        "(sleep 0.1 && echo 'Background') &"
    ]
    
    for cmd in commands:
        print(f"   Executing: {cmd}")
        subprocess.run(["sh", "-c", cmd], capture_output=True)
        time.sleep(0.1)

def python_script_test():
    """Test Python script execution (python interpreter fork/exec)"""
    print("\n9. Testing Python script execution")
    
    # Create a temporary Python script
    script_content = """
import os
import subprocess

print(f"Python script PID: {os.getpid()}")
subprocess.run(["echo", "Called from Python script"])
"""
    
    script_path = Path("/tmp/test_fork_script.py")
    script_path.write_text(script_content)
    
    try:
        # Execute Python script - this will fork and exec python
        result = subprocess.run([sys.executable, str(script_path)], 
                              capture_output=True, text=True)
        print(f"   Executed Python script: {result.stdout.strip()}")
    finally:
        script_path.unlink()  # Clean up

def daemon_process_test():
    """Test daemon-style process creation (double fork)"""
    print("\n10. Testing daemon-style process (double fork)")
    
    # First fork
    pid = os.fork()
    if pid == 0:
        # First child
        # Create new session
        os.setsid()
        
        # Second fork
        pid = os.fork()
        if pid == 0:
            # Second child (daemon)
            print(f"   Daemon process created: PID={os.getpid()}")
            time.sleep(0.5)  # Simulate some work
            os._exit(0)
        else:
            # First child exits
            os._exit(0)
    else:
        # Original parent waits for first child
        os.waitpid(pid, 0)
        time.sleep(0.1)

def main():
    parser = argparse.ArgumentParser(
        description='Generate various fork/clone/exec events for BPF fork tracer testing'
    )
    parser.add_argument('--continuous', action='store_true',
                       help='Run tests continuously until interrupted')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between test iterations (default: 1.0 seconds)')
    parser.add_argument('--quick', action='store_true',
                       help='Run a quick subset of tests')
    
    args = parser.parse_args()
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    print("="*70)
    print("BPF Fork Tracer Test Script")
    print("="*70)
    print("This script will generate various process creation events.")
    print("Run bpf_fork_tracer_enhanced.py in another terminal to observe the events.")
    print("\nPress Ctrl-C to stop.\n")
    
    time.sleep(2)  # Give user time to start the tracer
    
    iteration = 0
    while running:
        iteration += 1
        if args.continuous:
            print(f"\n{'='*50}")
            print(f"ITERATION {iteration}")
            print('='*50)
        
        # Run tests
        if args.quick:
            # Quick subset of tests
            simple_fork_test(count=3)
            subprocess_test(count=1)
            multiprocessing_test(num_processes=2)
        else:
            # Full test suite
            simple_fork_test()
            subprocess_test()
            exec_test()
            multiprocessing_test()
            thread_exec_test()
            fork_bomb_test()
            rapid_fork_test(duration=1)
            shell_command_test()
            python_script_test()
            daemon_process_test()
        
        if not args.continuous:
            break
        
        print(f"\nWaiting {args.delay} seconds before next iteration...")
        time.sleep(args.delay)
    
    print("\n" + "="*70)
    print("Test completed!")
    print("Check the BPF fork tracer output for results.")
    print("="*70)

if __name__ == "__main__":
    main()