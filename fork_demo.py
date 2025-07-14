#!/usr/bin/env python3
"""
fork_demo.py - Visual demonstration of fork() behavior
Creates a process tree and displays it visually
"""

import os
import sys
import time
import json
from pathlib import Path

# Shared file for process tree data
TREE_FILE = "/tmp/fork_demo_tree.json"

def write_node(pid, ppid, level, name):
    """Write process info to shared file"""
    node = {
        'pid': pid,
        'ppid': ppid,
        'level': level,
        'name': name,
        'time': time.time()
    }
    
    # Append to file (with file locking)
    for i in range(5):  # Retry a few times
        try:
            with open(TREE_FILE, 'a') as f:
                json.dump(node, f)
                f.write('\n')
            break
        except:
            time.sleep(0.01)

def create_process_tree():
    """Create a demonstration process tree"""
    
    # Initialize tree file
    with open(TREE_FILE, 'w') as f:
        f.write("")  # Clear file
    
    # Write root process
    root_pid = os.getpid()
    write_node(root_pid, 0, 0, "root")
    
    print(f"Creating process tree demonstration...")
    print(f"Root PID: {root_pid}\n")
    
    # Level 1: Create 3 children
    for i in range(3):
        pid = os.fork()
        
        if pid == 0:
            # Child process
            my_pid = os.getpid()
            write_node(my_pid, root_pid, 1, f"child_{i+1}")
            
            # Level 2: Each child creates 2 grandchildren
            for j in range(2):
                pid2 = os.fork()
                
                if pid2 == 0:
                    # Grandchild process
                    my_pid2 = os.getpid()
                    write_node(my_pid2, my_pid, 2, f"grandchild_{i+1}_{j+1}")
                    
                    # Level 3: Some grandchildren create great-grandchildren
                    if j == 0:  # Only first grandchild
                        pid3 = os.fork()
                        
                        if pid3 == 0:
                            # Great-grandchild
                            my_pid3 = os.getpid()
                            write_node(my_pid3, my_pid2, 3, f"ggchild_{i+1}")
                            time.sleep(0.5)
                            sys.exit(0)
                        else:
                            os.waitpid(pid3, 0)
                    
                    time.sleep(0.3)
                    sys.exit(0)
                else:
                    # Grandchild created
                    pass
            
            # Wait for grandchildren
            for j in range(2):
                os.wait()
            
            time.sleep(0.2)
            sys.exit(0)
        else:
            # Parent: continue to create more children
            pass
    
    # Root process waits for all children
    print("Waiting for all processes to complete...")
    for i in range(3):
        pid, status = os.wait()
        print(f"Child {pid} completed")
    
    # Display the tree
    time.sleep(0.5)  # Ensure all writes complete
    display_tree()

def display_tree():
    """Read and display the process tree"""
    
    print("\n" + "="*60)
    print("PROCESS TREE VISUALIZATION")
    print("="*60 + "\n")
    
    # Read all nodes
    nodes = []
    try:
        with open(TREE_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    nodes.append(json.loads(line))
    except:
        print("Error reading tree data")
        return
    
    # Sort by timestamp
    nodes.sort(key=lambda x: x['time'])
    
    # Create tree structure
    tree = {}
    for node in nodes:
        tree[node['pid']] = node
    
    # Display tree recursively
    def print_node(pid, prefix="", is_last=True):
        if pid not in tree:
            return
        
        node = tree[pid]
        
        # Print current node
        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}PID {node['pid']} ({node['name']})")
        
        # Find children
        children = [n for n in nodes if n['ppid'] == pid]
        
        # Print children
        extension = "    " if is_last else "│   "
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            print_node(child['pid'], prefix + extension, is_last_child)
    
    # Find root (ppid = 0)
    roots = [n for n in nodes if n['ppid'] == 0]
    for root in roots:
        print_node(root['pid'])
    
    # Summary
    print(f"\nTotal processes created: {len(nodes)}")
    max_level = max(n['level'] for n in nodes)
    print(f"Maximum tree depth: {max_level + 1} levels")
    
    # Level distribution
    print("\nProcesses per level:")
    for level in range(max_level + 1):
        count = sum(1 for n in nodes if n['level'] == level)
        print(f"  Level {level}: {count} processes")

def simple_fork_demo():
    """Simple fork demonstration with output"""
    
    print("SIMPLE FORK DEMONSTRATION")
    print("="*40)
    
    print(f"Parent process starting (PID: {os.getpid()})")
    
    pid = os.fork()
    
    if pid == 0:
        # Child process
        print(f"  Child process running (PID: {os.getpid()})")
        print(f"  Child: My parent is PID {os.getppid()}")
        time.sleep(1)
        print(f"  Child process exiting")
        sys.exit(0)
    else:
        # Parent process
        print(f"Parent: Created child with PID {pid}")
        print(f"Parent: Waiting for child to complete...")
        os.waitpid(pid, 0)
        print(f"Parent: Child has completed")
    
    print("\nFork demonstration complete!")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Visual demonstration of process forking'
    )
    parser.add_argument('--mode', choices=['simple', 'tree'], 
                       default='tree',
                       help='Demonstration mode')
    
    args = parser.parse_args()
    
    if args.mode == 'simple':
        simple_fork_demo()
    else:
        create_process_tree()
    
    # Cleanup
    try:
        os.unlink(TREE_FILE)
    except:
        pass

if __name__ == "__main__":
    main()