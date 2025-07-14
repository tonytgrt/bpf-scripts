#!/usr/bin/env python3

import sys
import subprocess
import re

def find_function_assembly(binary_file, function_name):
    """
    Finds and prints the assembly code for a specific function from a binary file.

    This function executes 'objdump -d' and parses its output to isolate the
    assembly code block belonging to the specified function.

    Args:
        binary_file (str): The path to the executable binary file.
        function_name (str): The name of the function to search for.
    """
    # Command to disassemble the binary file
    objdump_cmd = ["objdump", "-d", binary_file]

    try:
        # Run the objdump command, capturing its standard output
        result = subprocess.run(
            objdump_cmd,
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        print("Error: 'objdump' command not found. Is binutils installed and in your PATH? 😥", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        # This catches errors from objdump itself (e.g., file is not a valid object file)
        print(f"Error running objdump: {e.stderr}", file=sys.stderr)
        sys.exit(1)

    # Regex to match the start of any function label, e.g., "0000000000401136 <hello>:"
    function_label_regex = re.compile(r"^[0-9a-f]+\s<.*>:$")
    
    # The specific label for our target function
    target_label = f"<{function_name}>:"

    in_target_function = False
    for line in result.stdout.splitlines():
        # Check if the current line looks like a function label
        if function_label_regex.match(line):
            # If we were already inside our target function, this new label
            # signifies the start of the next function, so we can stop.
            if in_target_function:
                break
            
            # Check if this label is the one we're looking for
            if target_label in line:
                in_target_function = True

        # If we are in the target function, print the current line
        if in_target_function:
            print(line)

# --- Main execution block ---
if __name__ == "__main__":
    # Ensure correct number of command-line arguments are provided
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <binary_file> <function_name>")
        print(f"Example: python3 {sys.argv[0]} ./my_binary hello")
        sys.exit(1)

    binary = sys.argv[1]
    func_name = sys.argv[2]
    
    find_function_assembly(binary, func_name)