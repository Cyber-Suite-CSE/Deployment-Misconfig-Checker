import subprocess
import re
import os
import sys
import shutil
import threading
import time
from typing import Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from colorama import init, Fore, Style

init(autoreset=True)


class SlidingWindowDisplay:
    def __init__(self, max_lines=10):
        self.max_lines = max_lines
        self.lines = []
        self.terminal_width = shutil.get_terminal_size((80, 24)).columns
        self.is_initialized = False
        
    def initialize_display(self):
        if not self.is_initialized:
            print("\n" * self.max_lines)
            self.is_initialized = True
    
    def add_line(self, line):
        line = line.rstrip()
        if not line:
            return
            
        if len(line) > self.terminal_width - 4:
            line = line[:self.terminal_width - 7] + "..."
            
        self.lines.append(line)
        if len(self.lines) > self.max_lines:
            self.lines.pop(0)
        self.update_display()
    
    def update_display(self):
        if not self.is_initialized:
            return
            
        sys.stdout.write(f"\033[{self.max_lines}A")
        sys.stdout.write("\033[J")
        
        for line in self.lines:
            if line.strip():
                print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
        
        for _ in range(self.max_lines - len(self.lines)):
            print("")
        
        sys.stdout.flush()
    
    def finalize(self, full_output):
        if not self.is_initialized:
            return
            
        sys.stdout.write(f"\033[{self.max_lines}A")
        sys.stdout.write("\033[J")
        print()


def stream_output_with_sliding_window(process, max_window_lines=10):
    display = SlidingWindowDisplay(max_lines=max_window_lines)
    display.initialize_display()
    
    full_output = []
    full_stderr = []
    
    def read_stream(stream, is_stderr=False):
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                    
                line = line.rstrip()
                
                if is_stderr:
                    full_stderr.append(line)
                else:
                    full_output.append(line)
                
                display.add_line(line)
        except Exception as e:
            display.add_line(f"Error reading stream: {str(e)}")
    
    stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, False))
    stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, True))
    
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    
    stdout_thread.start()
    stderr_thread.start()
    
    process.wait()
    
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    
    full_output_str = "\n".join(full_output)
    full_stderr_str = "\n".join(full_stderr)
    
    display.finalize(full_output_str)
    
    return full_output_str, full_stderr_str, process.returncode



class WpscanInput(BaseModel):
    command: str = Field(description="The wpscan command to execute (e.g., 'wpscan --url https://example.com' or 'wpscan --help')")
    safe_mode: bool = Field(default=True, description="Whether to enforce safety checks on the command")


@tool("wpscan_executor", args_schema=WpscanInput, return_direct=False)
def execute_wpscan(command: str, safe_mode: bool = True) -> str:
    """
    Execute WPScan commands and return REAL output.

    THIS TOOL ACTUALLY RUNS COMMANDS ON THE SYSTEM.

    This tool can:
    - Run wpscan against WordPress sites with various options
    - Execute 'wpscan --help' to get documentation
    - Perform vulnerability scanning and enumeration

    Args:
        command: The wpscan command to execute
        safe_mode: Whether to enforce safety checks (default: True)

    Returns:
        The ACTUAL output of the wpscan command execution
    """

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Preparing to execute command: {Fore.WHITE}{command}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    print(f"{Fore.BLUE}[DEBUG] Checking for file output flags...{Style.RESET_ALL}")

    output_patterns = [
        r'--output\s+\S+',
        r'-o\s+\S+',
        r'--format\s+\S+',
        r'--log\s+\S+',
    ]

    original_command = command
    for pattern in output_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            command = re.sub(pattern, '', command, flags=re.IGNORECASE)
            print(f"{Fore.YELLOW}[DEBUG] Removed file output flag matching: {pattern}{Style.RESET_ALL}")

    command = re.sub(r'\s+', ' ', command).strip()

    if command != original_command:
        print(f"{Fore.YELLOW}[DEBUG] Modified command (file outputs removed): {command}{Style.RESET_ALL}")

    if safe_mode:
        print(f"{Fore.BLUE}[DEBUG] Running safety checks...{Style.RESET_ALL}")
        dangerous_patterns = [
            r';\s*rm',
            r'&&\s*rm',
            r'\|\s*rm',
            r'`',
            r'\$\(',
            r'\|.*sh',
            r'--script=.*\.\.',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                error_msg = f"Command blocked for safety reasons. Pattern '{pattern}' detected."
                print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
                return f"Error: {error_msg}"

        print(f"{Fore.GREEN}[DEBUG] Safety checks passed{Style.RESET_ALL}")

    if not (command.strip().startswith('wpscan')):
        error_msg = "Command must start with 'wpscan'"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return f"Error: {error_msg}"

    actual_command = command

    try:
        print(f"{Fore.YELLOW}[DEBUG] Executing command with sliding window display...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] Command: {Fore.WHITE}{actual_command}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] Starting real-time output streaming...{Style.RESET_ALL}\n")
        
        process = subprocess.Popen(
            actual_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        stdout, stderr, returncode = stream_output_with_sliding_window(process, max_window_lines=12)
        
        print(f"{Fore.GREEN}[DEBUG] Command execution completed{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[DEBUG] Return code: {Fore.WHITE}{returncode}{Style.RESET_ALL}")

        output = stdout
        if stderr:
            output += f"\n\n{Fore.YELLOW}===== Errors/Warnings ====={Style.RESET_ALL}\n{stderr}"

        if returncode != 0 and not output:
            output = f"Command failed with return code {returncode}"
            print(f"{Fore.RED}[DEBUG] {output}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[DEBUG] Tool execution complete, returning output{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}\n")

        return output if output else "No output from command"

    except subprocess.TimeoutExpired:
        error_msg = "Command timed out after 600 seconds"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[DEBUG] This scan may be too complex for the timeout limit{Style.RESET_ALL}")
        return f"TIMEOUT_ERROR: {error_msg} - Command: {actual_command}"
    except Exception as e:
        error_msg = f"Error executing command: {str(e)}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_wpscan_installed() -> bool:
    """Check if wpscan is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if wpscan is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            "wpscan --version",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        is_installed = result.returncode == 0
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] wpscan is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] wpscan is not installed{Style.RESET_ALL}")
        return is_installed
    except:
        print(f"{Fore.RED}[DEBUG] Error checking wpscan installation{Style.RESET_ALL}")
        return False
