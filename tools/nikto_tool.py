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

from tools._proc_runner import run_with_timeout

NIKTO_TIMEOUT_S = int(os.getenv("NIKTO_TIMEOUT", "1200"))

init(autoreset=True)

class NiktoInput(BaseModel):
    command: str = Field(description="The nikto command to execute (e.g., 'nikto -h https://example.com' or 'nikto -Help')")
    safe_mode: bool = Field(default=True, description="Whether to enforce safety checks on the command")


@tool("nikto_executor", args_schema=NiktoInput, return_direct=False)
def execute_nikto(command: str, safe_mode: bool = True) -> str:
    """
    Execute Nikto commands and return REAL output.

    THIS TOOL ACTUALLY RUNS COMMANDS ON THE SYSTEM.

    This tool can:
    - Run nikto against web servers with various options
    - Execute 'nikto -Help' to get documentation
    - Perform web vulnerability scanning and misconfiguration detection

    Args:
        command: The nikto command to execute
        safe_mode: Whether to enforce safety checks (default: True)

    Returns:
        The ACTUAL output of the nikto command execution
    """

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Preparing to execute command: {Fore.WHITE}{command}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    print(f"{Fore.BLUE}[DEBUG] Checking for file output flags...{Style.RESET_ALL}")

    output_patterns = [
        r'-o\s+\S+',
        r'-output\s+\S+',
        r'-Format\s+\S+',
        r'-f\s+\S+',
        r'-Save\s+\S+',
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
            r'-mutate.*\.\.',
            r'-Plugin.*\.\.',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                error_msg = f"Command blocked for safety reasons. Pattern '{pattern}' detected."
                print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
                return f"Error: {error_msg}"

        print(f"{Fore.GREEN}[DEBUG] Safety checks passed{Style.RESET_ALL}")

    stripped = command.strip()
    if not stripped.startswith('nikto'):
        command = f"nikto {stripped}"
        print(f"{Fore.YELLOW}[DEBUG] Auto-prepended 'nikto' (command was missing binary name){Style.RESET_ALL}")

    if '-ask' not in command.lower():
        command = command + ' -ask no'
        print(f"{Fore.YELLOW}[DEBUG] Added '-ask no' flag to suppress prompts{Style.RESET_ALL}")

    actual_command = command

    try:
        print(f"{Fore.YELLOW}[DEBUG] Executing command (standard logging)...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] Command: {Fore.WHITE}{actual_command}{Style.RESET_ALL}")

        stdout, stderr, returncode, timed_out = run_with_timeout(
            actual_command, timeout=NIKTO_TIMEOUT_S
        )

        if timed_out:
            error_msg = f"Command timed out after {NIKTO_TIMEOUT_S} seconds"
            print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
            return f"TIMEOUT_ERROR: {error_msg} - Command: {actual_command}"

        # stdout/stderr were already streamed to the terminal during execution.
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

    except Exception as e:
        error_msg = f"Error executing command: {str(e)}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_nikto_installed() -> bool:
    """Check if nikto is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if nikto is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            "nikto -Version",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        is_installed = result.returncode == 0
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] nikto is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] nikto is not installed{Style.RESET_ALL}")
        return is_installed
    except:
        print(f"{Fore.RED}[DEBUG] Error checking nikto installation{Style.RESET_ALL}")
        return False
