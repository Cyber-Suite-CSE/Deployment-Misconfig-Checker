import subprocess
import re
import os
import shlex
from typing import Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from colorama import init, Fore, Style

from tools._proc_runner import run_with_timeout

init(autoreset=True)

WPSCAN_TIMEOUT_S = int(os.getenv("WPSCAN_TIMEOUT", "600"))



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

    stripped = command.strip()
    if not stripped.startswith('wpscan'):
        command = f"wpscan {stripped}"
        print(f"{Fore.YELLOW}[DEBUG] Auto-prepended 'wpscan' (command was missing binary name){Style.RESET_ALL}")

    lower_command = command.lower()
    is_scan_command = (
        "--help" not in lower_command
        and "--version" not in lower_command
        and "--update" not in lower_command
        and "--list" not in lower_command
    )

    if is_scan_command and "--url" in lower_command:
        if "--enumerate" not in lower_command:
            command += " --enumerate ap,at,u"
            print(f"{Fore.YELLOW}[DEBUG] Added default enumeration flags (--enumerate ap,at,u){Style.RESET_ALL}")
        if "--plugins-detection" not in lower_command:
            command += " --plugins-detection aggressive"
            print(f"{Fore.YELLOW}[DEBUG] Added aggressive plugin detection flag{Style.RESET_ALL}")
        if "--random-user-agent" not in lower_command:
            command += " --random-user-agent"
            print(f"{Fore.YELLOW}[DEBUG] Added random user agent flag{Style.RESET_ALL}")
        if "--api-token" not in lower_command:
            api_token = os.getenv("WPSCAN_API_TOKEN")
            if api_token:
                # shlex.quote so a token containing shell metacharacters
                # ($, ;, etc.) is passed literally rather than interpreted.
                command += f" --api-token {shlex.quote(api_token)}"
                print(f"{Fore.YELLOW}[DEBUG] Injected WPScan API token from environment{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[DEBUG] No WPSCAN_API_TOKEN found in environment{Style.RESET_ALL}")

    actual_command = command

    try:
        print(f"{Fore.YELLOW}[DEBUG] Executing command...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] Command: {Fore.WHITE}{actual_command}{Style.RESET_ALL}")

        stdout, stderr, returncode, timed_out = run_with_timeout(
            actual_command, timeout=WPSCAN_TIMEOUT_S
        )

        if timed_out:
            error_msg = f"Command timed out after {WPSCAN_TIMEOUT_S} seconds"
            print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] Process group killed; this scan may be too complex for the timeout limit{Style.RESET_ALL}")
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
