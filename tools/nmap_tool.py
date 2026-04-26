import subprocess
import re
import os
from typing import Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from colorama import init, Fore, Style

from tools._proc_runner import run_with_timeout

NMAP_TIMEOUT_S = int(os.getenv("NMAP_TIMEOUT", "120"))

# Initialize colorama for colored output
init(autoreset=True)


class NmapInput(BaseModel):
    """Schema for NMAP tool input"""
    command: str = Field(description="The nmap command to execute (e.g., 'nmap -sS 192.168.1.1' or 'nmap --help')")
    safe_mode: bool = Field(default=True, description="Whether to enforce safety checks on the command")


def needs_root_privileges(command: str) -> bool:
    """
    Check if an nmap command requires root privileges

    Args:
        command: The nmap command to check

    Returns:
        True if the command needs root privileges
    """
    # Patterns that require root
    root_patterns = [
        r'-O',  # OS detection
        r'--osscan',  # OS scan
        r'-sS',  # SYN scan
        r'-sA',  # ACK scan
        r'-sW',  # Window scan
        r'-sM',  # Maimon scan
        r'-sU',  # UDP scan (usually needs root)
        r'-sN',  # Null scan
        r'-sF',  # FIN scan
        r'-sX',  # Xmas scan
        r'--scanflags',  # Custom TCP scan flags
        r'-sY',  # SCTP INIT scan
        r'-sZ',  # COOKIE-ECHO scan
        r'--traceroute',  # Traceroute
        r'-PA(?:\d|$)',  # TCP ACK ping (when not specified port)
        r'-PS(?:\d|$)',  # TCP SYN ping
        r'-PU',  # UDP ping
        r'-PY',  # SCTP ping
        r'--ip-options',  # IP options
        r'--spoof-mac',  # MAC address spoofing
    ]

    for pattern in root_patterns:
        if re.search(pattern, command):
            return True
    return False


@tool("nmap_executor", args_schema=NmapInput, return_direct=False)
def execute_nmap(command: str, safe_mode: bool = True) -> str:
    """
    Execute NMAP commands and return REAL output.

    THIS TOOL ACTUALLY RUNS COMMANDS ON THE SYSTEM.

    This tool can:
    - Run nmap scans with various options
    - Execute 'nmap --help' to get documentation
    - Execute 'man nmap' for detailed manual (if available)
    - Automatically use sudo for privileged operations

    Args:
        command: The nmap command to execute
        safe_mode: Whether to enforce safety checks (default: True)

    Returns:
        The ACTUAL output of the nmap command execution
    """

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Preparing to execute command: {Fore.WHITE}{command}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    # Remove any file output flags before processing
    print(f"{Fore.BLUE}[DEBUG] Checking for file output flags...{Style.RESET_ALL}")

    # Patterns for file output that should be removed
    output_patterns = [
        r'-oX\s+\S+',  # XML output
        r'-oN\s+\S+',  # Normal output
        r'-oG\s+\S+',  # Grepable output
        r'-oA\s+\S+',  # All formats output
        r'-oS\s+\S+',  # Script kiddie output
        r'--append-output',  # Append to files
        r'--resume\s+\S+',  # Resume from file
        r'--stylesheet\s+\S+',  # XSL stylesheet
        r'--webxml',  # Web XML
        r'--no-stylesheet',  # Related to XML output
    ]

    original_command = command
    for pattern in output_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            command = re.sub(pattern, '', command, flags=re.IGNORECASE)
            print(f"{Fore.YELLOW}[DEBUG] Removed file output flag matching: {pattern}{Style.RESET_ALL}")

    # Clean up any double spaces left after removal
    command = re.sub(r'\s+', ' ', command).strip()

    if command != original_command:
        print(f"{Fore.YELLOW}[DEBUG] Modified command (file outputs removed): {command}{Style.RESET_ALL}")

    # Basic safety checks when safe_mode is enabled
    if safe_mode:
        print(f"{Fore.BLUE}[DEBUG] Running safety checks...{Style.RESET_ALL}")
        # Dangerous patterns to block
        dangerous_patterns = [
            r';\s*rm',  # Command chaining with rm
            r'&&\s*rm',  # Command chaining with rm
            r'\|\s*rm',  # Piping to rm
            r'`',  # Command substitution
            r'\$\(',  # Command substitution
            r'\|.*sh',  # Piping to shell
            r'--script=.*\.\.',  # Path traversal in scripts
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                error_msg = f"Command blocked for safety reasons. Pattern '{pattern}' detected."
                print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
                return f"Error: {error_msg}"

        print(f"{Fore.GREEN}[DEBUG] Safety checks passed{Style.RESET_ALL}")

    # Ensure the command starts with 'nmap' or 'man nmap'.
    # If the LLM omitted the binary name, prepend it instead of bouncing the call —
    # avoids a wasted self-correction round-trip.
    stripped = command.strip()
    if not (stripped.startswith('nmap') or stripped.startswith('man nmap')):
        command = f"nmap {stripped}"
        print(f"{Fore.YELLOW}[DEBUG] Auto-prepended 'nmap' (command was missing binary name){Style.RESET_ALL}")

    # Check if the command needs root privileges
    needs_root = needs_root_privileges(command)
    actual_command = command

    if needs_root:
        print(f"{Fore.YELLOW}[DEBUG] Command requires root privileges{Style.RESET_ALL}")
        # Check if we're already root
        try:
            if os.geteuid() != 0:
                print(f"{Fore.CYAN}[DEBUG] Not running as root, prepending sudo...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[DEBUG] You will be prompted for sudo password{Style.RESET_ALL}")
                # Use sudo with -k to not cache password
                actual_command = f"sudo -k {command}"
            else:
                print(f"{Fore.GREEN}[DEBUG] Already running as root{Style.RESET_ALL}")
        except AttributeError:
            # Windows doesn't have geteuid
            print(f"{Fore.YELLOW}[DEBUG] Cannot determine if running as root (Windows?){Style.RESET_ALL}")

    try:
        print(f"{Fore.YELLOW}[DEBUG] Executing command via subprocess...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] Actual command: {Fore.WHITE}{actual_command}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] ----------------------------------------{Style.RESET_ALL}")

        stdout, stderr, returncode, timed_out = run_with_timeout(
            actual_command, timeout=NMAP_TIMEOUT_S
        )

        if timed_out:
            error_msg = f"Command timed out after {NMAP_TIMEOUT_S} seconds"
            print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] Process group killed; this scan may be too complex for the timeout limit{Style.RESET_ALL}")
            return f"TIMEOUT_ERROR: {error_msg} - Command: {actual_command}"

        print(f"{Fore.GREEN}[DEBUG] Command execution completed{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[DEBUG] Return code: {Fore.WHITE}{returncode}{Style.RESET_ALL}")

        # stdout/stderr were already streamed to the terminal during execution
        # by run_with_timeout; don't double-print them here.
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


def validate_nmap_installed() -> bool:
    """Check if nmap is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if nmap is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            "nmap --version",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        is_installed = result.returncode == 0
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] nmap is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] nmap is not installed{Style.RESET_ALL}")
        return is_installed
    except:
        print(f"{Fore.RED}[DEBUG] Error checking nmap installation{Style.RESET_ALL}")
        return False