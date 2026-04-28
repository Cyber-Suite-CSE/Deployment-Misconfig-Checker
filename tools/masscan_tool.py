import subprocess
import re
import os
import sys
from typing import Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from colorama import init, Fore, Style

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents import sudo_secrets

init(autoreset=True)


class MasscanInput(BaseModel):
    """Schema for MASSCAN tool input"""
    command: str = Field(description="The masscan command to execute (e.g., 'masscan -p80,443 192.168.1.0/24 --rate=1000' or 'masscan --help')")
    safe_mode: bool = Field(default=True, description="Whether to enforce safety checks on the command")


# masscan crafts its own raw packets, so anything beyond help/version needs root.
# Detect those exemptions to skip sudo elevation.
_INFO_ONLY_RE = re.compile(
    r'(?:^|\s)(--help|-h|--version|-V|--regress)(?:\s|$)', re.IGNORECASE
)


@tool("masscan_executor", args_schema=MasscanInput, return_direct=False)
def execute_masscan(command: str, safe_mode: bool = True) -> str:
    """
    Execute MASSCAN commands and return REAL output.

    THIS TOOL ACTUALLY RUNS COMMANDS ON THE SYSTEM.

    masscan is an Internet-scale port scanner — similar to nmap but optimized for
    sweeping very large IP ranges at very high packet rates by emitting its own
    raw packets. Almost every invocation therefore needs root; the tool prepends
    ``sudo -k`` automatically unless the command is help/version/regress.

    This tool can:
    - Run masscan port discovery against single hosts or large CIDR ranges
    - Execute 'masscan --help' to print usage information
    - Strip file-output flags so results stream back to stdout
    - Block obvious shell-injection patterns when safe_mode is on

    Args:
        command: The masscan command to execute
        safe_mode: Whether to enforce safety checks (default: True)

    Returns:
        The ACTUAL output of the masscan command execution
    """

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Preparing to execute command: {Fore.WHITE}{command}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    print(f"{Fore.BLUE}[DEBUG] Checking for file output flags...{Style.RESET_ALL}")

    output_patterns = [
        r'-oX\s+\S+',
        r'-oJ\s+\S+',
        r'-oG\s+\S+',
        r'-oL\s+\S+',
        r'-oB\s+\S+',
        r'-oD\s+\S+',
        r'--output-format\s+\S+',
        r'--output-filename\s+\S+',
        r'--output-file\s+\S+',
        r'--rotate\s+\S+',
        r'--rotate-dir\s+\S+',
        r'--append-output',
        r'--resume\s+\S+',
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
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                error_msg = f"Command blocked for safety reasons. Pattern '{pattern}' detected."
                print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
                return f"Error: {error_msg}"

        print(f"{Fore.GREEN}[DEBUG] Safety checks passed{Style.RESET_ALL}")

    if not (command.strip().startswith('masscan') or command.strip().startswith('man masscan')):
        error_msg = "Command must start with 'masscan' or 'man masscan'"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return f"Error: {error_msg}"

    is_info_only = bool(
        _INFO_ONLY_RE.search(command) or command.strip().startswith('man masscan')
    )

    actual_command = command
    sudo_stdin: Optional[str] = None
    if not is_info_only and not sudo_secrets.is_root():
        thread_id = sudo_secrets.current_thread_id.get()
        password = sudo_secrets.get_password(thread_id)
        if password is None:
            error_msg = (
                "masscan requires root for raw-socket access, but no sudo "
                "password is cached for this session. Approve a privileged "
                "command via HITL first to enter your sudo password, or "
                "rerun with the program already as root."
            )
            print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
            return f"Error: {error_msg}"
        actual_command = f"sudo -S -k -p '' {command}"
        sudo_stdin = password + "\n"
        print(f"{Fore.CYAN}[DEBUG] Using HITL-supplied sudo password (sudo -S){Style.RESET_ALL}")
    elif not is_info_only:
        print(f"{Fore.GREEN}[DEBUG] Already running as root{Style.RESET_ALL}")

    try:
        print(f"{Fore.YELLOW}[DEBUG] Executing command via subprocess...{Style.RESET_ALL}")
        display_command = actual_command if sudo_stdin is None else f"{actual_command}  [stdin: <password>]"
        print(f"{Fore.CYAN}[DEBUG] Actual command: {Fore.WHITE}{display_command}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] ----------------------------------------{Style.RESET_ALL}")

        result = subprocess.run(
            actual_command,
            shell=True,
            input=sudo_stdin,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

        print(f"{Fore.GREEN}[DEBUG] Command execution completed{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[DEBUG] Return code: {Fore.WHITE}{result.returncode}{Style.RESET_ALL}")

        if result.stdout:
            print(f"{Fore.CYAN}[DEBUG] ========== RAW STDOUT ==========={Style.RESET_ALL}")
            print(result.stdout)
            print(f"{Fore.CYAN}[DEBUG] ========== END STDOUT ==========={Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] No stdout output{Style.RESET_ALL}")

        if result.stderr:
            print(f"{Fore.MAGENTA}[DEBUG] ========== RAW STDERR ==========={Style.RESET_ALL}")
            print(result.stderr)
            print(f"{Fore.MAGENTA}[DEBUG] ========== END STDERR ==========={Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] No stderr output{Style.RESET_ALL}")

        # masscan often prints its banner and progress on stderr even when the
        # scan succeeds, so always merge it into the returned text.
        output = result.stdout
        if result.stderr:
            output += f"\n\n{Fore.YELLOW}===== Errors/Warnings ====={Style.RESET_ALL}\n{result.stderr}"

        if result.returncode != 0 and not output:
            output = f"Command failed with return code {result.returncode}"
            print(f"{Fore.RED}[DEBUG] {output}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[DEBUG] Tool execution complete, returning output{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}\n")

        return output if output else "No output from command"

    except subprocess.TimeoutExpired:
        error_msg = "Command timed out after 300 seconds"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[DEBUG] Consider lowering --rate or narrowing the target range{Style.RESET_ALL}")
        return f"TIMEOUT_ERROR: {error_msg} - Command: {actual_command}"
    except Exception as e:
        error_msg = f"Error executing command: {str(e)}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_masscan_installed() -> bool:
    """Check if masscan is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if masscan is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            "masscan --version",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Some masscan builds exit non-zero on --version while still printing
        # the banner — accept either rc=0 or "masscan" appearing in output.
        is_installed = (
            result.returncode == 0
            or "masscan" in (result.stdout + result.stderr).lower()
        )
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] masscan is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] masscan is not installed{Style.RESET_ALL}")
        return is_installed
    except Exception:
        print(f"{Fore.RED}[DEBUG] Error checking masscan installation{Style.RESET_ALL}")
        return False
