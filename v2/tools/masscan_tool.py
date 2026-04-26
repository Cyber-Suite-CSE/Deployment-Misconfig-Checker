import os
import re
import subprocess

from colorama import Fore, Style, init
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from tools._proc_runner import run_with_timeout

init(autoreset=True)

MASSCAN_TIMEOUT_S = int(os.getenv("MASSCAN_TIMEOUT", "300"))


class MasscanInput(BaseModel):
    command: str = Field(
        description="The masscan command to execute, for example 'masscan 192.168.1.0/24 -p80,443'"
    )
    safe_mode: bool = Field(
        default=True, description="Whether to enforce safety checks on the command"
    )


def validate_masscan_installed() -> bool:
    """Check whether masscan is installed."""
    try:
        result = subprocess.run(
            "masscan --version",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output = f"{result.stdout}\n{result.stderr}"
        return result.returncode == 0 or "Masscan version" in output
    except Exception:
        return False


def _needs_root_privileges(command: str) -> bool:
    return command.strip().startswith("masscan")


@tool("masscan_executor", args_schema=MasscanInput, return_direct=False)
def execute_masscan(command: str, safe_mode: bool = True) -> str:
    """
    Execute masscan commands and return real output.

    The tool degrades cleanly when masscan is not installed.
    """
    if not validate_masscan_installed():
        return (
            "MASSCAN_NOT_INSTALLED: masscan is not installed on this system. "
            "Service discovery should continue with nmap only."
        )

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Preparing to execute command: {Fore.WHITE}{command}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    output_patterns = [
        r"-oL\s+\S+",
        r"-oB\s+\S+",
        r"-oX\s+\S+",
        r"-oJ\s+\S+",
        r"--output-format\s+\S+",
        r"--output-filename\s+\S+",
    ]

    original_command = command
    for pattern in output_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            command = re.sub(pattern, "", command, flags=re.IGNORECASE)

    command = re.sub(r"\s+", " ", command).strip()
    if command != original_command:
        print(
            f"{Fore.YELLOW}[DEBUG] Modified command (file outputs removed): {command}{Style.RESET_ALL}"
        )

    if safe_mode:
        dangerous_patterns = [
            r";\s*rm",
            r"&&\s*rm",
            r"\|\s*rm",
            r"`",
            r"\$\(",
            r"\|.*sh",
            r"--banners.*\.\.",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return f"Error: Command blocked for safety reasons. Pattern '{pattern}' detected."

    stripped = command.strip()
    if not stripped.startswith("masscan"):
        command = f"masscan {stripped}"
        print(f"{Fore.YELLOW}[DEBUG] Auto-prepended 'masscan' (command was missing binary name){Style.RESET_ALL}")

    actual_command = command
    if _needs_root_privileges(command):
        try:
            if os.geteuid() != 0:
                actual_command = f"sudo -k {command}"
        except AttributeError:
            pass

    try:
        stdout, stderr, returncode, timed_out = run_with_timeout(
            actual_command, timeout=MASSCAN_TIMEOUT_S
        )
        if timed_out:
            return f"TIMEOUT_ERROR: Command timed out after {MASSCAN_TIMEOUT_S} seconds - Command: {actual_command}"
        output = stdout or ""
        if stderr:
            output += f"\n\n===== Errors/Warnings =====\n{stderr}"
        if returncode != 0 and not output:
            output = f"Command failed with return code {returncode}"
        return output or "No output from command"
    except Exception as exc:
        return f"Error executing command: {exc}"
