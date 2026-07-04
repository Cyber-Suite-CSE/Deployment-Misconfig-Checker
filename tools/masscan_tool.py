"""masscan tool — typed parameter schema, argv-based execution.

masscan needs raw-socket access for every real scan, so the tool always
elevates via sudo (cached HITL password). Only --version-style metadata
calls would skip elevation, but those are not part of the typed surface —
the agent uses the schema, not a help mode.
"""

import ipaddress
import os
import re
import subprocess
import sys
from typing import List, Literal, Optional

from colorama import Fore, Style, init
from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents import sudo_secrets

init(autoreset=True)


_PORTS_RE = re.compile(
    r"^([UT]:)?\d{1,5}(-\d{1,5})?(,([UT]:)?\d{1,5}(-\d{1,5})?)*$"
)
_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,16}$")
_IP_RANGE_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3}$"
)


def _validate_target_token(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("target token must not be empty")
    # IP / CIDR
    try:
        ipaddress.ip_network(v, strict=False)
        return v
    except ValueError:
        pass
    # Range like 10.0.0.1-10.0.0.50
    if _IP_RANGE_RE.match(v):
        return v
    raise ValueError(
        f"target {v!r} is not a valid IP, CIDR, or A.B.C.D-A.B.C.D range"
    )


class MasscanInput(BaseModel):
    """Typed input for the masscan executor."""

    targets: List[str] = Field(
        description=(
            "One or more targets. Each entry must be an IPv4/IPv6 address, "
            "a CIDR block ('10.0.0.0/24'), or a range ('10.0.0.1-10.0.0.50')."
        ),
    )
    ports: str = Field(
        description=(
            "Port spec. Formats: '80,443', '1-65535', '22,80-100,443', or with "
            "explicit transport: 'U:53,T:80'. There is no default — every real "
            "scan must name its ports."
        ),
    )
    rate: int = Field(
        default=1000,
        ge=1,
        le=100000,
        description=(
            "Packets per second. Guidance: 100=polite, 1000=LAN default, "
            "10000=large /16 sweeps, 100000+=lab links only."
        ),
    )
    banners: bool = Field(
        default=False,
        description="Add --banners to pull lightweight banners from open ports.",
    )
    excludes: Optional[List[str]] = Field(
        default=None,
        description="IPs/CIDRs/ranges to skip. Validated identically to targets.",
    )
    interface: Optional[str] = Field(
        default=None,
        description="Bind to a specific NIC (e.g. 'eth0'). Optional.",
    )
    wait_seconds: int = Field(
        default=10,
        ge=0,
        le=120,
        description="Seconds to wait for late responses after sending the last probe.",
    )

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("targets must contain at least one entry")
        if len(v) > 64:
            raise ValueError("at most 64 target entries per call")
        return [_validate_target_token(t) for t in v]

    @field_validator("excludes")
    @classmethod
    def _validate_excludes(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        if len(v) > 64:
            raise ValueError("at most 64 exclude entries per call")
        return [_validate_target_token(t) for t in v]

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: str) -> str:
        v = v.strip()
        if not _PORTS_RE.match(v):
            raise ValueError(
                f"ports {v!r} is not a valid spec "
                "(use '80,443' | '1-65535' | 'U:53,T:80')"
            )
        for part in v.split(","):
            chunk = part.split(":", 1)[-1]
            for endpoint in chunk.split("-"):
                p = int(endpoint)
                if not (0 <= p <= 65535):
                    raise ValueError(f"port {p} out of range 0-65535")
        return v

    @field_validator("interface")
    @classmethod
    def _validate_iface(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not _IFACE_RE.match(v):
            raise ValueError(
                "interface must be 1-16 alphanumerics or _.- (e.g. 'eth0')"
            )
        return v


def build_masscan_argv(params: MasscanInput) -> List[str]:
    argv: List[str] = ["masscan"]
    argv += ["-p", params.ports]
    argv += ["--rate", str(params.rate)]
    argv += ["--wait", str(params.wait_seconds)]
    if params.banners:
        argv.append("--banners")
    if params.interface:
        argv += ["-e", params.interface]
    if params.excludes:
        argv += ["--exclude", ",".join(params.excludes)]
    argv += params.targets
    return argv


@tool("masscan_executor", args_schema=MasscanInput, return_direct=False)
def execute_masscan(
    targets: List[str],
    ports: str,
    rate: int = 1000,
    banners: bool = False,
    excludes: Optional[List[str]] = None,
    interface: Optional[str] = None,
    wait_seconds: int = 10,
) -> str:
    """Run a masscan port-discovery sweep and return REAL output.

    Pick parameters from the typed schema; the tool composes a safe argv
    list internally and runs masscan via subprocess (no shell). Always
    elevated via sudo because masscan crafts raw packets.
    """
    params = MasscanInput(
        targets=targets,
        ports=ports,
        rate=rate,
        banners=banners,
        excludes=excludes,
        interface=interface,
        wait_seconds=wait_seconds,
    )
    argv = build_masscan_argv(params)
    sudo_stdin: Optional[str] = None

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Composed argv: {Fore.WHITE}{argv}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    if not sudo_secrets.is_root():
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
        argv = ["sudo", "-S", "-k", "-p", ""] + argv
        sudo_stdin = password + "\n"
        print(f"{Fore.CYAN}[DEBUG] Using HITL-supplied sudo password (sudo -S){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[DEBUG] Already running as root{Style.RESET_ALL}")

    try:
        display = " ".join(argv) + ("  [stdin: <password>]" if sudo_stdin else "")
        print(f"{Fore.CYAN}[DEBUG] Actual command: {Fore.WHITE}{display}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[DEBUG] ----------------------------------------{Style.RESET_ALL}")

        result = subprocess.run(
            argv,
            shell=False,
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
        if result.stderr:
            print(f"{Fore.MAGENTA}[DEBUG] ========== RAW STDERR ==========={Style.RESET_ALL}")
            print(result.stderr)
            print(f"{Fore.MAGENTA}[DEBUG] ========== END STDERR ==========={Style.RESET_ALL}")

        # masscan often prints banner/progress on stderr — merge it in.
        output = result.stdout
        if result.stderr:
            output += f"\n\n{Fore.YELLOW}===== Errors/Warnings ====={Style.RESET_ALL}\n{result.stderr}"

        if result.returncode != 0 and not output:
            output = f"Command failed with return code {result.returncode}"

        print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}\n")
        return output if output else "No output from command"

    except subprocess.TimeoutExpired:
        error_msg = "Command timed out after 300 seconds"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return f"TIMEOUT_ERROR: {error_msg} - argv: {argv}"
    except FileNotFoundError as e:
        error_msg = f"masscan binary not found: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg
    except Exception as e:
        error_msg = f"Error executing command: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_masscan_installed() -> bool:
    """Check if masscan is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if masscan is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            ["masscan", "--version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
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
