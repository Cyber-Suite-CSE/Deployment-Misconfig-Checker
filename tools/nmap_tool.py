"""nmap tool — typed parameter schema, argv-based execution.

The agent picks fields from :class:`NmapInput`; this module composes the argv
list. ``shell=False`` everywhere — no concatenation of agent input into a
shell command line.
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


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)
_PORT_SPEC_RE = re.compile(r"^(top-\d{1,5}|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$")


_NSE_SCRIPT_ALLOWLIST = Literal[
    "vuln",
    "default",
    "safe",
    "discovery",
    "auth",
    "http-title",
    "http-headers",
    "http-enum",
    "http-methods",
    "http-robots.txt",
    "ssl-cert",
    "ssl-enum-ciphers",
    "smb-os-discovery",
    "smb-vuln-ms17-010",
    "smb-enum-shares",
    "ftp-anon",
    "dns-brute",
]


class NmapInput(BaseModel):
    """Typed input for the nmap executor.

    Pick a target, choose a scan_profile baseline, and toggle granular flags.
    The tool composes the argv internally — there is no command string to
    write. Field descriptions are sent to the LLM as the schema reference.
    """

    target: str = Field(
        description=(
            "Single target. IPv4/IPv6 address, hostname (RFC 1123), or "
            "CIDR block. Examples: '192.168.1.1', 'example.com', "
            "'10.0.0.0/24'. Multiple targets are not supported in one call."
        ),
    )
    scan_profile: Literal["quick", "standard", "comprehensive", "stealth", "ping"] = Field(
        default="standard",
        description=(
            "Baseline scan strategy.\n"
            "- quick: top 100 ports, no service detect (fast triage).\n"
            "- standard: top 1000 ports + version probe (default).\n"
            "- comprehensive: full TCP range + -sV + -sC + -O (slow, requires sudo).\n"
            "- stealth: SYN scan with -T2 (requires sudo).\n"
            "- ping: -sn host discovery only, no port scan."
        ),
    )
    ports: Optional[str] = Field(
        default=None,
        description=(
            "Override port spec. Formats: '80,443', '1-1000', '22,80-100,443', "
            "or 'top-N' (e.g. 'top-100'). When None, the scan_profile default applies."
        ),
    )
    service_detection: bool = Field(
        default=False,
        description="Add -sV (probe open ports for service/version). Layered on top of profile.",
    )
    os_detection: bool = Field(
        default=False,
        description="Add -O (OS fingerprint). REQUIRES SUDO. Layered on top of profile.",
    )
    default_scripts: bool = Field(
        default=False,
        description="Add -sC (NSE default-category scripts). Layered on top of profile.",
    )
    timing: Literal["polite", "normal", "aggressive", "insane"] = Field(
        default="normal",
        description=(
            "Timing template. polite=-T2 (slow), normal=-T3 (default), "
            "aggressive=-T4 (preferred for LAN), insane=-T5 (unreliable)."
        ),
    )
    nse_scripts: Optional[List[_NSE_SCRIPT_ALLOWLIST]] = Field(  # type: ignore[valid-type]
        default=None,
        description=(
            "Allowlisted NSE script categories or specific scripts to run via "
            "--script. Only the listed names are accepted; arbitrary script names "
            "are rejected by the schema."
        ),
    )
    open_only: bool = Field(
        default=True,
        description="Add --open (only show ports in the open state). Cleaner output.",
    )

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        # Try IP / network first.
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
        # Fall back to hostname.
        if _HOSTNAME_RE.match(v):
            return v
        raise ValueError(
            f"target {v!r} is not a valid IPv4/IPv6 address, CIDR block, or hostname"
        )

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not _PORT_SPEC_RE.match(v):
            raise ValueError(
                f"ports {v!r} is not a valid spec (use '80,443' | '1-1000' | 'top-N')"
            )
        # Sanity-check numeric ranges.
        if v.startswith("top-"):
            n = int(v.split("-", 1)[1])
            if not (1 <= n <= 65535):
                raise ValueError("top-N must be between 1 and 65535")
            return v
        for part in v.split(","):
            for endpoint in part.split("-"):
                p = int(endpoint)
                if not (1 <= p <= 65535):
                    raise ValueError(f"port {p} out of range 1-65535")
        return v


_TIMING_FLAG = {"polite": "-T2", "normal": "-T3", "aggressive": "-T4", "insane": "-T5"}


def _profile_argv(profile: str) -> List[str]:
    """argv fragment contributed by the scan_profile baseline (no target, no ports)."""
    if profile == "quick":
        return ["--top-ports", "100"]
    if profile == "standard":
        return ["--top-ports", "1000", "-sV"]
    if profile == "comprehensive":
        return ["-p-", "-sV", "-sC", "-O"]
    if profile == "stealth":
        return ["-sS"]
    if profile == "ping":
        return ["-sn"]
    return []


def _ports_argv(ports: Optional[str], profile: str) -> List[str]:
    if ports is None:
        return []
    if ports.startswith("top-"):
        n = ports.split("-", 1)[1]
        return ["--top-ports", n]
    # Comprehensive already pins -p-; explicit ports override that.
    return ["-p", ports]


_PROFILE_NON_PORT_ARGS = {
    "quick": [],
    "standard": ["-sV"],
    "comprehensive": ["-sV", "-sC", "-O"],
    "stealth": ["-sS"],
    "ping": ["-sn"],
}


def build_nmap_argv(params: NmapInput) -> List[str]:
    """Compose the argv list executed by subprocess.run(..., shell=False)."""
    argv: List[str] = ["nmap"]

    # When explicit ports are given, drop the profile's own port flags but
    # keep its non-port behaviour (e.g. -sV/-sC/-O for "comprehensive").
    if params.ports is None:
        argv += _profile_argv(params.scan_profile)
    else:
        argv += _PROFILE_NON_PORT_ARGS[params.scan_profile]

    argv += _ports_argv(params.ports, params.scan_profile)

    if params.service_detection and "-sV" not in argv:
        argv.append("-sV")
    if params.os_detection and "-O" not in argv:
        argv.append("-O")
    if params.default_scripts and "-sC" not in argv:
        argv.append("-sC")

    # Stealth profile already pins -T2; let user-specified timing override only when stronger.
    if params.scan_profile != "stealth":
        argv.append(_TIMING_FLAG[params.timing])
    elif params.timing != "normal":
        argv.append(_TIMING_FLAG[params.timing])

    if params.open_only and params.scan_profile != "ping":
        argv.append("--open")

    if params.nse_scripts:
        argv += ["--script", ",".join(params.nse_scripts)]

    argv.append(params.target)
    return argv


def needs_root(params: NmapInput) -> bool:
    """True iff the resolved nmap call needs raw-socket / kernel privileges."""
    if params.os_detection:
        return True
    if params.scan_profile in {"comprehensive", "stealth"}:
        return True
    return False


@tool("nmap_executor", args_schema=NmapInput, return_direct=False)
def execute_nmap(
    target: str,
    scan_profile: str = "standard",
    ports: Optional[str] = None,
    service_detection: bool = False,
    os_detection: bool = False,
    default_scripts: bool = False,
    timing: str = "normal",
    nse_scripts: Optional[List[str]] = None,
    open_only: bool = True,
) -> str:
    """Run an nmap scan and return REAL output.

    Pick parameters; the tool composes a safe argv list internally and runs
    nmap via subprocess (no shell). All inputs are validated by the schema —
    invalid targets, ports, or scripts are rejected before execution.
    """
    params = NmapInput(
        target=target,
        scan_profile=scan_profile,  # type: ignore[arg-type]
        ports=ports,
        service_detection=service_detection,
        os_detection=os_detection,
        default_scripts=default_scripts,
        timing=timing,  # type: ignore[arg-type]
        nse_scripts=nse_scripts,  # type: ignore[arg-type]
        open_only=open_only,
    )

    argv = build_nmap_argv(params)
    sudo_stdin: Optional[str] = None

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Composed argv: {Fore.WHITE}{argv}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    if needs_root(params) and not sudo_secrets.is_root():
        thread_id = sudo_secrets.current_thread_id.get()
        password = sudo_secrets.get_password(thread_id)
        if password is None:
            error_msg = (
                "Command requires root, but no sudo password is cached for this "
                "session. Approve a privileged command via HITL first to enter "
                "your sudo password, or rerun with the program already as root."
            )
            print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
            return f"Error: {error_msg}"
        argv = ["sudo", "-S", "-k", "-p", ""] + argv
        sudo_stdin = password + "\n"
        print(f"{Fore.CYAN}[DEBUG] Using HITL-supplied sudo password (sudo -S){Style.RESET_ALL}")
    elif needs_root(params):
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
            timeout=120,
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
        error_msg = "Command timed out after 120 seconds"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return f"TIMEOUT_ERROR: {error_msg} - argv: {argv}"
    except FileNotFoundError as e:
        error_msg = f"nmap binary not found: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg
    except Exception as e:
        error_msg = f"Error executing command: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_nmap_installed() -> bool:
    """Check if nmap is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if nmap is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            ["nmap", "--version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_installed = result.returncode == 0
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] nmap is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] nmap is not installed{Style.RESET_ALL}")
        return is_installed
    except Exception:
        print(f"{Fore.RED}[DEBUG] Error checking nmap installation{Style.RESET_ALL}")
        return False
