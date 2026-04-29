"""nikto tool — typed parameter schema, argv-based execution."""

import ipaddress
import re
import subprocess
from typing import List, Literal, Optional
from urllib.parse import urlparse

from colorama import Fore, Style, init
from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator

init(autoreset=True)


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)
_USER_AGENT_RE = re.compile(r"^[\w \-./;:()+,]+$")


class NiktoInput(BaseModel):
    """Typed input for the nikto executor."""

    target: str = Field(
        description=(
            "Target host or URL. Accepts: hostname (e.g. 'example.com'), "
            "IPv4/IPv6 address, or full URL (e.g. 'https://example.com/path'). "
            "When a full URL is given, the scheme determines SSL handling."
        ),
    )
    port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Port number override. None = nikto default (80, or 443 with ssl=True).",
    )
    ssl: bool = Field(
        default=False,
        description="Force SSL/TLS. Implied if target is an https:// URL.",
    )
    tuning: Optional[
        List[Literal["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c"]]
    ] = Field(
        default=None,
        description=(
            "Restrict checks to specific test categories. Common IDs:\n"
            "  1 interesting files / risky checks\n"
            "  2 misconfigurations / default files\n"
            "  3 information disclosure\n"
            "  4 injection (XSS, SQLi, etc.)\n"
            "  5 remote file retrieval\n"
            "  6 denial of service (avoid in prod)\n"
            "  9 SQL injection\n"
            "  a authentication bypass\n"
            "  b software identification\n"
            "Pass a list, e.g. ['1','2','3']."
        ),
    )
    evasion: Optional[Literal["1", "2", "3", "4", "5", "6", "7", "8"]] = Field(
        default=None,
        description="IDS evasion technique (1-8). Use sparingly.",
    )
    user_agent: Optional[str] = Field(
        default=None,
        max_length=200,
        description=(
            "Override the User-Agent string. Allowed chars: alphanumerics and "
            "the printable set ' -./;:()+,'."
        ),
    )
    cgi_dirs: Optional[Literal["all", "none"]] = Field(
        default=None,
        description="Force-check CGI directories: 'all' or 'none'. Default: scan default list.",
    )

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        # If it parses as a URL with scheme http(s), accept.
        parsed = urlparse(v)
        if parsed.scheme in {"http", "https"}:
            if not parsed.netloc:
                raise ValueError("target URL is missing a host")
            if any(c in v for c in [" ", "\t", "\n", "\r"]):
                raise ValueError("target must not contain whitespace")
            return v
        # IP address?
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        # Hostname?
        if _HOSTNAME_RE.match(v):
            return v
        raise ValueError(
            f"target {v!r} is not a valid hostname, IP address, or http(s) URL"
        )

    @field_validator("user_agent")
    @classmethod
    def _validate_user_agent(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not _USER_AGENT_RE.match(v):
            raise ValueError(
                "user_agent contains disallowed characters; allowed set is "
                "alphanumerics and ' -./;:()+,'"
            )
        return v


def build_nikto_argv(params: NiktoInput) -> List[str]:
    argv: List[str] = ["nikto", "-h", params.target]
    if params.port is not None:
        argv += ["-p", str(params.port)]
    # nikto auto-derives SSL from an https:// URL; only add -ssl when requested
    # explicitly and the target isn't already an https URL.
    if params.ssl and not params.target.startswith("https://"):
        argv.append("-ssl")
    if params.tuning:
        argv += ["-Tuning", "".join(params.tuning)]
    if params.evasion:
        argv += ["-evasion", params.evasion]
    if params.user_agent:
        argv += ["-useragent", params.user_agent]
    if params.cgi_dirs:
        argv += ["-Cgidirs", params.cgi_dirs]
    # Always suppress nikto's interactive update prompt — replaces the old
    # regex-based string injection with a hardcoded argv element.
    argv += ["-ask", "no"]
    return argv


@tool("nikto_executor", args_schema=NiktoInput, return_direct=False)
def execute_nikto(
    target: str,
    port: Optional[int] = None,
    ssl: bool = False,
    tuning: Optional[List[str]] = None,
    evasion: Optional[str] = None,
    user_agent: Optional[str] = None,
    cgi_dirs: Optional[str] = None,
) -> str:
    """Run a nikto web-server vulnerability scan and return REAL output.

    Pick parameters from the typed schema; the tool composes a safe argv
    list internally and runs nikto via subprocess (no shell). Targets are
    validated by Pydantic before execution.
    """
    params = NiktoInput(
        target=target,
        port=port,
        ssl=ssl,
        tuning=tuning,  # type: ignore[arg-type]
        evasion=evasion,  # type: ignore[arg-type]
        user_agent=user_agent,
        cgi_dirs=cgi_dirs,  # type: ignore[arg-type]
    )
    argv = build_nikto_argv(params)

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Composed argv: {Fore.WHITE}{argv}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    try:
        result = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=1200,
        )

        if result.stdout:
            print(f"{Fore.WHITE}{result.stdout}{Style.RESET_ALL}")
        if result.stderr:
            print(f"{Fore.RED}{result.stderr}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[DEBUG] Command execution completed{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[DEBUG] Return code: {Fore.WHITE}{result.returncode}{Style.RESET_ALL}")

        output = result.stdout
        if result.stderr:
            output += f"\n\n{Fore.YELLOW}===== Errors/Warnings ====={Style.RESET_ALL}\n{result.stderr}"

        if result.returncode != 0 and not output:
            output = f"Command failed with return code {result.returncode}"

        print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}\n")
        return output if output else "No output from command"

    except subprocess.TimeoutExpired:
        error_msg = "Command timed out after 1200 seconds"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return f"TIMEOUT_ERROR: {error_msg} - argv: {argv}"
    except FileNotFoundError as e:
        error_msg = f"nikto binary not found: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg
    except Exception as e:
        error_msg = f"Error executing command: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_nikto_installed() -> bool:
    """Check if nikto is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if nikto is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            ["nikto", "-Version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_installed = result.returncode == 0
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] nikto is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] nikto is not installed{Style.RESET_ALL}")
        return is_installed
    except Exception:
        print(f"{Fore.RED}[DEBUG] Error checking nikto installation{Style.RESET_ALL}")
        return False
