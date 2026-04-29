"""wpscan tool — typed parameter schema, argv-based execution.

Replaces opaque "auto-injected flag" behaviour with explicit Pydantic
fields. Every flag wpscan sees is derived from validated input.
"""

import os
import re
import shutil
import subprocess
import sys
import threading
from typing import List, Literal, Optional
from urllib.parse import urlparse

from colorama import Fore, Style, init
from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator, model_validator

init(autoreset=True)


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-@]{1,64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9]{20,128}$")


class SlidingWindowDisplay:
    """Stream wpscan stdout to the terminal in a fixed-height window."""

    def __init__(self, max_lines: int = 10) -> None:
        self.max_lines = max_lines
        self.lines: List[str] = []
        self.terminal_width = shutil.get_terminal_size((80, 24)).columns
        self.is_initialized = False
        self.current_line_count = 0

    def initialize_display(self) -> None:
        if not self.is_initialized:
            self.is_initialized = True

    def add_line(self, line: str) -> None:
        line = line.rstrip()
        if not line:
            return
        if len(line) > self.terminal_width - 4:
            line = line[: self.terminal_width - 7] + "..."
        self.lines.append(line)
        if len(self.lines) <= self.max_lines:
            print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
            sys.stdout.flush()
            self.current_line_count += 1
        else:
            self.lines.pop(0)
            self.update_display(line)

    def update_display(self, new_line: str) -> None:
        if not self.is_initialized:
            return
        sys.stdout.write(f"\033[{self.max_lines}A")
        sys.stdout.write("\033[1M")
        sys.stdout.write(f"\033[{self.max_lines - 1}B")
        print(f"{Fore.WHITE}{new_line}{Style.RESET_ALL}")
        sys.stdout.flush()

    def finalize(self, full_output: str) -> None:
        if not self.is_initialized:
            return
        sys.stdout.write(f"\033[{self.max_lines}A")
        sys.stdout.write("\033[J")
        print()


def stream_output_with_sliding_window(process, max_window_lines: int = 10, timeout: Optional[float] = None):
    display = SlidingWindowDisplay(max_lines=max_window_lines)
    display.initialize_display()

    full_output: List[str] = []
    full_stderr: List[str] = []

    def read_stream(stream, is_stderr: bool = False) -> None:
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
            display.add_line(f"Error reading stream: {e}")

    stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, False))
    stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, True))
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        display.finalize("\n".join(full_output))
        raise

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)

    full_output_str = "\n".join(full_output)
    full_stderr_str = "\n".join(full_stderr)
    display.finalize(full_output_str)
    return full_output_str, full_stderr_str, process.returncode


_ENUMERATE_CODE = {
    "plugins-all": "ap",
    "plugins-popular": "p",
    "plugins-vulnerable": "vp",
    "themes-all": "at",
    "themes-popular": "t",
    "themes-vulnerable": "vt",
    "users": "u",
    "media": "m",
    "config-backups": "cb",
    "db-exports": "dbe",
    "timthumbs": "tt",
}


class WpscanInput(BaseModel):
    """Typed input for the wpscan executor."""

    url: str = Field(
        description=(
            "Target WordPress site URL with scheme. "
            "Examples: 'https://example.com', 'http://blog.local/wp'. "
            "When targeting localhost (or 127.0.0.1 / ::1), the port MUST be "
            "included in the URL (e.g. 'http://localhost:8080'). A bare "
            "'http://localhost' will hit port 80 and almost certainly miss "
            "the WordPress instance."
        ),
    )
    enumerate: List[
        Literal[
            "plugins-all",
            "plugins-popular",
            "plugins-vulnerable",
            "themes-all",
            "themes-popular",
            "themes-vulnerable",
            "users",
            "media",
            "config-backups",
            "db-exports",
            "timthumbs",
        ]
    ] = Field(
        default=["plugins-all", "themes-all", "users"],
        description=(
            "What to enumerate. Default covers all plugins, all themes, and "
            "users. Pass a narrower list (e.g. ['users']) when the operator "
            "requests a focused scan."
        ),
    )
    detection_mode: Literal["passive", "aggressive", "mixed"] = Field(
        default="mixed",
        description="WordPress detection mode (overall fingerprinting strategy).",
    )
    plugins_detection: Literal["passive", "aggressive", "mixed"] = Field(
        default="aggressive",
        description="Plugin detection mode. Aggressive is loud but most thorough.",
    )
    plugins_version_detection: Literal["passive", "aggressive", "mixed"] = Field(
        default="mixed",
        description="Plugin version-detection mode.",
    )
    random_user_agent: bool = Field(
        default=True,
        description="Add --random-user-agent to rotate UAs and reduce blocking.",
    )
    password_attack: Optional[Literal["wp-login", "xmlrpc", "xmlrpc-multicall"]] = Field(
        default=None,
        description=(
            "Brute-force attack mode. Only set when the operator explicitly "
            "asks for password testing. Requires `usernames` to be set."
        ),
    )
    usernames: Optional[List[str]] = Field(
        default=None,
        description=(
            "Usernames to brute-force (max 10). Required when password_attack "
            "is set. Each username must match ^[A-Za-z0-9_.\\-@]{1,64}$."
        ),
    )
    api_token: Optional[str] = Field(
        default=None,
        description=(
            "WPVulnDB API token. When omitted, the tool falls back to the "
            "WPSCAN_API_TOKEN environment variable. 20-128 alphanumerics."
        ),
    )

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("url must start with http:// or https://")
        if not parsed.netloc:
            raise ValueError("url is missing a host")
        if any(c in v for c in [" ", "\t", "\n", "\r"]):
            raise ValueError("url must not contain whitespace")
        host = (parsed.hostname or "").lower()
        if host in {"localhost", "127.0.0.1", "::1"} and parsed.port is None:
            raise ValueError(
                f"localhost targets must include a port in the URL "
                f"(e.g. 'http://{host}:8080'); got {v!r}"
            )
        return v

    @field_validator("usernames")
    @classmethod
    def _validate_usernames(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        if len(v) > 10:
            raise ValueError("at most 10 usernames per call")
        for u in v:
            if not _USERNAME_RE.match(u):
                raise ValueError(
                    f"username {u!r} is not valid (allowed: alphanumerics, _.-@, 1-64 chars)"
                )
        return v

    @field_validator("api_token")
    @classmethod
    def _validate_token(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not _TOKEN_RE.match(v):
            raise ValueError("api_token must be 20-128 alphanumeric characters")
        return v

    @model_validator(mode="after")
    def _check_password_attack(self) -> "WpscanInput":
        if self.password_attack is not None and not self.usernames:
            raise ValueError("password_attack requires `usernames` to be set")
        return self


def build_wpscan_argv(params: WpscanInput) -> List[str]:
    argv: List[str] = ["wpscan", "--url", params.url, "--no-banner"]

    if params.enumerate:
        codes = ",".join(_ENUMERATE_CODE[name] for name in params.enumerate)
        argv += ["--enumerate", codes]

    argv += ["--detection-mode", params.detection_mode]
    argv += ["--plugins-detection", params.plugins_detection]
    argv += ["--plugins-version-detection", params.plugins_version_detection]

    if params.random_user_agent:
        argv.append("--random-user-agent")

    if params.password_attack:
        argv += ["--password-attack", params.password_attack]
        argv += ["--usernames", ",".join(params.usernames or [])]

    token = params.api_token or os.getenv("WPSCAN_API_TOKEN")
    if token:
        argv += ["--api-token", token]

    return argv


@tool("wpscan_executor", args_schema=WpscanInput, return_direct=False)
def execute_wpscan(
    url: str,
    enumerate: Optional[List[str]] = None,
    detection_mode: str = "mixed",
    plugins_detection: str = "aggressive",
    plugins_version_detection: str = "mixed",
    random_user_agent: bool = True,
    password_attack: Optional[str] = None,
    usernames: Optional[List[str]] = None,
    api_token: Optional[str] = None,
) -> str:
    """Run a wpscan WordPress audit and return REAL output.

    Pick parameters from the typed schema; the tool composes a safe argv
    list internally and runs wpscan via subprocess (no shell). Targets,
    usernames, and tokens are validated by Pydantic before execution.
    """
    params = WpscanInput(
        url=url,
        enumerate=enumerate if enumerate is not None else ["plugins-all", "themes-all", "users"],  # type: ignore[arg-type]
        detection_mode=detection_mode,  # type: ignore[arg-type]
        plugins_detection=plugins_detection,  # type: ignore[arg-type]
        plugins_version_detection=plugins_version_detection,  # type: ignore[arg-type]
        random_user_agent=random_user_agent,
        password_attack=password_attack,  # type: ignore[arg-type]
        usernames=usernames,
        api_token=api_token,
    )
    argv = build_wpscan_argv(params)

    print(f"\n{Fore.CYAN}[DEBUG] ========================================")
    print(f"{Fore.YELLOW}[DEBUG] Composed argv: {Fore.WHITE}{argv}")
    print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}")

    try:
        print(f"{Fore.CYAN}[DEBUG] Starting real-time output streaming...{Style.RESET_ALL}\n")
        process = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        stdout, stderr, returncode = stream_output_with_sliding_window(
            process, max_window_lines=12, timeout=600
        )

        print(f"{Fore.GREEN}[DEBUG] Command execution completed{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[DEBUG] Return code: {Fore.WHITE}{returncode}{Style.RESET_ALL}")

        output = stdout
        if stderr:
            output += f"\n\n{Fore.YELLOW}===== Errors/Warnings ====={Style.RESET_ALL}\n{stderr}"

        if returncode != 0 and not output:
            output = f"Command failed with return code {returncode}"

        print(f"{Fore.CYAN}[DEBUG] ========================================{Style.RESET_ALL}\n")
        return output if output else "No output from command"

    except subprocess.TimeoutExpired:
        error_msg = "Command timed out after 600 seconds"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return f"TIMEOUT_ERROR: {error_msg} - argv: {argv}"
    except FileNotFoundError as e:
        error_msg = f"wpscan binary not found: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg
    except Exception as e:
        error_msg = f"Error executing command: {e}"
        print(f"{Fore.RED}[DEBUG] {error_msg}{Style.RESET_ALL}")
        return error_msg


def validate_wpscan_installed() -> bool:
    """Check if wpscan is installed on the system"""
    try:
        print(f"{Fore.BLUE}[DEBUG] Checking if wpscan is installed...{Style.RESET_ALL}")
        result = subprocess.run(
            ["wpscan", "--version"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_installed = result.returncode == 0
        if is_installed:
            print(f"{Fore.GREEN}[DEBUG] wpscan is installed{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[DEBUG] wpscan is not installed{Style.RESET_ALL}")
        return is_installed
    except Exception:
        print(f"{Fore.RED}[DEBUG] Error checking wpscan installation{Style.RESET_ALL}")
        return False
