"""In-memory sudo password store + per-tool root detection.

Passwords are scoped to a LangGraph ``thread_id`` and never persisted. They are
cleared on ``/clear``, on session timeout, and on app exit.

The HITL flow stores a password here after the operator approves a privileged
tool call; the tool wrapper then reads it via :func:`get` and feeds it to
``sudo -S`` on stdin. The audit log records that sudo was used; the password
itself is never logged or written to disk.

A :class:`ContextVar` exposes the current thread_id to tools running inside
LangGraph's executor — the executor uses ``copy_context().run(...)`` to
propagate context into tool-execution threads, which is the same channel the
TUI's ``current_card_id`` already rides on.
"""

from __future__ import annotations

import os
import re
import threading
from contextvars import ContextVar
from typing import Dict, Optional

current_thread_id: ContextVar[Optional[str]] = ContextVar(
    "sudo_current_thread_id", default=None
)

_lock = threading.Lock()
_secrets: Dict[str, str] = {}


def set_password(thread_id: str, password: str) -> None:
    """Cache the sudo password for ``thread_id`` (in-memory only)."""
    if not thread_id:
        return
    with _lock:
        _secrets[thread_id] = password


def get_password(thread_id: Optional[str]) -> Optional[str]:
    """Return the cached password for ``thread_id`` (or ``None`` if absent)."""
    if not thread_id:
        return None
    with _lock:
        return _secrets.get(thread_id)


def has_password(thread_id: Optional[str]) -> bool:
    return get_password(thread_id) is not None


def clear(thread_id: str) -> None:
    """Drop the cached password for one thread (``/clear``, session end)."""
    with _lock:
        _secrets.pop(thread_id, None)


def clear_all() -> None:
    """Drop every cached password (app exit)."""
    with _lock:
        _secrets.clear()


# Patterns that require root because nmap needs raw socket access for them.
_NMAP_ROOT_PATTERNS = [
    r'-O\b', r'--osscan', r'-sS\b', r'-sA\b', r'-sW\b', r'-sM\b', r'-sU\b',
    r'-sN\b', r'-sF\b', r'-sX\b', r'--scanflags', r'-sY\b', r'-sZ\b',
    r'--traceroute', r'-PA(?:\d|$)', r'-PS(?:\d|$)', r'-PU\b', r'-PY\b',
    r'--ip-options', r'--spoof-mac',
]
_NMAP_ROOT_RE = re.compile('|'.join(_NMAP_ROOT_PATTERNS), re.IGNORECASE)

# masscan crafts raw packets, so anything beyond help/version/regress needs root.
_MASSCAN_INFO_RE = re.compile(
    r'(?:^|\s)(--help|-h|--version|-V|--regress)(?:\s|$)', re.IGNORECASE
)


def is_root() -> bool:
    """True if the current process already has root (skip prompts entirely)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def command_needs_root(tool_name: str, command: str) -> bool:
    """Return True iff executing ``command`` under ``tool_name`` needs sudo.

    Used by both the HITL flow (to know when to capture a password) and the
    tool wrappers (to know when to invoke ``sudo -S``).
    """
    if is_root():
        return False
    if not isinstance(command, str):
        return False
    if tool_name == "nmap_executor":
        return bool(_NMAP_ROOT_RE.search(command))
    if tool_name == "masscan_executor":
        if command.strip().startswith("man "):
            return False
        return not bool(_MASSCAN_INFO_RE.search(command))
    return False


def extract_command(tool_name: str, args: Dict[str, object]) -> Optional[str]:
    """Pull the executable command string out of a tool's args dict.

    Mirrors :func:`agents.hitl_helpers._extract_command` but without the JSON
    fallback — returns ``None`` when no command-shaped value is present so
    callers can skip the root check entirely.
    """
    if not isinstance(args, dict):
        return None
    for key in ("command", "cmd"):
        v = args.get(key)
        if isinstance(v, str):
            return v
    return None
