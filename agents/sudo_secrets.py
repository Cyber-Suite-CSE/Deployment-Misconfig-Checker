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


def is_root() -> bool:
    """True if the current process already has root (skip prompts entirely)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# Tools whose typed inputs always require raw-socket / kernel privileges.
_ALWAYS_ROOT_TOOLS = {"masscan_executor"}

# nmap fields that imply raw-socket scans.
_NMAP_ROOT_PROFILES = {"comprehensive", "stealth"}


def args_need_root(tool_name: str, args: Dict[str, object]) -> bool:
    """Return True iff a typed-args call to ``tool_name`` needs sudo.

    Used by both the HITL flow (to know when to capture a password) and the
    tool wrappers (to know when to invoke ``sudo -S``).
    """
    if is_root():
        return False
    if not isinstance(args, dict):
        return False
    if tool_name in _ALWAYS_ROOT_TOOLS:
        return True
    if tool_name == "nmap_executor":
        if args.get("os_detection") is True:
            return True
        profile = args.get("scan_profile")
        if isinstance(profile, str) and profile in _NMAP_ROOT_PROFILES:
            return True
        return False
    return False


