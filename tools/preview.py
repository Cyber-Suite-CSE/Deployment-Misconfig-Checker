"""argv preview for the HITL approval flow.

Each typed-input executor has a Pydantic schema and a ``build_*_argv``
function that turns validated input into the exact argv the tool will run.
This module looks up the right pair by tool name and returns either the
argv list or a joined display string — so HITL can show the operator the
effective command line before they approve it.

Validation errors are swallowed and surface as ``None``; the HITL flow
falls back to the raw args summary in that case.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from pydantic import BaseModel

from agents import sudo_secrets

from .masscan_tool import MasscanInput, build_masscan_argv
from .nikto_tool import NiktoInput, build_nikto_argv
from .nmap_tool import NmapInput, build_nmap_argv
from .wpscan_tool import WpscanInput, build_wpscan_argv


_BUILDERS: Dict[str, Tuple[Type[BaseModel], Callable[[Any], List[str]]]] = {
    "nmap_executor": (NmapInput, build_nmap_argv),
    "wpscan_executor": (WpscanInput, build_wpscan_argv),
    "nikto_executor": (NiktoInput, build_nikto_argv),
    "masscan_executor": (MasscanInput, build_masscan_argv),
}


def preview_argv(tool_name: str, args: Dict[str, Any]) -> Optional[List[str]]:
    """Return the validated argv list for a typed-input tool call, or None."""
    builder = _BUILDERS.get(tool_name)
    if builder is None:
        return None
    schema_cls, build_fn = builder
    try:
        schema = schema_cls(**(args or {}))
    except Exception:
        return None
    argv = list(build_fn(schema))
    if sudo_secrets.args_need_root(tool_name, args or {}):
        argv = ["sudo"] + argv
    return argv


def preview_command(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    """Return the effective command-line string the tool will execute, or None."""
    argv = preview_argv(tool_name, args)
    if argv is None:
        return None
    return " ".join(argv)
