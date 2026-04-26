"""Tool-call interception via @tool .func monkey-patching.

Both V1 (single agent, all tools) and V2 (orchestrator + sub-agents) eventually
invoke the same underlying tool callables. By wrapping their `.func` attribute
inside a context manager, we capture every tool call regardless of which agent
made it — no need to thread callbacks through the agent code.
"""

from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterator

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.nmap_tool import execute_nmap
from tools.wpscan_tool import execute_wpscan
from tools.nikto_tool import execute_nikto
from tools.metasploit_passive_tool import (
    list_available_exploits,
    get_exploit_details,
    search_exploits_by_cve,
)


RECORDED_TOOLS = [
    execute_nmap,
    execute_wpscan,
    execute_nikto,
    list_available_exploits,
    get_exploit_details,
    search_exploits_by_cve,
]


def _stringify(value: Any, limit: int = 500) -> str:
    s = str(value)
    return s if len(s) <= limit else s[:limit] + f"…<truncated {len(s) - limit} chars>"


@contextmanager
def record_tool_calls() -> Iterator[list[dict]]:
    """Wrap every tool's underlying function so we can log invocations.

    Yields a list that gets appended to as tools are called. The list is the
    canonical trace for the metrics layer.
    """
    calls: list[dict] = []
    originals: list[tuple[Any, Any]] = []

    for tool_obj in RECORDED_TOOLS:
        original_func = tool_obj.func
        originals.append((tool_obj, original_func))

        def _make_wrapper(t, original):
            def wrapped(*args, **kwargs):
                start = time.perf_counter()
                err: str | None = None
                output: Any = None
                try:
                    output = original(*args, **kwargs)
                    return output
                except Exception as exc:  # noqa: BLE001 — record then re-raise
                    err = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    duration = time.perf_counter() - start
                    calls.append(
                        {
                            "tool": t.name,
                            "args": list(args),
                            "kwargs": kwargs,
                            "started_at": start,
                            "duration_s": duration,
                            "output_len": len(str(output)) if output is not None else 0,
                            "output_preview": _stringify(output),
                            "error": err,
                        }
                    )

            return wrapped

        tool_obj.func = _make_wrapper(tool_obj, original_func)

    try:
        yield calls
    finally:
        for tool_obj, original in originals:
            tool_obj.func = original
