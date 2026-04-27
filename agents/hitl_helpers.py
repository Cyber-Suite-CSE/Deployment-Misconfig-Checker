"""Human-in-the-loop helpers shared by every sub-agent.

Three responsibilities:
1. Build per-tool ``HumanInTheLoopMiddleware`` instances with dynamic descriptions.
2. Render an interrupt at the CLI and collect an approve/edit/reject decision.
3. Append the decision to a JSONL audit log.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from colorama import Fore, Style, init
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langgraph.types import Interrupt

init(autoreset=True)


_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG_PATH = os.path.join(_PROJECT_ROOT, "logs", "hitl_decisions.jsonl")
CHECKPOINT_DB_PATH = os.path.join(_PROJECT_ROOT, ".langgraph_checkpoint.sqlite")


def get_checkpointer(*, db_path: str = CHECKPOINT_DB_PATH):
    """Open a fresh SqliteSaver against the shared project checkpoint DB.

    Each caller gets its own ``sqlite3.Connection`` so connections don't cross
    threads. Safe to call repeatedly — SQLite handles concurrent writers.
    """
    import sqlite3
    from langgraph.checkpoint.sqlite import SqliteSaver

    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    return SqliteSaver(conn)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_URL_RE = re.compile(r"https?://[^\s'\"]+")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


def _extract_target(text: str) -> str:
    for matcher in (_URL_RE, _IP_RE, _DOMAIN_RE):
        m = matcher.search(text)
        if m:
            return m.group(0)
    return "<no target found>"


def _extract_command(args: Dict[str, Any]) -> str:
    for key in ("command", "cmd", "url", "target"):
        if key in args and isinstance(args[key], str):
            return args[key]
    return json.dumps(args, default=str)


def describe_nmap(tool_call, state, runtime) -> str:  # noqa: ANN001 - matches _DescriptionFactory
    cmd = _extract_command(tool_call.get("args", {}))
    target = _extract_target(cmd)
    return (
        f"nmap_executor: SCAN {target} | command='{cmd}' "
        f"(intrusive — scans real network)"
    )


def describe_wpscan(tool_call, state, runtime) -> str:  # noqa: ANN001
    cmd = _extract_command(tool_call.get("args", {}))
    target = _extract_target(cmd)
    return (
        f"wpscan_executor: WORDPRESS SCAN {target} | command='{cmd}' "
        f"(intrusive — probes WordPress vulns)"
    )


def describe_nikto(tool_call, state, runtime) -> str:  # noqa: ANN001
    cmd = _extract_command(tool_call.get("args", {}))
    target = _extract_target(cmd)
    return (
        f"nikto_executor: WEB SCAN {target} | command='{cmd}' "
        f"(intrusive — probes web server vulns)"
    )


def build_hitl(
    tool_name: str,
    describer: Callable[..., str],
    *,
    description_prefix: str = "Tool execution requires approval",
) -> HumanInTheLoopMiddleware:
    """Build a HumanInTheLoopMiddleware that gates a single tool with all 3 decisions."""
    return HumanInTheLoopMiddleware(
        interrupt_on={
            tool_name: {
                "allowed_decisions": ["approve", "edit", "reject"],
                "description": describer,
            }
        },
        description_prefix=description_prefix,
    )


def build_passive_hitl(tool_names: List[str]) -> HumanInTheLoopMiddleware:
    """Auto-approve every named tool (for read-only RPC lookups like MSF passive)."""
    return HumanInTheLoopMiddleware(
        interrupt_on={name: False for name in tool_names},
    )


def _read_line(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""


def _edit_args(original: Dict[str, Any]) -> Dict[str, Any]:
    print(
        f"{Fore.YELLOW}[HITL] Edit mode — press Enter to keep current value{Style.RESET_ALL}"
    )
    edited: Dict[str, Any] = {}
    for key, value in original.items():
        current = json.dumps(value, default=str) if not isinstance(value, str) else value
        print(f"  {Fore.CYAN}{key}{Style.RESET_ALL} = {Fore.WHITE}{current}{Style.RESET_ALL}")
        new_raw = _read_line(f"  new {key} > ").strip()
        if not new_raw:
            edited[key] = value
            continue
        if isinstance(value, str):
            edited[key] = new_raw
        else:
            try:
                edited[key] = json.loads(new_raw)
            except (ValueError, json.JSONDecodeError):
                edited[key] = new_raw
    return edited


_prompter: Optional[Callable[[Interrupt], Dict[str, Any]]] = None


def set_prompter(fn: Optional[Callable[[Interrupt], Dict[str, Any]]]) -> None:
    """Install a custom interrupt prompter (e.g. a TUI). Pass None to restore CLI."""
    global _prompter
    _prompter = fn


def prompt_for_decision(interrupt: Interrupt) -> Dict[str, Any]:
    """Dispatch to the active prompter (TUI if registered, else CLI)."""
    if _prompter is not None:
        return _prompter(interrupt)
    return _cli_prompt_for_decision(interrupt)


def _cli_prompt_for_decision(interrupt: Interrupt) -> Dict[str, Any]:
    """Render an interrupt at the CLI and return a Command(resume=...) payload.

    Decisions are returned in the same order as ``interrupt.value['action_requests']``.
    """
    payload = interrupt.value or {}
    action_requests = payload.get("action_requests") or []

    if not action_requests:
        return {"decisions": []}

    decisions: List[Dict[str, Any]] = []

    print()
    print(
        f"{Fore.MAGENTA}╔══════════════ HUMAN APPROVAL REQUIRED ══════════════╗{Style.RESET_ALL}"
    )
    print(
        f"{Fore.MAGENTA}║ {len(action_requests)} pending action(s){' ' * 36}║{Style.RESET_ALL}"
    )
    print(
        f"{Fore.MAGENTA}╚════════════════════════════════════════════════════╝{Style.RESET_ALL}"
    )

    for idx, request in enumerate(action_requests, start=1):
        name = request.get("name", "<unknown_tool>")
        args = request.get("args", {}) or {}
        description = request.get("description", "")

        print(
            f"\n{Fore.YELLOW}[{idx}/{len(action_requests)}] {Fore.CYAN}{name}{Style.RESET_ALL}"
        )
        if description:
            print(f"  {Fore.WHITE}{description}{Style.RESET_ALL}")
        if args:
            print(f"  {Fore.YELLOW}args:{Style.RESET_ALL} {json.dumps(args, default=str, indent=2)}")
        print(
            f"  {Fore.RED}EXECUTE?{Style.RESET_ALL} "
            f"({Fore.GREEN}a{Style.RESET_ALL})pprove / "
            f"({Fore.YELLOW}e{Style.RESET_ALL})dit / "
            f"({Fore.RED}r{Style.RESET_ALL})eject"
        )

        while True:
            choice = _read_line("  > ").strip().lower()
            if choice in ("a", "approve", ""):
                decisions.append({"type": "approve"})
                print(f"  {Fore.GREEN}→ approved{Style.RESET_ALL}")
                break
            if choice in ("r", "reject"):
                reason = _read_line(
                    f"  {Fore.RED}reason{Style.RESET_ALL} > "
                ).strip() or "rejected by operator"
                decisions.append({"type": "reject", "message": reason})
                print(f"  {Fore.RED}→ rejected: {reason}{Style.RESET_ALL}")
                break
            if choice in ("e", "edit"):
                edited = _edit_args(args)
                decisions.append(
                    {
                        "type": "edit",
                        "edited_action": {"name": name, "args": edited},
                    }
                )
                print(f"  {Fore.YELLOW}→ edited args: {edited}{Style.RESET_ALL}")
                break
            print(f"  {Fore.RED}invalid choice — type a, e, or r{Style.RESET_ALL}")

    return {"decisions": decisions}


def audit_log(
    decisions_payload: Dict[str, Any],
    action_requests: List[Dict[str, Any]],
    thread_id: str,
    *,
    log_path: str = AUDIT_LOG_PATH,
) -> int:
    """Append one JSONL line per decision. Returns count written."""
    decisions = decisions_payload.get("decisions", [])
    if not decisions:
        return 0
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    written = 0
    with open(log_path, "a", encoding="utf-8") as fh:
        for decision, request in zip(decisions, action_requests):
            entry = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "thread_id": thread_id,
                "tool": request.get("name"),
                "original_args": request.get("args"),
                "description": request.get("description"),
                "decision": decision.get("type"),
            }
            if decision.get("type") == "edit":
                entry["edited_args"] = (
                    decision.get("edited_action", {}).get("args")
                )
            elif decision.get("type") == "reject":
                entry["reason"] = decision.get("message")
            fh.write(json.dumps(entry, default=str) + "\n")
            written += 1
    return written


def handle_interrupt_loop(
    invoke_fn: Callable[..., Any],
    *,
    initial_input: Any,
    config: Dict[str, Any],
    thread_id: str,
) -> Any:
    """Drive an agent through any number of HITL interrupts until completion.

    ``invoke_fn`` is the agent's ``.invoke`` method. We pass ``initial_input``
    on the first call, then ``Command(resume=...)`` on each subsequent call
    until the response no longer contains ``__interrupt__``.

    Returns the final agent result dict.
    """
    from langgraph.types import Command  # local import keeps top of file lean

    next_input: Any = initial_input
    while True:
        result = invoke_fn(next_input, config=config)
        interrupts = []
        if isinstance(result, dict):
            interrupts = result.get("__interrupt__") or []
        if not interrupts:
            return result
        # We only handle the first interrupt; the agent will surface the next on resume.
        first = interrupts[0]
        if not isinstance(first, Interrupt):
            # Older runtimes pass a list/tuple of Interrupts under __interrupt__
            try:
                first = first[0]  # type: ignore[index]
            except Exception:  # pragma: no cover - defensive
                return result
        decisions_payload = prompt_for_decision(first)
        written = audit_log(
            decisions_payload,
            (first.value or {}).get("action_requests", []),
            thread_id,
        )
        if written:
            print(
                f"{Fore.BLUE}[Audit] {written} decision(s) logged for thread {thread_id[:8]}{Style.RESET_ALL}"
            )
        next_input = Command(resume=decisions_payload)
