"""Human-in-the-loop helpers shared by every sub-agent.

Three responsibilities:
1. Build per-tool ``HumanInTheLoopMiddleware`` instances with dynamic descriptions.
2. Render an interrupt at the CLI and collect an approve/edit/reject decision.
3. Append the decision to a JSONL audit log.
"""

from __future__ import annotations

import getpass
import json
import os
import sys
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from colorama import Fore, Style, init
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langgraph.types import Interrupt

from agents import sudo_secrets

init(autoreset=True)


_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG_PATH = os.path.join(_PROJECT_ROOT, "logs", "hitl_decisions.jsonl")
CHECKPOINT_DB_PATH = os.path.join(_PROJECT_ROOT, ".langgraph_checkpoint.sqlite")
SESSION_STORE_PATH = os.path.join(_PROJECT_ROOT, ".langgraph_sessions.json")


# Tools no longer accept a free-form `command` string — every executor takes
# typed Pydantic fields, and the executable name is hardcoded inside the tool.


def format_rejection_message(tool_name: str, reason: str) -> str:
    """Wrap an operator's rejection reason as a directive ToolMessage body.

    The wrapped text is what the agent's LLM sees, so it reads like an
    instruction rather than a bare error string. Audit logs record the raw
    reason separately.
    """
    reason = (reason or "").strip() or "rejected by operator"
    return (
        f"OPERATOR REJECTED `{tool_name}`. Reason: {reason}\n"
        "Revise your approach using this feedback. "
        "Do NOT repeat the same tool call. "
        "If the reason supplies a corrected target, parameter, or scope, use it. "
        "If the reason is vague, ask the user via your final message instead of retrying."
    )


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

def _summarise_args(args: Dict[str, Any]) -> str:
    """Render a typed args dict as a compact key=value summary for the HITL UI."""
    parts: List[str] = []
    for key, value in args.items():
        if value is None or value == [] or value is False:
            continue
        if isinstance(value, str):
            parts.append(f"{key}={value!r}")
        elif isinstance(value, (list, tuple)):
            parts.append(f"{key}={list(value)}")
        else:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else "<no args>"


def _primary_target(args: Dict[str, Any]) -> str:
    """Pull the most user-meaningful target field out of a typed args dict."""
    for key in ("url", "target"):
        v = args.get(key)
        if isinstance(v, str) and v:
            return v
    targets = args.get("targets")
    if isinstance(targets, list) and targets:
        return ", ".join(str(t) for t in targets[:3]) + ("…" if len(targets) > 3 else "")
    for key in ("exploit_path", "cve_id", "vulnerability_keywords"):
        v = args.get(key)
        if isinstance(v, str) and v:
            return v
    return "<no target>"


def describe_nmap(tool_call, state, runtime) -> str:  # noqa: ANN001 - matches _DescriptionFactory
    args = tool_call.get("args", {}) or {}
    return (
        f"nmap_executor: SCAN {_primary_target(args)} | "
        f"{_summarise_args(args)} (intrusive — scans real network)"
    )


def describe_wpscan(tool_call, state, runtime) -> str:  # noqa: ANN001
    args = tool_call.get("args", {}) or {}
    return (
        f"wpscan_executor: WORDPRESS SCAN {_primary_target(args)} | "
        f"{_summarise_args(args)} (intrusive — probes WordPress vulns)"
    )


def describe_nikto(tool_call, state, runtime) -> str:  # noqa: ANN001
    args = tool_call.get("args", {}) or {}
    return (
        f"nikto_executor: WEB SCAN {_primary_target(args)} | "
        f"{_summarise_args(args)} (intrusive — probes web server vulns)"
    )


def describe_masscan(tool_call, state, runtime) -> str:  # noqa: ANN001
    args = tool_call.get("args", {}) or {}
    return (
        f"masscan_executor: FAST PORT SWEEP {_primary_target(args)} | "
        f"{_summarise_args(args)} (very intrusive — high packet rate, raw socket)"
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


def _edit_args(original: Dict[str, Any], *, tool_name: str) -> Dict[str, Any]:
    """Walk the typed args dict and let the operator edit each field.

    Tools no longer accept a free-form `command` string — every field is
    typed (target, ports, scan_profile, etc.) and the executable name is
    fixed inside the tool. So we just iterate keys; press Enter to keep,
    or type a new value (JSON for non-string types).
    """
    del tool_name  # retained for backwards-compatible signature
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


def _final_args_for_decision(
    decision: Dict[str, Any], original: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Return the typed args dict that will actually run for a decision.

    For ``approve`` we use the original args; for ``edit`` we take the
    post-edit args; for ``reject`` nothing runs, so we return ``None``.
    """
    if decision.get("type") == "reject":
        return None
    if decision.get("type") == "edit":
        return (decision.get("edited_action") or {}).get("args") or {}
    return original.get("args") or {}


def maybe_capture_sudo_password(
    decision: Dict[str, Any],
    request: Dict[str, Any],
    thread_id: str,
    *,
    password_reader: Callable[[str], str] = getpass.getpass,
) -> bool:
    """If the decision will execute a tool that needs root, capture the password.

    Stores the password in :mod:`agents.sudo_secrets` keyed by ``thread_id``
    and annotates the decision with ``"requires_sudo": True`` so the audit
    log can record it. Returns True if a sudo prompt was shown.

    Already-cached passwords are reused — operators don't get re-prompted on
    every privileged scan in the same session.
    """
    tool_name = (decision.get("edited_action") or {}).get("name") or request.get("name") or ""
    args = _final_args_for_decision(decision, request)
    if args is None or not sudo_secrets.args_need_root(tool_name, args):
        return False

    decision["requires_sudo"] = True
    if sudo_secrets.has_password(thread_id):
        return False

    print(
        f"  {Fore.YELLOW}[sudo] this command needs root — enter password "
        f"(stored in memory only, cleared on /clear){Style.RESET_ALL}"
    )
    try:
        pw = password_reader(f"  {Fore.YELLOW}[sudo] password > {Style.RESET_ALL}")
    except (EOFError, KeyboardInterrupt):
        print(f"  {Fore.RED}→ no password supplied; sudo will fail at runtime{Style.RESET_ALL}")
        return False
    if pw:
        sudo_secrets.set_password(thread_id, pw)
        print(f"  {Fore.GREEN}→ sudo password cached for this session{Style.RESET_ALL}")
    return True


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
            # Render the exact argv that will run, so the operator sees the
            # effective command line — including a sudo prefix when relevant.
            try:
                from tools.preview import preview_command  # local import: avoid import-time cycle
                effective = preview_command(name, args)
            except Exception:
                effective = None
            if effective:
                print(f"  {Fore.GREEN}effective:{Style.RESET_ALL} {effective}")
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
                raw_reason = _read_line(
                    f"  {Fore.RED}reason{Style.RESET_ALL} > "
                ).strip() or "rejected by operator"
                decisions.append(
                    {
                        "type": "reject",
                        "message": format_rejection_message(name, raw_reason),
                        "raw_reason": raw_reason,
                    }
                )
                print(f"  {Fore.RED}→ rejected: {raw_reason}{Style.RESET_ALL}")
                break
            if choice in ("e", "edit"):
                edited = _edit_args(args, tool_name=name)
                decisions.append(
                    {
                        "type": "edit",
                        "edited_action": {"name": name, "args": edited},
                    }
                )
                print(f"  {Fore.YELLOW}→ edited args: {edited}{Style.RESET_ALL}")
                break
            print(f"  {Fore.RED}invalid choice — type a, e, or r{Style.RESET_ALL}")

        thread_id = sudo_secrets.current_thread_id.get()
        if thread_id:
            maybe_capture_sudo_password(decisions[-1], request, thread_id)

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
                entry["reason"] = decision.get("raw_reason") or decision.get("message")
            if decision.get("requires_sudo"):
                entry["requires_sudo"] = True
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

    # Publish the thread_id on a ContextVar so:
    #  1. the prompter (CLI / TUI) can capture a sudo password into
    #     ``sudo_secrets`` keyed by this thread, and
    #  2. tool wrappers running inside LangGraph's executor can look up that
    #     password (LangGraph propagates context via ``copy_context().run``).
    sudo_secrets.current_thread_id.set(thread_id)

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
