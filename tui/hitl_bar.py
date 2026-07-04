"""Inline approval bar — takes over the input slot during a HITL interrupt.

Four internal modes:
- ``choose``         a / e / r bindings active; arrow keys move the selection
                     cursor; Enter activates the cursor's option
- ``edit``           Input is focused, cycles through args one at a time
- ``reject``         Input is focused, captures a single reason string
- ``sudo_password``  Masked Input is focused, captures a sudo password for the
                     current session when the just-approved command needs root

The bar resolves the worker's ``Future`` with the same payload shape the
LangGraph runtime expects: ``{"decisions": [...]}`` in the order of
``interrupt.value["action_requests"]``.
"""

from __future__ import annotations

import json
from concurrent.futures import Future
from typing import Any, Callable, Dict, List, Optional

from langgraph.types import Interrupt
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Static

from agents import sudo_secrets
from agents.hitl_helpers import format_rejection_message


class HITLBar(Vertical):
    """Inline HITL bar.

    Key handling lives on the parent ``CyberExecApp`` (see ``BINDINGS`` /
    ``check_action`` there) because ``Vertical`` containers do not reliably take
    focus and the (hidden) prompt ``Input`` can otherwise swallow keys. The
    ``approve`` / ``edit`` / ``reject`` / ``cancel_subprompt`` methods below are
    invoked by the app's action handlers.
    """

    DEFAULT_CSS = """
    HITLBar {
        height: auto;
        padding: 0 2;
        margin: 0;
    }
    HITLBar > .sep {
        color: $text-muted;
        height: 1;
    }
    HITLBar > .title {
        color: $warning;
        height: 1;
    }
    HITLBar > .body {
        color: $text-muted;
        height: auto;
    }
    HITLBar > .actions {
        color: $text-muted;
        height: 1;
    }
    HITLBar > .hint {
        color: $text-muted;
        height: 1;
    }
    HITLBar > Input {
        border: none;
        padding: 0 0;
        margin: 0;
        background: transparent;
        height: 1;
    }
    HITLBar > Input:focus {
        border: none;
    }
    """

    def __init__(
        self,
        interrupt: Interrupt,
        future: "Future[Dict[str, Any]]",
        on_done: Callable[[], None],
        thread_id: Optional[str] = None,
    ) -> None:
        super().__init__()
        self._future = future
        self._on_done = on_done
        self._thread_id = thread_id
        payload = interrupt.value or {}
        self._action_requests: List[Dict[str, Any]] = list(payload.get("action_requests") or [])
        self._decisions: List[Optional[Dict[str, Any]]] = [None] * len(self._action_requests)
        self._idx = 0
        self._mode = "choose"
        self._edit_keys: List[str] = []
        self._edit_idx = 0
        self._edited: Dict[str, Any] = {}
        # 0=approve, 1=edit, 2=reject
        self._selected_idx = 0
        self._option_actions = ("approve", "edit", "reject")

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static("─ approval needed ─", classes="sep")
        yield Static("", id="hitl-title", classes="title")
        yield Static("", id="hitl-body", classes="body")
        yield Static("", id="hitl-actions", classes="actions")
        yield Static("", id="hitl-hint", classes="hint")
        inp = Input(id="hitl-input")
        inp.display = False
        yield inp
        # Separate masked input for sudo password capture; kept distinct from
        # the main input so we don't have to flip ``password=True`` at runtime
        # (Textual handles ``password`` as a constructor param more reliably).
        pw_inp = Input(id="hitl-sudo-input", password=True)
        pw_inp.display = False
        yield pw_inp

    @property
    def mode(self) -> str:
        return self._mode

    def on_mount(self) -> None:
        if not self._action_requests:
            self._finish()
            return
        self._refresh_view()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _refresh_view(self) -> None:
        title = self.query_one("#hitl-title", Static)
        body = self.query_one("#hitl-body", Static)
        actions = self.query_one("#hitl-actions", Static)
        hint = self.query_one("#hitl-hint", Static)
        inp = self.query_one("#hitl-input", Input)
        pw_inp = self.query_one("#hitl-sudo-input", Input)
        # Default: hide the sudo input; the sudo_password branch turns it on.
        pw_inp.display = False

        if self._mode == "choose":
            req = self._action_requests[self._idx]
            name = req.get("name", "<unknown>")
            description = req.get("description", "") or ""
            args = req.get("args", {}) or {}
            summary = description or self._extract_command(args)
            effective = self._effective_command(name, args)
            total = len(self._action_requests)
            counter = f" [{self._idx + 1}/{total}]" if total > 1 else ""
            title.update(f"{name}{counter}")
            body_lines = [self._truncate(summary, 200)]
            if effective:
                body_lines.append(
                    f"[green]effective:[/green] {self._truncate(effective, 200)}"
                )
            body.update("\n".join(body_lines))
            body.display = True
            actions.update(self._render_options())
            actions.display = True
            hint.update("[dim]←→ navigate · ↵ select · a/e/r shortcut[/dim]")
            hint.display = True
            inp.display = False
            return

        if self._mode == "edit":
            req = self._action_requests[self._idx]
            args = req.get("args", {}) or {}
            key = self._edit_keys[self._edit_idx]
            current = self._edited.get(key, args.get(key))
            tool_name = req.get("name", "")
            initial = current if isinstance(current, str) else json.dumps(current, default=str)
            placeholder = key
            body_text = f"{key} ({self._edit_idx + 1}/{len(self._edit_keys)})"
            title.update(f"edit · {tool_name or '<unknown>'}")
            body.update(body_text)
            body.display = True
            actions.update("")
            actions.display = False
            hint.update("[dim]↵ next · esc cancel[/dim]")
            hint.display = True
            inp.display = True
            inp.value = initial
            inp.placeholder = placeholder
            inp.focus()
            return

        if self._mode == "reject":
            req = self._action_requests[self._idx]
            title.update(f"reject · {req.get('name', '<unknown>')}")
            body.update("")
            body.display = False
            actions.update("")
            actions.display = False
            hint.update("[dim]↵ submit · esc cancel[/dim]")
            hint.display = True
            inp.display = True
            inp.value = ""
            inp.placeholder = "reason"
            inp.focus()
            return

        if self._mode == "sudo_password":
            req = self._action_requests[self._idx]
            tool_name = req.get("name", "<unknown>")
            title.update(f"sudo password · {tool_name}")
            body.update(
                "[dim]this command needs root — password is held in memory "
                "for this session only and cleared on /clear[/dim]"
            )
            body.display = True
            actions.update("")
            actions.display = False
            hint.update("[dim]↵ submit · esc skip (tool will fail)[/dim]")
            hint.display = True
            inp.display = False
            pw_inp.display = True
            pw_inp.value = ""
            pw_inp.placeholder = "sudo password"
            pw_inp.focus()

    def _render_options(self) -> str:
        labels = ("approve", "edit", "reject")
        parts: List[str] = []
        for i, label in enumerate(labels):
            if i == self._selected_idx:
                parts.append(f"[bold reverse]‹ {label} ›[/bold reverse]")
            else:
                parts.append(f"[dim]  {label}  [/dim]")
        return "    ".join(parts)

    # ------------------------------------------------------------------
    # Bindings
    # ------------------------------------------------------------------
    def action_approve(self) -> None:
        if self._mode != "choose":
            return
        self._decisions[self._idx] = {"type": "approve"}
        self._after_decision()

    def action_edit(self) -> None:
        if self._mode != "choose":
            return
        req = self._action_requests[self._idx]
        args = req.get("args", {}) or {}
        if not args:
            self._decisions[self._idx] = {"type": "approve"}
            self._after_decision()
            return
        self._edit_keys = list(args.keys())
        self._edit_idx = 0
        self._edited = {}
        self._mode = "edit"
        self._refresh_view()

    def action_reject(self) -> None:
        if self._mode != "choose":
            return
        self._mode = "reject"
        self._refresh_view()

    def action_cancel_subprompt(self) -> None:
        if self._mode in ("edit", "reject"):
            self._mode = "choose"
            self._edit_keys = []
            self._edit_idx = 0
            self._edited = {}
            self._refresh_view()
        elif self._mode == "sudo_password":
            # Operator chose not to enter a password. The decision still
            # stands; the tool will return a clear "no password cached" error
            # if it actually tries to elevate.
            self._mode = "choose"
            self._advance()

    def action_select_prev(self) -> None:
        if self._mode != "choose":
            return
        self._selected_idx = (self._selected_idx - 1) % len(self._option_actions)
        self._refresh_view()

    def action_select_next(self) -> None:
        if self._mode != "choose":
            return
        self._selected_idx = (self._selected_idx + 1) % len(self._option_actions)
        self._refresh_view()

    def action_confirm(self) -> None:
        if self._mode != "choose":
            return
        choice = self._option_actions[self._selected_idx]
        if choice == "approve":
            self.action_approve()
        elif choice == "edit":
            self.action_edit()
        elif choice == "reject":
            self.action_reject()

    # ------------------------------------------------------------------
    # Input submission
    # ------------------------------------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id not in ("hitl-input", "hitl-sudo-input"):
            return
        event.stop()
        if self._mode == "edit":
            req = self._action_requests[self._idx]
            args = req.get("args", {}) or {}
            key = self._edit_keys[self._edit_idx]
            raw = event.value
            original = args.get(key)
            if isinstance(original, str):
                self._edited[key] = raw
            else:
                try:
                    self._edited[key] = json.loads(raw)
                except (ValueError, json.JSONDecodeError):
                    self._edited[key] = raw
            self._edit_idx += 1
            if self._edit_idx >= len(self._edit_keys):
                merged = {**args, **self._edited}
                self._decisions[self._idx] = {
                    "type": "edit",
                    "edited_action": {"name": req.get("name"), "args": merged},
                }
                self._mode = "choose"
                self._edit_keys = []
                self._edit_idx = 0
                self._edited = {}
                self._after_decision()
            else:
                self._refresh_view()
        elif self._mode == "sudo_password":
            password = event.value
            if password and self._thread_id:
                sudo_secrets.set_password(self._thread_id, password)
                # Mark the decision so audit_log records ``requires_sudo``;
                # password itself stays only in ``sudo_secrets`` (in-memory).
                if self._decisions[self._idx] is not None:
                    self._decisions[self._idx]["requires_sudo"] = True
            # Wipe the widget's buffer so the password doesn't linger in the
            # rendered tree — sudo_secrets is now the single source of truth.
            event.input.value = ""
            self._mode = "choose"
            self._advance()
        elif self._mode == "reject":
            req = self._action_requests[self._idx]
            tool_name = req.get("name", "")
            raw_reason = event.value.strip() or "rejected by operator"
            self._decisions[self._idx] = {
                "type": "reject",
                "message": format_rejection_message(tool_name, raw_reason),
                "raw_reason": raw_reason,
            }
            self._mode = "choose"
            self._advance()

    # ------------------------------------------------------------------
    # Internal flow
    # ------------------------------------------------------------------
    def _after_decision(self) -> None:
        """Run between a finished decision and the move to the next request.

        If the just-finished decision will execute a command that needs root
        and we don't already have a password cached for this thread, switch
        to ``sudo_password`` mode to capture one. Otherwise advance.
        """
        decision = self._decisions[self._idx]
        request = self._action_requests[self._idx]
        if decision and self._needs_sudo_password(decision, request):
            self._mode = "sudo_password"
            self._refresh_view()
            return
        self._advance()

    def _needs_sudo_password(
        self, decision: Dict[str, Any], request: Dict[str, Any]
    ) -> bool:
        if decision.get("type") == "reject":
            return False
        if not self._thread_id:
            return False
        if sudo_secrets.has_password(self._thread_id):
            return False
        if decision.get("type") == "edit":
            args = (decision.get("edited_action") or {}).get("args") or {}
            tool_name = (decision.get("edited_action") or {}).get("name") or ""
        else:
            tool_name = request.get("name") or ""
            args = request.get("args") or {}
        return sudo_secrets.args_need_root(tool_name, args)

    def _advance(self) -> None:
        self._idx += 1
        self._selected_idx = 0
        if self._idx >= len(self._action_requests):
            self._finish()
        else:
            self._refresh_view()

    def _finish(self) -> None:
        decisions = [d for d in self._decisions if d is not None]
        if not self._future.done():
            self._future.set_result({"decisions": decisions})
        self._on_done()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_command(args: Dict[str, Any]) -> str:
        """Render a one-line preview of the typed args dict for the HITL bar."""
        for key in ("url", "target"):
            v = args.get(key)
            if isinstance(v, str) and v:
                return v
        targets = args.get("targets")
        if isinstance(targets, list) and targets:
            return ", ".join(str(t) for t in targets[:3]) + ("…" if len(targets) > 3 else "")
        try:
            return json.dumps(args, default=str)
        except Exception:
            return str(args)

    @staticmethod
    def _effective_command(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
        """Render the exact argv that will run, or None on validation error."""
        try:
            from tools.preview import preview_command  # local: avoid import cycle
            return preview_command(tool_name, args)
        except Exception:
            return None

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 1] + "…"
