"""Textual ``App`` — minimal Claude-Code-style layout."""

from __future__ import annotations

import os
import sys
from concurrent.futures import Future
from threading import Thread
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from langgraph.types import Interrupt
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Input, Static

from agents import hitl_helpers

from .bridge import TUIBridge
from .hitl_bar import HITLBar
from .stdout_tee import TeeStdout
from .widgets import AgentStepCard, ReportCard, UserMessageCard, WelcomeCard

if TYPE_CHECKING:
    from agents.orchestrator_agent import OrchestratorAgent


class CyberExecApp(App):
    CSS = """
    Screen {
        layout: vertical;
        background: $background;
    }
    #conversation {
        height: 1fr;
        padding: 0 2;
        scrollbar-size: 0 1;
    }
    #status {
        height: 1;
        padding: 0 2;
        color: $text-muted;
    }
    #prompt-row {
        height: 2;
        border-top: solid gray;
        padding: 0 2;
        margin-bottom: 1;
        background: transparent;
    }
    #prompt-prefix {
        width: 2;
        color: #7aa2f7;
        text-style: bold;
        height: 1;
    }
    #prompt {
        border: none;
        background: transparent;
        padding: 0;
        height: 1;
        width: 1fr;
    }
    #prompt:focus {
        border: none;
        background: transparent;
    }
    #prompt.-busy {
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "request_quit", show=False),
        Binding("ctrl+d", "request_quit", show=False),
        Binding("ctrl+l", "clear_conversation", show=False),
        # HITL keys are gated by ``check_action`` below so they don't intercept
        # normal typing in the prompt or while editing inside the bar.
        Binding("a", "hitl_approve", show=False, priority=True),
        Binding("e", "hitl_edit", show=False, priority=True),
        Binding("r", "hitl_reject", show=False, priority=True),
        Binding("escape", "hitl_cancel_sub", show=False, priority=True),
        # Cursor navigation in the HITL options row (left/right also up/down).
        Binding("left", "hitl_select_prev", show=False, priority=True),
        Binding("up", "hitl_select_prev", show=False, priority=True),
        Binding("right", "hitl_select_next", show=False, priority=True),
        Binding("down", "hitl_select_next", show=False, priority=True),
        Binding("enter", "hitl_confirm", show=False, priority=True),
    ]

    IDLE_HINT = "[dim]ask anything · ? help · ⌃l clear · ⌃c quit[/dim]"

    def __init__(self, orchestrator: "OrchestratorAgent") -> None:
        super().__init__()
        self.orchestrator = orchestrator
        self.bridge = TUIBridge(self)
        self._active_card: Optional[AgentStepCard] = None
        self._cards_by_id: Dict[str, AgentStepCard] = {}
        self._busy = False
        self._hitl_bar: Optional[HITLBar] = None
        self._hitl_queue: List[Tuple[Interrupt, "Future[Dict[str, Any]]"]] = []

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="conversation")
        yield Static("", id="status")
        with Horizontal(id="prompt-row"):
            yield Static(">", id="prompt-prefix")
            yield Input(placeholder="ask anything…", id="prompt")

    def on_mount(self) -> None:
        hitl_helpers.set_prompter(self.bridge.prompt_decision)
        self._append(WelcomeCard())
        self._set_status(self.IDLE_HINT)
        self.query_one("#prompt", Input).focus()

    def on_unmount(self) -> None:
        hitl_helpers.set_prompter(None)

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "prompt":
            return
        text = event.value.strip()
        if not text:
            return
        prompt = self.query_one("#prompt", Input)
        prompt.value = ""
        if self._busy:
            return
        lower = text.lower()
        if lower in ("exit", "quit"):
            self.exit()
            return
        if lower in ("help", "?"):
            self._show_help()
            return
        if lower == "capabilities":
            self._show_capabilities()
            return
        if lower == "clear":
            self.action_clear_conversation()
            return
        self._submit_request(text)

    def _submit_request(self, text: str) -> None:
        self._append(UserMessageCard(text))
        self._set_busy(True)
        self._set_status("running…")
        Thread(
            target=self._worker_body,
            args=(text,),
            name="orchestrator-worker",
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    def _worker_body(self, text: str) -> None:
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        tee_stdout = TeeStdout(
            original_stdout,
            lambda line, cid: self.bridge.emit({"type": "stdout", "line": line, "card_id": cid}),
        )
        tee_stderr = TeeStdout(
            original_stderr,
            lambda line, cid: self.bridge.emit({"type": "stdout", "line": line, "card_id": cid}),
        )
        sys.stdout = tee_stdout
        sys.stderr = tee_stderr
        try:
            response = self.orchestrator.process_user_request(
                text,
                progress_callback=lambda entry: self.bridge.emit({"type": "step_completed", **entry}),
                step_started_callback=lambda entry: self.bridge.emit({"type": "step_started", **entry}),
            )
            self.bridge.emit({"type": "report", "markdown": response or ""})
        except Exception as exc:  # pragma: no cover
            self.bridge.emit({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            self.bridge.emit({"type": "done"})

    # ------------------------------------------------------------------
    # Worker -> UI
    # ------------------------------------------------------------------
    def handle_worker_event(self, event: Dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "step_started":
            card = AgentStepCard(
                agent=event.get("agent", "?"),
                task=event.get("task", ""),
                step=event.get("step", 0),
            )
            self._active_card = card
            card_id = event.get("card_id")
            if card_id:
                self._cards_by_id[card_id] = card
            self._append(card)
        elif kind == "step_completed":
            card_id = event.get("card_id")
            target = self._cards_by_id.get(card_id) if card_id else None
            if target is None:
                target = self._active_card_for_agent(event.get("agent"))
            if target is not None:
                target.mark_complete(event)
            if card_id:
                self._cards_by_id.pop(card_id, None)
        elif kind == "stdout":
            line = event.get("line", "")
            card_id = event.get("card_id")
            target = self._cards_by_id.get(card_id) if card_id else None
            if target is None:
                target = self._active_card
            if target is not None:
                target.append_line(line)
        elif kind == "report":
            self._append(ReportCard(event.get("markdown", "")))
        elif kind == "error":
            if self._active_card is not None:
                self._active_card.mark_failed(event.get("message", "error"))
            self._append(_ErrorLine(event.get("message", "error")))
        elif kind == "done":
            self._set_busy(False)
            self._set_status(self.IDLE_HINT)

    def _active_card_for_agent(self, agent: Optional[str]) -> Optional[AgentStepCard]:
        if self._active_card is not None and (agent is None or self._active_card.agent_name == agent):
            return self._active_card
        if agent is None:
            return None
        try:
            container = self.query_one("#conversation", VerticalScroll)
        except Exception:
            return None
        for child in reversed(list(container.children)):
            if isinstance(child, AgentStepCard) and child.agent_name == agent:
                return child
        return None

    # ------------------------------------------------------------------
    # HITL — inline (replaces the input)
    # ------------------------------------------------------------------
    def show_hitl_modal(self, interrupt: Interrupt, future: "Future[Dict[str, Any]]") -> None:
        if self._hitl_bar is not None:
            # Another tool is already waiting on the operator. Queue this one
            # so its worker thread keeps blocking on its Future until we get
            # to it — without this the Future would never resolve and the
            # parallel tool call would hang indefinitely.
            self._hitl_queue.append((interrupt, future))
            return
        self._mount_hitl(interrupt, future)

    def _mount_hitl(self, interrupt: Interrupt, future: "Future[Dict[str, Any]]") -> None:
        prompt_row = self.query_one("#prompt-row")
        prompt_row.display = False
        bar = HITLBar(interrupt, future, on_done=self._hide_hitl)
        self._hitl_bar = bar
        self.mount(bar, after=self.query_one("#status", Static))

    def _hide_hitl(self) -> None:
        if self._hitl_bar is None:
            return
        bar = self._hitl_bar
        self._hitl_bar = None
        bar.remove()
        if self._hitl_queue:
            next_interrupt, next_future = self._hitl_queue.pop(0)
            self._mount_hitl(next_interrupt, next_future)
            return
        prompt_row = self.query_one("#prompt-row")
        prompt_row.display = True
        if not self._busy:
            self.query_one("#prompt", Input).focus()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _append(self, widget) -> None:
        try:
            container = self.query_one("#conversation", VerticalScroll)
        except Exception:
            return
        container.mount(widget)
        container.scroll_end(animate=False)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        prompt = self.query_one("#prompt", Input)
        prompt.disabled = busy
        if busy:
            prompt.add_class("-busy")
        else:
            prompt.remove_class("-busy")
            if self._hitl_bar is None:
                prompt.focus()

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#status", Static).update(text)
        except Exception:
            pass

    def _show_help(self) -> None:
        text = (
            "[dim]commands[/dim]  help  ·  capabilities  ·  clear  ·  exit\n"
            "[dim]examples[/dim]  scan localhost  ·  scan WordPress site https://example.com"
        )
        self._append(_HelpLine(text))

    def _show_capabilities(self) -> None:
        try:
            caps = self.orchestrator.get_available_capabilities()
        except Exception as exc:
            caps = f"(failed to fetch capabilities: {exc})"
        self._append(_HelpLine(caps))

    # ------------------------------------------------------------------
    # Bindings
    # ------------------------------------------------------------------
    def check_action(self, action: str, parameters):  # type: ignore[override]
        """Gate HITL bindings by bar state so they don't swallow normal keystrokes."""
        if action.startswith("hitl_"):
            bar = self._hitl_bar
            if bar is None:
                return False
            if action == "hitl_cancel_sub":
                return bar.mode in ("edit", "reject")
            # approve / edit / reject — only active in choose mode so the user
            # can still type those characters in the inline edit/reject input.
            return bar.mode == "choose"
        return True

    def action_hitl_approve(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_approve()

    def action_hitl_edit(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_edit()

    def action_hitl_reject(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_reject()

    def action_hitl_cancel_sub(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_cancel_subprompt()

    def action_hitl_select_prev(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_select_prev()

    def action_hitl_select_next(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_select_next()

    def action_hitl_confirm(self) -> None:
        if self._hitl_bar is not None:
            self._hitl_bar.action_confirm()

    def action_request_quit(self) -> None:
        self.exit()

    def action_clear_conversation(self) -> None:
        if self._busy:
            return
        try:
            container = self.query_one("#conversation", VerticalScroll)
        except Exception:
            return
        for child in list(container.children):
            child.remove()
        self._active_card = None
        self._cards_by_id.clear()


class _HelpLine(Static):
    DEFAULT_CSS = """
    _HelpLine {
        margin-top: 1;
        height: auto;
        color: $text;
    }
    """


class _ErrorLine(Static):
    DEFAULT_CSS = """
    _ErrorLine {
        margin-top: 1;
        height: auto;
        color: $error;
    }
    """

    def __init__(self, message: str) -> None:
        super().__init__(f"[dim]error[/dim] {message}")


def run_tui(orchestrator: "OrchestratorAgent") -> None:
    """Launch the TUI for an already-initialised ``OrchestratorAgent``."""
    if not sys.stdout.isatty() and not os.environ.get("TEXTUAL"):
        raise RuntimeError("--tui requires an interactive terminal (stdout is not a TTY)")
    CyberExecApp(orchestrator).run()
