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
from textual.suggester import SuggestFromList
from textual.widgets import Input, Static

from agents import hitl_helpers, sudo_secrets

from .bridge import TUIBridge
from .hitl_bar import HITLBar
from .resume_bar import ResumeBar
from .stdout_tee import TeeStdout
from .widgets import AgentStepCard, ReportCard, UserMessageCard, WelcomeCard


class CommandInput(Input):
    """Input that also accepts the suggester's completion when Tab is pressed.

    Textual's stock ``Input`` already accepts suggestions on Right/End via
    ``action_cursor_right`` (it applies ``self._suggestion`` when the cursor is
    at end of input). We just route Tab to the same action.
    """

    BINDINGS = [Binding("tab", "cursor_right", show=False)]

if TYPE_CHECKING:
    from agents.orchestrator_agent import OrchestratorAgent


_DISPATCHER_TO_AGENT = {
    "run_nmap_agent": "nmap",
    "run_wpscan_agent": "wpscan",
    "run_nikto_agent": "nikto",
    "run_msf_passive_agent": "metasploit",
}


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
        # Resume bar — same keys, different actions, gated by check_action so
        # they only fire when the resume bar is visible (HITL bar is not).
        Binding("up", "resume_prev", show=False, priority=True),
        Binding("down", "resume_next", show=False, priority=True),
        Binding("enter", "resume_confirm", show=False, priority=True),
        Binding("escape", "resume_cancel", show=False, priority=True),
    ]

    IDLE_HINT = "[dim]ask anything · ? help · /clear new · /resume continue · ⌃c quit[/dim]"

    COMMAND_SUGGESTIONS = [
        "/clear",
        "/resume",
        "help",
        "capabilities",
        "exit",
        "quit",
    ]

    def __init__(self, orchestrator: "OrchestratorAgent") -> None:
        super().__init__()
        self.orchestrator = orchestrator
        self.bridge = TUIBridge(self)
        self._active_card: Optional[AgentStepCard] = None
        self._cards_by_id: Dict[str, AgentStepCard] = {}
        self._busy = False
        self._hitl_bar: Optional[HITLBar] = None
        self._hitl_queue: List[
            Tuple[Interrupt, "Future[Dict[str, Any]]", Optional[str]]
        ] = []
        self._resume_bar: Optional[ResumeBar] = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield VerticalScroll(id="conversation")
        yield Static("", id="status")
        with Horizontal(id="prompt-row"):
            yield Static(">", id="prompt-prefix")
            yield CommandInput(
                placeholder="ask anything…",
                id="prompt",
                suggester=SuggestFromList(self.COMMAND_SUGGESTIONS, case_sensitive=False),
            )

    def on_mount(self) -> None:
        hitl_helpers.set_prompter(self.bridge.prompt_decision)
        self._append(WelcomeCard())
        sid = self.orchestrator.current_session_id()[:8]
        self._append(_HelpLine(f"[dim]session[/dim] {sid}"))
        self._set_status(self.IDLE_HINT)
        self.query_one("#prompt", Input).focus()

    def on_unmount(self) -> None:
        hitl_helpers.set_prompter(None)
        # Drop every cached sudo password on app exit. ``sudo_secrets`` is
        # process-local in-memory, but be explicit so we don't rely on the
        # interpreter shutting down promptly.
        sudo_secrets.clear_all()

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
        if lower == "/clear":
            sudo_secrets.clear_all()
            new_id = self.orchestrator.new_session()
            self.action_clear_conversation()
            self._append(WelcomeCard())
            self._append(_HelpLine(f"[dim]session[/dim] new {new_id[:8]}"))
            self._set_status(self.IDLE_HINT)
            return
        if lower == "/resume" or lower.startswith("/resume "):
            self._handle_resume(text[len("/resume"):].strip())
            return
        self._submit_request(text)

    def _handle_resume(self, arg: str) -> None:
        if arg:
            self._do_resume(arg)
            return
        current = self.orchestrator.current_session_id()
        sessions = [
            s for s in self.orchestrator.list_sessions()
            if s.get("thread_id") != current
        ]
        if not sessions:
            self._append(_HelpLine("[dim]no other sessions to resume[/dim]"))
            return
        self._show_resume_bar(sessions)

    # ------------------------------------------------------------------
    # Resume bar — inline picker (replaces the input)
    # ------------------------------------------------------------------
    def _show_resume_bar(self, sessions: List[Dict[str, Any]]) -> None:
        if self._resume_bar is not None or self._hitl_bar is not None:
            return
        prompt_row = self.query_one("#prompt-row")
        prompt_row.display = False
        bar = ResumeBar(
            sessions=sessions,
            on_select=self._on_resume_select,
            on_cancel=self._hide_resume_bar,
        )
        self._resume_bar = bar
        self.mount(bar, after=self.query_one("#status", Static))

    def _on_resume_select(self, thread_id: str) -> None:
        resolved = self.orchestrator.resume_session(thread_id) if thread_id else None
        self._hide_resume_bar()
        if not resolved:
            self._append(_HelpLine("[red]could not resume session[/red]"))
            return
        self._do_resume(resolved)

    def _do_resume(self, id_or_prefix: str) -> None:
        """Common path for both `/resume <id>` and panel-pick: resolve, clear, replay."""
        resolved = self.orchestrator.resume_session(id_or_prefix)
        if not resolved:
            self._append(_HelpLine(f"[red]no session found matching[/red] {id_or_prefix!r}"))
            return
        self.action_clear_conversation()
        self._append(_HelpLine(f"[dim]session[/dim] resumed {resolved[:8]}"))
        messages = self.orchestrator.get_session_messages(resolved)
        if messages:
            self._replay_messages(messages)
        else:
            self._append(_HelpLine("[dim](no prior messages stored)[/dim]"))

    def _replay_messages(self, messages: List[Any]) -> None:
        """Render past UserMessageCard / AgentStepCard / ReportCard widgets from stored state.

        Stored tool messages carry only the structured JSON the supervisor saw — sub-agent
        stdout (the [DEBUG] lines streamed live) was never persisted, so replayed cards
        show the call + result but no per-line scrollback.
        """
        tool_results: Dict[str, Any] = {}
        for m in messages:
            tcid = getattr(m, "tool_call_id", None)
            if tcid:
                tool_results[tcid] = m

        for msg in messages:
            cls_name = msg.__class__.__name__
            content = self._extract_text(getattr(msg, "content", None))
            if cls_name in ("HumanMessage", "Human"):
                if content:
                    self._append(UserMessageCard(content))
                continue
            if cls_name in ("AIMessage", "AI", "AIMessageChunk"):
                tool_calls = getattr(msg, "tool_calls", None) or []
                for tc in tool_calls:
                    name = (tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "")) or ""
                    args = (tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})) or {}
                    tc_id = (tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")) or ""
                    agent = _DISPATCHER_TO_AGENT.get(name, name or "agent")
                    task = args.get("task") if isinstance(args, dict) else str(args)
                    card = AgentStepCard(agent=agent, task=task or "", step=0)
                    self._append(card)
                    if tc_id in tool_results:
                        card.mark_complete({"executed": True, "success": True})
                    else:
                        card.mark_failed("(no result recorded)")
                if content and not tool_calls:
                    self._append(ReportCard(content))
                continue
            # ToolMessage handled via the tool_results map above.

    @staticmethod
    def _extract_text(content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for chunk in content:
                if isinstance(chunk, dict):
                    text = chunk.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                elif isinstance(chunk, str):
                    parts.append(chunk)
            return "".join(parts)
        return str(content)

    def _hide_resume_bar(self) -> None:
        if self._resume_bar is None:
            return
        bar = self._resume_bar
        self._resume_bar = None
        bar.remove()
        prompt_row = self.query_one("#prompt-row")
        prompt_row.display = True
        if not self._busy and self._hitl_bar is None:
            self.query_one("#prompt", Input).focus()

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
    def show_hitl_modal(
        self,
        interrupt: Interrupt,
        future: "Future[Dict[str, Any]]",
        thread_id: Optional[str] = None,
    ) -> None:
        if self._hitl_bar is not None:
            # Another tool is already waiting on the operator. Queue this one
            # so its worker thread keeps blocking on its Future until we get
            # to it — without this the Future would never resolve and the
            # parallel tool call would hang indefinitely.
            self._hitl_queue.append((interrupt, future, thread_id))
            return
        self._mount_hitl(interrupt, future, thread_id)

    def _mount_hitl(
        self,
        interrupt: Interrupt,
        future: "Future[Dict[str, Any]]",
        thread_id: Optional[str] = None,
    ) -> None:
        prompt_row = self.query_one("#prompt-row")
        prompt_row.display = False
        bar = HITLBar(
            interrupt, future, on_done=self._hide_hitl, thread_id=thread_id
        )
        self._hitl_bar = bar
        self.mount(bar, after=self.query_one("#status", Static))

    def _hide_hitl(self) -> None:
        if self._hitl_bar is None:
            return
        bar = self._hitl_bar
        self._hitl_bar = None
        bar.remove()
        if self._hitl_queue:
            next_interrupt, next_future, next_thread_id = self._hitl_queue.pop(0)
            self._mount_hitl(next_interrupt, next_future, next_thread_id)
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
        sid = self.orchestrator.current_session_id()[:8]
        text = (
            "[dim]commands[/dim]  help  ·  capabilities  ·  /clear  ·  /resume [id]  ·  exit\n"
            f"[dim]session[/dim]  {sid}\n"
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
        """Gate HITL/resume bindings by bar state so they don't swallow normal keystrokes."""
        if action.startswith("hitl_"):
            bar = self._hitl_bar
            if bar is None:
                return False
            if action == "hitl_cancel_sub":
                return bar.mode in ("edit", "reject", "sudo_password")
            # approve / edit / reject — only active in choose mode so the user
            # can still type those characters in the inline edit/reject input.
            return bar.mode == "choose"
        if action.startswith("resume_"):
            return self._resume_bar is not None and self._hitl_bar is None
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

    def action_resume_prev(self) -> None:
        if self._resume_bar is not None:
            self._resume_bar.action_prev()

    def action_resume_next(self) -> None:
        if self._resume_bar is not None:
            self._resume_bar.action_next()

    def action_resume_confirm(self) -> None:
        if self._resume_bar is not None:
            self._resume_bar.action_confirm()

    def action_resume_cancel(self) -> None:
        if self._resume_bar is not None:
            self._resume_bar.action_cancel()

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
