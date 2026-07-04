"""Inline session-resume panel — takes over the prompt slot for `/resume`.

Mirrors the ``HITLBar`` pattern (key handling lives on the parent App, see
``BINDINGS`` / ``check_action`` there) so cursor navigation works without
fighting focus on a non-focusable ``Vertical`` container.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static


class ResumeBar(Vertical):
    DEFAULT_CSS = """
    ResumeBar {
        height: auto;
        padding: 0 2;
        margin: 0;
    }
    ResumeBar > .sep {
        color: $text-muted;
        height: 1;
    }
    ResumeBar > .row {
        height: 1;
        color: $text-muted;
        padding: 0 1;
    }
    ResumeBar > .row.-cursor {
        color: $text;
        background: $accent 20%;
        text-style: bold;
    }
    ResumeBar > .hint {
        color: $text-muted;
        height: 1;
    }
    """

    def __init__(
        self,
        sessions: List[Dict[str, Any]],
        on_select: Callable[[str], None],
        on_cancel: Callable[[], None],
    ) -> None:
        super().__init__()
        self._sessions = sessions
        self._on_select = on_select
        self._on_cancel = on_cancel
        self._idx = 0

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static("─ resume session ─", classes="sep")
        for i in range(len(self._sessions)):
            yield Static("", id=f"resume-row-{i}", classes="row")
        yield Static(
            "[dim]↑↓ navigate · ↵ select · esc cancel[/dim]",
            classes="hint",
        )

    def on_mount(self) -> None:
        if not self._sessions:
            self._on_cancel()
            return
        self._refresh_view()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _refresh_view(self) -> None:
        for i, entry in enumerate(self._sessions):
            try:
                row = self.query_one(f"#resume-row-{i}", Static)
            except Exception:
                continue
            text = self._format_row(entry)
            cursor = "›" if i == self._idx else " "
            row.update(f"{cursor} {text}")
            if i == self._idx:
                row.add_class("-cursor")
            else:
                row.remove_class("-cursor")

    @staticmethod
    def _format_row(entry: Dict[str, Any]) -> str:
        tid = (entry.get("thread_id") or "")[:8]
        updated = (entry.get("updated_at") or "")[:19].replace("T", " ")
        turns = entry.get("turn_count", 0)
        first = (entry.get("first_message") or "").replace("\n", " ")
        if len(first) > 60:
            first = first[:57] + "..."
        return f"[cyan]{tid}[/cyan]  {updated}  turns={turns}  {first}"

    # ------------------------------------------------------------------
    # Bindings (driven from the parent App)
    # ------------------------------------------------------------------
    def action_prev(self) -> None:
        if not self._sessions:
            return
        self._idx = (self._idx - 1) % len(self._sessions)
        self._refresh_view()

    def action_next(self) -> None:
        if not self._sessions:
            return
        self._idx = (self._idx + 1) % len(self._sessions)
        self._refresh_view()

    def action_confirm(self) -> None:
        if not self._sessions:
            self._on_cancel()
            return
        thread_id = self._sessions[self._idx].get("thread_id", "")
        self._on_select(thread_id)

    def action_cancel(self) -> None:
        self._on_cancel()
