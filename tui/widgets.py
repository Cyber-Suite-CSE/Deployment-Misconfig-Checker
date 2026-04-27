"""Conversation widgets — minimal, glyph-based, no boxes."""

from __future__ import annotations

from typing import Any, Dict, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Markdown, RichLog, Static

_AGENT_LABELS = {
    "nmap": "nmap",
    "wpscan": "wpscan",
    "nikto": "nikto",
    "metasploit": "msf",
}


class UserMessageCard(Static):
    DEFAULT_CSS = """
    UserMessageCard {
        margin-top: 1;
        height: auto;
    }
    """

    def __init__(self, text: str) -> None:
        super().__init__(f"[dim]>[/dim] {text}")


class WelcomeCard(Static):
    """First-run greeting. Stays in the scrollback as conversation grows."""

    DEFAULT_CSS = """
    WelcomeCard {
        margin-top: 1;
        height: auto;
        color: $text;
    }
    """

    BODY = (
        "[bold]cyberexec[/bold]   [dim]multi-agent cybersecurity[/dim]\n"
        "\n"
        "[dim]real commands · human approval gates each tool[/dim]\n"
        "\n"
        "[dim]try:[/dim]\n"
        "  scan localhost\n"
        "  scan https://example.com for vulnerabilities\n"
        "  find Metasploit modules for CVE-2017-0144\n"
        "\n"
        "[dim]help · capabilities · clear · exit[/dim]"
    )

    def __init__(self) -> None:
        super().__init__(self.BODY)


class AgentStepCard(Vertical):
    """One agent step as a chevron + title line, with output streaming below.

    Title color states (driven by class):
        running — accent ($warning)
        done    — dim
        failed  — error
    Chevron: ``▾`` when expanded, ``▸`` when collapsed. Click the title to toggle.
    Auto-collapses on success so completed steps don't dominate the conversation;
    failures stay expanded for visibility.
    """

    DEFAULT_CSS = """
    AgentStepCard {
        height: auto;
        margin-top: 1;
    }
    AgentStepCard > .title {
        height: 1;
    }
    AgentStepCard > .title:hover {
        text-style: underline;
    }
    AgentStepCard.-running > .title { color: $warning; }
    AgentStepCard.-done    > .title { color: $text-muted; }
    AgentStepCard.-failed  > .title { color: $error; }
    AgentStepCard > RichLog {
        height: auto;
        max-height: 12;
        padding: 0 0 0 2;
        background: transparent;
        border: none;
        scrollbar-size: 0 0;
        color: $text-muted;
    }
    AgentStepCard.-collapsed > RichLog {
        display: none;
    }
    AgentStepCard > .result {
        padding-left: 2;
        color: $text-muted;
        height: auto;
    }
    AgentStepCard.-collapsed > .result {
        display: none;
    }
    """

    def __init__(self, agent: str, task: str, step: int) -> None:
        super().__init__()
        self.agent_name = agent
        self.agent_task = task
        self.agent_step = step
        self._title: Optional[Static] = None
        self._log: Optional[RichLog] = None
        self._result: Optional[Static] = None
        self.add_class("-running")

    def compose(self) -> ComposeResult:
        self._title = Static(self._title_text(), classes="title")
        yield self._title
        self._log = RichLog(
            highlight=False, markup=False, auto_scroll=True, wrap=True, max_lines=2000
        )
        yield self._log
        self._result = Static("", classes="result")
        yield self._result

    def append_line(self, line: str) -> None:
        if self._log is None:
            return
        try:
            self._log.write(Text.from_ansi(line))
        except Exception:
            self._log.write(line)

    def mark_complete(self, entry: Dict[str, Any]) -> None:
        executed = entry.get("executed", False)
        success = entry.get("success", False)
        ok = bool(executed and success)
        self.remove_class("-running")
        self.add_class("-done" if ok else "-failed")
        if ok:
            self.add_class("-collapsed")
        self._refresh_title()

    def mark_failed(self, message: str) -> None:
        self.remove_class("-running")
        self.add_class("-failed")
        self.agent_task = message
        self._refresh_title()

    def on_click(self) -> None:
        if self.has_class("-collapsed"):
            self.remove_class("-collapsed")
        else:
            self.add_class("-collapsed")
        self._refresh_title()

    def _refresh_title(self) -> None:
        if self._title is not None:
            self._title.update(self._title_text())

    def _title_text(self) -> str:
        chevron = "▸" if self.has_class("-collapsed") else "▾"
        label = _AGENT_LABELS.get(self.agent_name, self.agent_name)
        return f"{chevron} {label} [dim]·[/dim] {self._truncate(self.agent_task, 80)}"

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 1] + "…"


class ReportCard(Vertical):
    """Final supervisor synthesis — Markdown under a thin separator."""

    DEFAULT_CSS = """
    ReportCard {
        height: auto;
        margin-top: 1;
    }
    ReportCard > .sep {
        color: $text-muted;
        height: 1;
    }
    ReportCard > Markdown {
        margin: 0;
        padding: 0;
        background: transparent;
    }
    """

    def __init__(self, markdown: str) -> None:
        super().__init__()
        self._markdown = markdown or "_(no synthesis produced)_"

    def compose(self) -> ComposeResult:
        yield Static("─ final ─", classes="sep")
        yield Markdown(self._markdown)
