"""Per-step routing context for the TUI.

Sub-agent threads inherit this ``ContextVar`` because LangGraph's executor
submits work via ``contextvars.copy_context().run(...)`` — so a card id set in
the dispatcher thread is visible to the worker thread that actually runs the
gated tool. ``TeeStdout`` reads it to route ``print()`` output to the right
``AgentStepCard`` even under parallel tool calls.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

current_card_id: ContextVar[Optional[str]] = ContextVar(
    "tui_current_card_id", default=None
)
