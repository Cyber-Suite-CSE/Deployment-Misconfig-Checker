"""Textual TUI front-end for the multi-agent cybersecurity system.

Public surface: ``run_tui(orchestrator)``. Lives behind the ``--tui`` flag in
``main.py``; the classic CLI path is untouched when this package is not imported.
"""

from .app import run_tui

__all__ = ["run_tui"]
