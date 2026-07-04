"""Textual TUI front-end for the multi-agent cybersecurity system.

Public surface: ``run_tui(orchestrator)``. Lives behind the ``--tui`` flag in
``main.py``; the classic CLI path is untouched when this package is not imported.

``run_tui`` is loaded lazily so that lightweight modules (``tui.context``) can
be imported by the orchestrator without pulling in Textual.
"""

__all__ = ["run_tui"]


def run_tui(orchestrator):  # noqa: ANN001 — thin lazy shim
    from .app import run_tui as _run_tui

    return _run_tui(orchestrator)
