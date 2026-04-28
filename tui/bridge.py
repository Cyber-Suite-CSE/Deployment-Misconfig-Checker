"""Worker-thread <-> Textual main-loop bridge.

The orchestrator runs sync in a worker thread; the Textual ``App`` runs on the
main thread's asyncio loop. Two crossings are needed:

* ``prompt_decision`` — worker blocks on a ``Future`` while a HITL modal collects
  the user's decision on the main thread.
* ``emit`` — fire-and-forget delivery of stdout / progress events.

Both crossings go through ``App.call_from_thread``, which is the only safe way to
schedule UI work from a non-UI thread.
"""

from __future__ import annotations

from concurrent.futures import Future
from typing import Any, Dict, Optional, TYPE_CHECKING

from langgraph.types import Interrupt

from agents import sudo_secrets

if TYPE_CHECKING:
    from .app import CyberExecApp


class TUIBridge:
    def __init__(self, app: "CyberExecApp") -> None:
        self._app = app

    def prompt_decision(self, interrupt: Interrupt) -> Dict[str, Any]:
        """Called from the worker thread; blocks until the modal returns."""
        fut: "Future[Dict[str, Any]]" = Future()
        # Read the thread_id ContextVar here, *in the worker thread* where it
        # was set by ``handle_interrupt_loop``. ``call_from_thread`` runs the
        # callback on the event loop with its own context, so the modal can't
        # see the var directly — we plumb the value through instead.
        thread_id: Optional[str] = sudo_secrets.current_thread_id.get()
        self._app.call_from_thread(
            self._app.show_hitl_modal, interrupt, fut, thread_id
        )
        return fut.result()

    def emit(self, event: Dict[str, Any]) -> None:
        """Called from the worker thread; non-blocking."""
        self._app.call_from_thread(self._app.handle_worker_event, event)
