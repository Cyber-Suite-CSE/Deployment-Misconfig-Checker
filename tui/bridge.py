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
from typing import Any, Dict, TYPE_CHECKING

from langgraph.types import Interrupt

if TYPE_CHECKING:
    from .app import CyberExecApp


class TUIBridge:
    def __init__(self, app: "CyberExecApp") -> None:
        self._app = app

    def prompt_decision(self, interrupt: Interrupt) -> Dict[str, Any]:
        """Called from the worker thread; blocks until the modal returns."""
        fut: "Future[Dict[str, Any]]" = Future()
        self._app.call_from_thread(self._app.show_hitl_modal, interrupt, fut)
        return fut.result()

    def emit(self, event: Dict[str, Any]) -> None:
        """Called from the worker thread; non-blocking."""
        self._app.call_from_thread(self._app.handle_worker_event, event)
