"""Adapters to run the CLI orchestrator workflow in a streaming context."""

from __future__ import annotations

import asyncio
import re
from contextlib import redirect_stdout, redirect_stderr
from typing import AsyncIterator, Optional, Dict, Any

from agents.orchestrator_agent import OrchestratorAgent
from api.schemas import WorkflowRequest, WorkflowEvent

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def strip_ansi(value: str) -> str:
    """Remove ANSI color codes to keep SSE payloads clean."""
    return ANSI_RE.sub("", value)


class EventPublisher:
    """Thread-safe helper that converts events into SSE frames."""

    def __init__(
        self,
        queue: "asyncio.Queue[str]",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.queue = queue
        self.metadata = metadata

    def emit(
        self,
        event_type: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Serialize an event and push it onto the queue."""
        event = WorkflowEvent(
            type=event_type,
            message=message,
            payload=payload,
            metadata=self.metadata,
        )
        frame = f"data: {event.model_dump_json()}\n\n"
        self.queue.put_nowait(frame)

    def log(self, line: str) -> None:
        """Emit a log event after stripping ANSI sequences."""
        cleaned = strip_ansi(line).strip()
        if cleaned:
            payload: Dict[str, Any] = {}
            # Surface lightweight structure for downstream UIs.
            if cleaned.startswith("[Orchestrator] Next Agent:"):
                payload["agent_hint"] = cleaned.split(":", 1)[1].strip()
                event_type = "agent_planning"
            elif "Initializing execution system" in cleaned:
                event_type = "status"
            elif cleaned.startswith("[NMAP") or cleaned.startswith("[WPSCAN") or cleaned.startswith("[NIKTO"):
                event_type = "agent_log"
            elif cleaned.startswith("[Metasploit"):
                event_type = "agent_log"
            else:
                event_type = "log"
            self.emit(event_type=event_type, message=cleaned, payload=payload or None)


class StreamingStdOut:
    """File-like object that forwards stdout writes into SSE events."""

    def __init__(self, publisher: EventPublisher) -> None:
        self.publisher = publisher
        self._buffer = ""

    def write(self, data: str) -> int:
        if not data:
            return 0
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self.publisher.log(line)
        return len(data)

    def flush(self) -> None:
        if self._buffer:
            self.publisher.log(self._buffer)
            self._buffer = ""


async def stream_workflow(request: WorkflowRequest) -> AsyncIterator[str]:
    """
    Execute the orchestrator workflow and yield SSE frames as they become available.
    """
    queue: "asyncio.Queue[Optional[str]]" = asyncio.Queue()
    publisher = EventPublisher(queue, request.metadata)
    loop = asyncio.get_running_loop()

    def run_orchestrator() -> None:
        """Blocking workflow execution inside a thread."""
        try:
            publisher.emit("status", "Initializing orchestrator")
            orchestrator = OrchestratorAgent()
            publisher.emit("status", "Orchestrator ready")

            with redirect_stdout(StreamingStdOut(publisher)), redirect_stderr(
                StreamingStdOut(publisher)
            ):
                final_response = orchestrator.process_user_request(request.prompt)

            cleaned_response = strip_ansi(final_response).strip()
            publisher.emit(
                "final",
                cleaned_response,
                payload={"final_response": cleaned_response},
            )
            publisher.emit(
                "workflow_complete",
                "Workflow finished successfully",
                payload={"final_response": cleaned_response},
            )
        except Exception as exc:  # noqa: BLE001
            publisher.emit("error", f"Workflow failed: {exc}")
        finally:
            queue.put_nowait(None)

    future = loop.run_in_executor(None, run_orchestrator)

    try:
        while True:
            frame = await queue.get()
            if frame is None:
                break
            yield frame
    finally:
        await future
