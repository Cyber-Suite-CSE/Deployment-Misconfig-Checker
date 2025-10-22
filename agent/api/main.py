"""FastAPI application exposing the orchestrator workflow via Server-Sent Events."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import AsyncIterator

if __package__ is None or __name__ == "__main__":
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from dotenv import load_dotenv  # noqa: E402
from fastapi import FastAPI, HTTPException, Request, status  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from sse_starlette.sse import EventSourceResponse  # noqa: E402
import uvicorn  # noqa: E402

from api.schemas import WorkflowRequest  # noqa: E402
from api.orchestrator_streaming import stream_workflow  # noqa: E402

# Ensure .env values are available when the module is imported.
load_dotenv()

app = FastAPI(
    title="Agent Workflow API",
    description="Serve the multi-agent cybersecurity workflow over SSE.",
    version="0.1.0",
)


@app.get("/healthz", summary="Service health probe")
async def healthcheck() -> JSONResponse:
    """Simple readiness endpoint."""
    return JSONResponse(
        {
            "status": "ok",
            "requires_google_api_key": bool(os.getenv("GOOGLE_API_KEY")),
            "requires_msf_password": bool(os.getenv("MSF_PASSWORD")),
        }
    )


@app.post(
    "/workflows/run",
    summary="Kick off an agentic workflow and stream progress via SSE",
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_workflow_endpoint(payload: WorkflowRequest, request: Request) -> EventSourceResponse:
    """
    Start the orchestrator workflow for a given prompt and stream Server-Sent Events.
    """
    if not os.getenv("GOOGLE_API_KEY"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GOOGLE_API_KEY missing. Configure the environment before running workflows.",
        )

    async def event_publisher() -> AsyncIterator[str]:
        async for frame in stream_workflow(payload):
            if await request.is_disconnected():
                break
            yield frame

    return EventSourceResponse(event_publisher(), media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run("agent.api.main:app", host="0.0.0.0", port=8000, reload=False)
