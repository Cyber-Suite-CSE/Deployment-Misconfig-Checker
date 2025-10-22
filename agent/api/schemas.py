"""Pydantic models for the FastAPI workflow API."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class WorkflowRequest(BaseModel):
    """Payload for kicking off the orchestrated workflow."""

    prompt: str = Field(..., description="Operator instruction, same as CLI input.")
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional client metadata echoed back in events.",
    )


class WorkflowEvent(BaseModel):
    """Structured representation of an SSE event payload."""

    type: str = Field(
        ...,
        description="Event category (log, agent_start, agent_result, workflow_complete, error, final).",
    )
    message: str = Field(
        ...,
        description="Human-readable content safe to display in UIs.",
    )
    payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured data relevant to the event (optional).",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Original request metadata echoed to the client.",
    )

