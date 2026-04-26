"""V1: Monolithic single-agent design.

One ReAct agent owns all security tools (nmap, nikto, wpscan, metasploit-passive).
No orchestrator, no per-tool structured output parsing, no retry logic. Raw tool
output flows back into the agent's context as-is — this is the design whose
failure modes V2 was built to address.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain.chat_models import init_chat_model
from langgraph.prebuilt import create_react_agent

from tools.nmap_tool import execute_nmap
from tools.wpscan_tool import execute_wpscan
from tools.nikto_tool import execute_nikto
from tools.metasploit_passive_tool import (
    list_available_exploits,
    get_exploit_details,
    search_exploits_by_cve,
)


SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent / "system_prompt.txt"


def _serialize_message(msg: Any) -> dict:
    """Best-effort serialization of a LangChain message for trace dumps."""
    msg_type = getattr(msg, "type", type(msg).__name__)
    content = getattr(msg, "content", str(msg))
    tool_calls = getattr(msg, "tool_calls", None)
    return {
        "type": msg_type,
        "content": str(content)[:2000],
        "tool_calls": tool_calls if tool_calls else None,
    }


class SingleSecurityAgent:
    """Single ReAct agent with every security tool bound to it.

    The paper's V1 baseline. Uses GPT-4o by default (matching the paper's
    methodology section); pass `model` and `temperature` to override.
    """

    DEFAULT_MODEL = "gpt-4o"
    DEFAULT_TEMPERATURE = 0.0
    DEFAULT_RECURSION_LIMIT = 30

    def __init__(
        self,
        model: str | None = None,
        temperature: float | None = None,
        recursion_limit: int | None = None,
    ):
        self.model = model or self.DEFAULT_MODEL
        self.temperature = self.DEFAULT_TEMPERATURE if temperature is None else temperature
        self.recursion_limit = recursion_limit or self.DEFAULT_RECURSION_LIMIT

        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is required for V1 (uses OpenAI per the paper). "
                "Set it in your .env file."
            )

        self.llm = init_chat_model(
            self.model, model_provider="openai", temperature=self.temperature
        )

        # All four tools attached to one agent — the V1 design point.
        self.tools = [
            execute_nmap,
            execute_nikto,
            execute_wpscan,
            list_available_exploits,
            get_exploit_details,
            search_exploits_by_cve,
        ]

        self.system_prompt = SYSTEM_PROMPT_PATH.read_text()
        self.agent = create_react_agent(self.llm, self.tools)

    def process_request(self, request: str) -> dict[str, Any]:
        """Invoke the single agent on a natural-language request.

        Returns a dict containing the final assistant message, the full message
        trace (serialized), and wall-clock duration. The eval harness adds the
        tool-call trace separately via the recorder.
        """
        messages = [
            ("system", self.system_prompt),
            ("human", request),
        ]
        start = time.perf_counter()
        result = self.agent.invoke(
            {"messages": messages},
            config={"recursion_limit": self.recursion_limit},
        )
        elapsed = time.perf_counter() - start

        all_messages = result.get("messages", [])
        final = all_messages[-1] if all_messages else None
        final_content = getattr(final, "content", str(final)) if final else ""

        return {
            "final_message": str(final_content),
            "all_messages": [_serialize_message(m) for m in all_messages],
            "wall_clock_seconds": elapsed,
            "model": self.model,
            "temperature": self.temperature,
            "recursion_limit": self.recursion_limit,
        }
