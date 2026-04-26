import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional

from colorama import init
from deepagents import create_deep_agent
from deepagents.backends import StateBackend

from llm_factory import create_llm
from v2.prompts import SUPERVISOR_SYSTEM_PROMPT
from v2.subagents import ExploitReconSubagent, ServiceDiscoverSubagent, WebScanSubagent

init(autoreset=True)


class V2DeepOrchestrator:
    """Deep Agents based orchestrator for the v2 architecture."""

    SUBAGENT_NAMES = {
        "service_discover_agent",
        "web_scan_agent",
        "exploit_recon_agent",
    }

    def __init__(
        self,
        llm: Any = None,
        agent_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.llm = llm or create_llm(temperature=0.1)
        self.agent_factory = agent_factory

        self.service_agent = ServiceDiscoverSubagent(llm=self.llm)
        self.web_agent = WebScanSubagent(llm=self.llm)
        self.exploit_recon_agent = ExploitReconSubagent(llm=self.llm)

        self._supervisor = None

    def _build_supervisor(self) -> Any:
        if self._supervisor is not None:
            return self._supervisor

        subagents = [
            self.service_agent.as_supervisor_config(),
            self.web_agent.as_supervisor_config(),
            self.exploit_recon_agent.as_supervisor_config(),
        ]

        factory = self.agent_factory or create_deep_agent
        # Note: previously this passed a deny-all FilesystemPermission. That rule
        # only restricts the named filesystem tools (write_file/edit_file) — not
        # the FilesystemMiddleware's internal eviction writes — so it added no
        # real safety while preventing the agent from using its own filesystem
        # tools. Dropped.
        self._supervisor = factory(
            model=self.llm,
            subagents=subagents,
            system_prompt=SUPERVISOR_SYSTEM_PROMPT,
            backend=StateBackend(),
            name="v2-supervisor-agent",
        )
        return self._supervisor

    @staticmethod
    def _extract_content(response: Any) -> str:
        if isinstance(response, dict) and "messages" in response and response["messages"]:
            final_message = response["messages"][-1]
            if hasattr(final_message, "content"):
                return str(final_message.content)
            return str(final_message)
        if isinstance(response, dict) and "output" in response:
            return str(response["output"])
        return str(response)

    @staticmethod
    def _message_content_to_text(content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text")
                    if text:
                        parts.append(str(text))
                else:
                    parts.append(str(item))
            return "\n".join(parts)
        return str(content)

    def _is_information_query(self, user_request: str) -> bool:
        request_lower = user_request.lower()
        info_keywords = [
            "what can",
            "capabilities",
            "help",
            "explain",
            "describe",
            "what is",
            "how does",
        ]
        execution_keywords = [
            "scan",
            "enumerate",
            "discover",
            "check",
            "assess",
            "recon",
            "exploit",
        ]
        is_info = any(keyword in request_lower for keyword in info_keywords)
        is_exec = any(keyword in request_lower for keyword in execution_keywords)
        return is_info and not is_exec

    def _answer_information_query(self) -> str:
        return (
            "V2 Deep Orchestrator capabilities:\n"
            "- Deep Agents supervisor self-plans and delegates to subagents\n"
            "- service_discover_agent: nmap and masscan for host, port, and service discovery\n"
            "- web_scan_agent: nikto and wpscan for web and WordPress assessment\n"
            "- exploit_recon_agent: Metasploit search and correlation only, with no exploit execution\n"
            "- the parent agent has no direct execution tools; only subagents do"
        )

    def _parse_json_content(self, content: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = json.loads(content)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _extract_subagent_name(self, message: Any) -> Optional[str]:
        for attr in ("name",):
            value = getattr(message, attr, None)
            if value in self.SUBAGENT_NAMES:
                return value

        for attr in ("metadata", "additional_kwargs", "response_metadata"):
            value = getattr(message, attr, None) or {}
            if not isinstance(value, dict):
                continue
            for key in ("lc_agent_name", "agent_name", "name", "subagent_name"):
                candidate = value.get(key)
                if candidate in self.SUBAGENT_NAMES:
                    return candidate

        return None

    def _extract_task_hint(self, message: Any, fallback: str) -> str:
        for attr in ("artifact", "additional_kwargs", "metadata"):
            value = getattr(message, attr, None) or {}
            if not isinstance(value, dict):
                continue
            for key in ("task", "input", "delegated_task", "prompt"):
                if value.get(key):
                    return str(value[key])
        return fallback

    def _extract_primary_target(self, structured_data: Dict[str, Any], fallback: str) -> str:
        for field in ("target", "target_url"):
            if structured_data.get(field):
                return str(structured_data[field])
        match = re.search(r"https?://[^\s]+", fallback)
        if match:
            return match.group(0)
        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", fallback)
        if match:
            return match.group(0)
        return "unknown"

    def _build_execution_history(self, response: Any, user_request: str) -> List[Dict[str, Any]]:
        if not isinstance(response, dict) or "messages" not in response:
            return []

        history: List[Dict[str, Any]] = []
        messages = response.get("messages", [])

        for message in messages:
            subagent_name = self._extract_subagent_name(message)
            if subagent_name is None:
                continue

            content = self._message_content_to_text(getattr(message, "content", ""))
            structured_data = self._parse_json_content(content)
            if structured_data is None:
                continue

            task = self._extract_task_hint(message, user_request)
            history.append(
                {
                    "agent": subagent_name,
                    "task": task,
                    "structured_data": structured_data,
                    "raw_result": content,
                    "timestamp": str(len(history)),
                    "tool_name": None,
                    "target": self._extract_primary_target(structured_data, task),
                }
            )

        return history

    @staticmethod
    def _extract_messages(data: Any) -> List[Any]:
        if isinstance(data, dict):
            messages = data.get("messages", [])
            return messages if isinstance(messages, list) else []
        return []

    @staticmethod
    def _extract_tool_calls(message: Any) -> List[Dict[str, Any]]:
        tool_calls = getattr(message, "tool_calls", None)
        if isinstance(tool_calls, list):
            return tool_calls

        additional_kwargs = getattr(message, "additional_kwargs", None) or {}
        tool_calls = additional_kwargs.get("tool_calls")
        return tool_calls if isinstance(tool_calls, list) else []

    def _track_pending_subagents(
        self, active_subagents: Dict[str, Dict[str, Any]], chunk: Dict[str, Any]
    ) -> None:
        if chunk.get("ns"):
            return
        if chunk.get("type") != "updates":
            return

        data = chunk.get("data", {})
        if not isinstance(data, dict):
            return

        model_request = data.get("model_request")
        if not isinstance(model_request, dict):
            return

        for msg in self._extract_messages(model_request):
            for tool_call in self._extract_tool_calls(msg):
                if tool_call.get("name") != "task":
                    continue
                tool_call_id = tool_call.get("id")
                if not tool_call_id or tool_call_id in active_subagents:
                    continue
                args = tool_call.get("args", {}) or {}
                subagent_type = args.get("subagent_type")
                if subagent_type not in self.SUBAGENT_NAMES:
                    continue
                active_subagents[tool_call_id] = {
                    "agent": subagent_type,
                    "task": args.get("description") or args.get("task") or "",
                    "status": "pending",
                }

    def _mark_running_subagents(
        self, active_subagents: Dict[str, Dict[str, Any]], chunk: Dict[str, Any]
    ) -> None:
        ns = chunk.get("ns") or ()
        if not ns:
            return
        if not any(str(segment).startswith("tools:") for segment in ns):
            return

        for subagent in active_subagents.values():
            if subagent["status"] == "pending":
                subagent["status"] = "running"
                break

    def _consume_completed_subagents(
        self,
        active_subagents: Dict[str, Dict[str, Any]],
        execution_history: List[Dict[str, Any]],
        chunk: Dict[str, Any],
        user_request: str,
        progress_callback=None,
    ) -> None:
        if chunk.get("ns"):
            return
        if chunk.get("type") != "updates":
            return

        data = chunk.get("data", {})
        if not isinstance(data, dict):
            return

        tools_node = data.get("tools")
        if not isinstance(tools_node, dict):
            return

        for msg in self._extract_messages(tools_node):
            if getattr(msg, "type", None) != "tool":
                continue

            tool_call_id = getattr(msg, "tool_call_id", None)
            if not tool_call_id:
                continue
            tracked = active_subagents.get(tool_call_id)
            if not tracked or tracked.get("status") == "complete":
                continue

            content = self._message_content_to_text(getattr(msg, "content", ""))
            # Subagents with response_format usually emit JSON via Pydantic
            # model_dump_json(); when they don't (e.g. agent finished without
            # populating structured_response), content is plain text. Capture
            # the step either way — the empty structured_data is fine, the
            # raw_result still feeds downstream consumers.
            structured_data = self._parse_json_content(content) or {}

            tracked["status"] = "complete"
            task = tracked.get("task") or user_request
            record = {
                "agent": tracked["agent"],
                "task": task,
                "structured_data": structured_data,
                "raw_result": content,
                "timestamp": str(len(execution_history)),
                "tool_name": getattr(msg, "name", None),
                "target": self._extract_primary_target(structured_data, task),
            }
            execution_history.append(record)

            if progress_callback:
                progress_callback({**record, "step": len(execution_history)})

    def _extract_final_response_from_chunk(
        self, chunk: Dict[str, Any], current_response: str
    ) -> str:
        if chunk.get("ns"):
            return current_response
        if chunk.get("type") != "updates":
            return current_response

        data = chunk.get("data", {})
        if not isinstance(data, dict):
            return current_response

        for node_data in data.values():
            if not isinstance(node_data, dict):
                continue
            for msg in self._extract_messages(node_data):
                if getattr(msg, "type", None) == "tool":
                    continue
                content = self._message_content_to_text(getattr(msg, "content", ""))
                if content:
                    current_response = content
        return current_response

    def _summarize_vulnerabilities(
        self, execution_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        vulnerability_details: List[str] = []
        exploitable_services: List[str] = []

        for entry in execution_history:
            structured = entry.get("structured_data", {})
            if entry["agent"] == "service_discover_agent":
                for vuln in structured.get("vulnerabilities", []):
                    vulnerability_details.append(f"Service discovery: {vuln}")
                exploitable_services.extend(structured.get("detected_services", []))
            elif entry["agent"] == "web_scan_agent":
                for vuln in structured.get("vulnerabilities", []):
                    vulnerability_details.append(f"Web scan: {vuln}")
                for misconfig in structured.get("misconfigurations", []):
                    vulnerability_details.append(f"Web misconfiguration: {misconfig}")
            elif entry["agent"] == "exploit_recon_agent":
                for candidate in structured.get("candidate_modules", []):
                    module = candidate.get("module") if isinstance(candidate, dict) else str(candidate)
                    vulnerability_details.append(f"Exploit recon candidate: {module}")
                exploitable_services.extend(structured.get("matched_services", []))

        vulnerability_details = list(dict.fromkeys(vulnerability_details))
        exploitable_services = list(dict.fromkeys(exploitable_services))

        return {
            "vulnerabilities_found": bool(vulnerability_details),
            "vulnerability_details": vulnerability_details,
            "exploitable_services": exploitable_services,
            "total_vulnerabilities": len(vulnerability_details),
        }

    def run_workflow(
        self, user_request: str, max_iterations: int = 50, progress_callback=None
    ) -> Dict[str, Any]:
        try:
            if self._is_information_query(user_request):
                return {
                    "success": True,
                    "type": "information",
                    "response": self._answer_information_query(),
                    "execution_history": [],
                }

            # Rebuild supervisor every run. deepagents' StateBackend is stateful;
            # leftover state from an aborted previous run can wedge the next one.
            self._supervisor = None
            supervisor = self._build_supervisor()
            execution_history: List[Dict[str, Any]] = []
            active_subagents: Dict[str, Dict[str, Any]] = {}
            final_response = ""

            wall_timeout = float(os.getenv("WORKFLOW_WALL_TIMEOUT", "1800"))
            deadline = time.monotonic() + wall_timeout
            wall_timed_out = False

            for chunk in supervisor.stream(
                {"messages": [{"role": "user", "content": user_request}]},
                stream_mode="updates",
                subgraphs=True,
                version="v2",
            ):
                if time.monotonic() > deadline:
                    wall_timed_out = True
                    break
                self._track_pending_subagents(active_subagents, chunk)
                self._mark_running_subagents(active_subagents, chunk)
                self._consume_completed_subagents(
                    active_subagents=active_subagents,
                    execution_history=execution_history,
                    chunk=chunk,
                    user_request=user_request,
                    progress_callback=progress_callback,
                )
                final_response = self._extract_final_response_from_chunk(
                    chunk, final_response
                )

            if wall_timed_out:
                marker = f"\n[WORKFLOW_TIMEOUT: wall-clock budget of {wall_timeout:.0f}s exceeded; partial results returned]"
                final_response = (final_response or "") + marker

            return {
                "success": bool(execution_history) or bool(final_response),
                "type": "execution",
                "response": final_response,
                "execution_history": execution_history,
                "vulnerabilities": self._summarize_vulnerabilities(execution_history),
            }
        except Exception as exc:
            return {
                "success": False,
                "type": "execution",
                "response": f"V2 orchestrator error: {exc}",
                "execution_history": [],
                "vulnerabilities": {
                    "vulnerabilities_found": False,
                    "vulnerability_details": [],
                    "exploitable_services": [],
                    "total_vulnerabilities": 0,
                },
                "error": str(exc),
            }

    def process_user_request(self, user_request: str) -> str:
        result = self.run_workflow(user_request)
        if not result.get("success") and result.get("error"):
            return f"❌ {result['error']}"
        return result.get("response", "No response generated")

    def get_available_capabilities(self) -> str:
        return self._answer_information_query()
