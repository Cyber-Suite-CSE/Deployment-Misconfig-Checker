import os
from typing import List, Dict, Any
from uuid import uuid4

from langchain.agents import create_agent
from colorama import init, Fore, Style
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.metasploit_passive_tool import (
    list_available_exploits,
    get_exploit_details,
    search_exploits_by_cve,
)
from models.structured_results import MetasploitResult, ExploitInfo
from llm_factory import create_llm
from prompts import PromptProvider
from agents.hitl_helpers import (
    build_passive_hitl,
    get_checkpointer,
    handle_interrupt_loop,
)

init(autoreset=True)

try:
    from langchain_core.messages import ToolMessage
except ImportError:  # Fallback for older langchain versions
    ToolMessage = None

METASPLOIT_PASSIVE_AGENT_PROMPT = PromptProvider.get_agent_prompt(
    "metasploit_passive", "system"
)


class MetasploitPassiveAgent:
    """Passive Metasploit agent for exploit reconnaissance without execution"""

    def __init__(self, llm=None):
        """Initialize the passive Metasploit agent with LLM"""
        print(
            f"{Fore.GREEN}[MetasploitPassiveAgent] Initializing Metasploit Reconnaissance Agent (PASSIVE MODE){Style.RESET_ALL}"
        )

        if llm is None:
            self.llm = create_llm(temperature=0.1)
        else:
            self.llm = llm

        self.tools = [
            list_available_exploits,
            get_exploit_details,
            search_exploits_by_cve,
        ]

        print(
            f"{Fore.BLUE}[MetasploitPassiveAgent] Tools loaded: list_available_exploits, get_exploit_details, search_exploits_by_cve{Style.RESET_ALL}"
        )
        print(
            f"{Fore.YELLOW}[MetasploitPassiveAgent] PASSIVE MODE - Will NOT execute any exploits{Style.RESET_ALL}"
        )

        system_prompt = METASPLOIT_PASSIVE_AGENT_PROMPT.format(
            skill=PromptProvider.get_skill("metasploit_passive"),
        )

        # Read-only RPC lookups — auto-approve all 3 tools so the operator isn't
        # prompted on every search. The middleware is wired uniformly anyway, so
        # adding active modules later is one config change.
        self.agent_executor = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            middleware=[
                build_passive_hitl(
                    [
                        "list_available_exploits",
                        "get_exploit_details",
                        "search_exploits_by_cve",
                    ]
                )
            ],
            checkpointer=get_checkpointer(),
        )

    def process_request(
        self, user_request: str, vulnerability_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Process a reconnaissance request to find potential exploits

        Args:
            user_request: The exploitation reconnaissance task
            vulnerability_data: Dict containing target IP and vulnerabilities found

        Returns:
            Dictionary containing exploit recommendations
        """
        print(
            f"{Fore.CYAN}[MetasploitPassiveAgent] ========================================"
        )
        print(
            f"{Fore.YELLOW}[MetasploitPassiveAgent] RECONNAISSANCE REQUEST: {Fore.WHITE}{user_request}"
        )
        print(
            f"{Fore.CYAN}[MetasploitPassiveAgent] ========================================{Style.RESET_ALL}"
        )

        try:
            enriched_request = user_request

            if vulnerability_data:
                enriched_request += "\n\n=== VULNERABILITY DATA ==="

                if "target" in vulnerability_data:
                    enriched_request += f"\nTarget: {vulnerability_data['target']}"

                if (
                    "vulnerabilities" in vulnerability_data
                    and vulnerability_data["vulnerabilities"]
                ):
                    enriched_request += f"\nVulnerabilities Found:"
                    for vuln in vulnerability_data["vulnerabilities"][:10]:
                        enriched_request += f"\n  - {vuln}"

                if "services" in vulnerability_data and vulnerability_data["services"]:
                    enriched_request += f"\nServices Detected:"
                    for service in vulnerability_data["services"][:10]:
                        enriched_request += f"\n  - {service}"

                if "wordpress_version" in vulnerability_data:
                    enriched_request += f"\nWordPress Version: {vulnerability_data['wordpress_version']}"

                if "plugins" in vulnerability_data and vulnerability_data["plugins"]:
                    enriched_request += f"\nPlugins Found:"
                    for plugin in vulnerability_data["plugins"][:10]:
                        enriched_request += f"\n  - {plugin}"

            print(
                f"{Fore.CYAN}[MetasploitPassiveAgent] Processing with enriched context...{Style.RESET_ALL}"
            )

            thread_id = uuid4().hex
            response = handle_interrupt_loop(
                self.agent_executor.invoke,
                initial_input={"messages": [("user", enriched_request)]},
                config={"configurable": {"thread_id": thread_id}},
                thread_id=thread_id,
            )

            result_messages = response.get("messages", []) if isinstance(response, dict) else []

            tool_used = False
            for msg in result_messages:
                msg_type = getattr(msg, "type", "")
                if msg_type == "tool":
                    tool_used = True
                if ToolMessage and isinstance(msg, ToolMessage):
                    tool_used = True

            final_response = ""
            for msg in result_messages:
                if hasattr(msg, "content"):
                    content = str(msg.content)
                    if content and len(content) > 10:
                        final_response = content

            if not final_response:
                final_response = "No exploit reconnaissance results generated"

            debug_detected = any(
                "[DEBUG]" in str(getattr(msg, "content", "")) for msg in result_messages
            )
            executed = tool_used or debug_detected

            print(
                f"{Fore.GREEN}[MetasploitPassiveAgent] Reconnaissance complete!{Style.RESET_ALL}"
            )
            print(
                f"{Fore.CYAN}[MetasploitPassiveAgent] ========================================{Style.RESET_ALL}"
            )

            structured_result = self._parse_to_structured_result(
                final_response, user_request
            )

            return {
                "success": True,
                "executed": executed,
                "result": final_response,
                "request": user_request,
                "structured_result": structured_result,
                "passive_mode": True,
            }

        except Exception as e:
            error_msg = f"Error in MetasploitPassiveAgent: {str(e)}"
            print(f"{Fore.RED}[MetasploitPassiveAgent] {error_msg}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": error_msg,
                "result": str(e),
                "executed": False,
                "request": user_request,
                "passive_mode": True,
            }

    def _parse_to_structured_result(
        self, raw_output: str, request: str
    ) -> MetasploitResult:
        """Parse raw output into structured MetasploitResult"""
        exploits = []
        exploit_pattern = r"(exploit/[^\s\n]+|auxiliary/[^\s\n]+)"
        exploit_matches = re.findall(exploit_pattern, raw_output)

        for exploit_path in set(exploit_matches):
            desc_pattern = f"{re.escape(exploit_path)}[^\n]*Description:([^\n]+)"
            desc_match = re.search(desc_pattern, raw_output)
            description = desc_match.group(1).strip() if desc_match else ""

            exploits.append(
                ExploitInfo(
                    name=exploit_path,
                    description=description[:200]
                    if description
                    else "Metasploit exploit module",
                )
            )

        exploit_count = len(exploits)
        if exploit_count > 0:
            summary = f"Found {exploit_count} potential exploit(s) - PASSIVE reconnaissance only"
        else:
            summary = (
                "Exploit reconnaissance completed - no specific modules identified"
            )

        return MetasploitResult(
            request=request,
            exploits_found=exploits[:10],
            sessions_active=[],
            exploitation_attempted=False,
            payload_generated=False,
            post_exploitation_performed=False,
            module_results=[],
            scan_summary=summary,
        )

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw output into structured format (for orchestrator compatibility)

        Args:
            raw_output: Raw output from reconnaissance

        Returns:
            Dictionary with structured MetasploitResult data
        """
        structured = self._parse_to_structured_result(
            raw_output, "Passive reconnaissance"
        )
        if hasattr(structured, "model_dump"):
            return structured.model_dump()
        return structured
