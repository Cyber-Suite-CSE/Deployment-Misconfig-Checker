import os
from typing import List, Dict, Any
from uuid import uuid4

from langchain.agents import create_agent
from colorama import init, Fore, Style
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.nmap_tool import execute_nmap
from models.structured_results import NmapResult, PortInfo
from llm_factory import create_llm
from prompts import PromptProvider
from agents.hitl_helpers import (
    build_hitl,
    describe_nmap,
    get_checkpointer,
    handle_interrupt_loop,
)

init(autoreset=True)

NMAP_AGENT_PROMPT = PromptProvider.get_agent_prompt("nmap", "system")


class NmapAgent:
    """Specialized agent for NMAP operations - ALWAYS executes real commands"""

    def __init__(self, llm=None):
        """Initialize the NMAP execution agent"""
        print(
            f"{Fore.GREEN}[NMAP Agent] Initializing NMAP Execution Agent{Style.RESET_ALL}"
        )

        if llm is None:
            self.llm = create_llm(temperature=0.1)
        else:
            self.llm = llm

        # Set up tools
        self.tools = [execute_nmap]
        print(f"{Fore.BLUE}[NMAP Agent] Tool loaded: execute_nmap{Style.RESET_ALL}")

        # Render the prompt body once; create_agent supplies its own ReAct scaffolding,
        # so the {tool_names}/{tools}/{input}/{agent_scratchpad} placeholders get neutralized.
        system_prompt = NMAP_AGENT_PROMPT.format(
            skill=PromptProvider.get_skill("nmap"),
            tool_names="execute_nmap",
            tools=(
                "execute_nmap: runs nmap with typed parameters (target, "
                "scan_profile, ports, service_detection, os_detection, "
                "default_scripts, timing, nse_scripts, open_only). "
                "There is no command string — choose the right parameters."
            ),
            input="",
            agent_scratchpad="",
        )

        # HITL middleware gates the execute_nmap tool with approve / edit / reject.
        # Each sub-agent owns its own SqliteSaver so HITL state survives Ctrl-C.
        self.agent_executor = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            middleware=[build_hitl("nmap_executor", describe_nmap)],
            checkpointer=get_checkpointer(),
        )

    def process_request(self, request: str) -> Dict[str, Any]:
        """
        Process a scanning request - ALWAYS EXECUTES REAL COMMANDS

        Args:
            request: Scanning request that WILL BE EXECUTED

        Returns:
            Dictionary containing actual scan results from real execution
        """
        print(f"{Fore.CYAN}[NMAP Agent] ========================================")
        print(f"{Fore.YELLOW}[NMAP Agent] Processing request: {Fore.WHITE}{request}")
        print(
            f"{Fore.CYAN}[NMAP Agent] ========================================{Style.RESET_ALL}"
        )

        try:
            # Create an execution-focused request
            execution_request = f"""
MANDATORY SCAN TASK:
{request}

YOU MUST:
1. Call the execute_nmap tool RIGHT NOW with typed parameters.
2. Choose the target, scan_profile, and any granular flags
   (service_detection, os_detection, default_scripts, ports, timing,
   nse_scripts) from the schema. There is NO command string.
3. The tool will show [DEBUG] output with the real argv and results.
4. Return those real results.

DO NOT just explain — USE THE TOOL with parameters!
"""

            print(
                f"{Fore.MAGENTA}[NMAP Agent] Forcing tool execution...{Style.RESET_ALL}"
            )

            # Execute the agent (drives any number of HITL approve/edit/reject cycles)
            print(
                f"{Fore.YELLOW}[NMAP Agent] Invoking agent executor...{Style.RESET_ALL}"
            )
            thread_id = uuid4().hex
            response = handle_interrupt_loop(
                self.agent_executor.invoke,
                initial_input={"messages": [("user", execution_request)]},
                config={"configurable": {"thread_id": thread_id}},
                thread_id=thread_id,
            )

            # Extract the response
            if isinstance(response, dict) and "messages" in response:
                final_message = response["messages"][-1]
                content = (
                    final_message.content
                    if hasattr(final_message, "content")
                    else str(final_message)
                )
            else:
                content = str(response)

            # Verify execution happened — look across the whole response (tool messages
            # carry [DEBUG] markers, even if the final AIMessage is a clean synthesis).
            response_text = str(response)
            rejected_by_operator = "OPERATOR REJECTED" in response_text
            if rejected_by_operator:
                # Operator deliberately rejected the call; the agent's revised
                # response (or clarification ask) is the truthful result.
                executed = False
            elif "[DEBUG]" not in response_text and "nmap_executor" not in response_text:
                executed = False
                print(
                    f"{Fore.RED}[NMAP Agent] WARNING: No tool execution detected!{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}[NMAP Agent] Attempting direct tool execution...{Style.RESET_ALL}"
                )

                # Direct fallback uses the typed schema. Extract a target from
                # the request; if none, surface the failure rather than guess.
                target: str | None = None
                if "localhost" in request.lower():
                    target = "localhost"
                else:
                    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                    ips = re.findall(ip_pattern, request)
                    if ips:
                        target = ips[0]

                if target:
                    fallback_result = execute_nmap.invoke(
                        {"target": target, "scan_profile": "standard"}
                    )
                    content = f"Direct execution result:\n{fallback_result}"
                else:
                    content = (
                        "Agent did not execute a tool and no target could be "
                        "extracted from the request for a direct fallback."
                    )
            else:
                executed = True

            print(f"{Fore.GREEN}[NMAP Agent] Execution complete{Style.RESET_ALL}")
            print(
                f"{Fore.CYAN}[NMAP Agent] ========================================{Style.RESET_ALL}"
            )

            return {
                "success": True,
                "result": content,
                "request": request,
                "executed": executed,
            }

        except Exception as e:
            print(f"{Fore.RED}[NMAP Agent] Error: {str(e)}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": str(e),
                "request": request,
                "executed": False,
            }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw nmap output into structured format using LLM

        Args:
            raw_output: Raw nmap command output

        Returns:
            Dictionary with structured, parsed data
        """
        print(
            f"{Fore.CYAN}[NMAP Agent] Parsing output into structured format...{Style.RESET_ALL}"
        )

        try:
            parser_llm = self.llm.with_structured_output(NmapResult, method="function_calling")

            parse_prompt_template = PromptProvider.get_agent_prompt("nmap", "parsing")
            parse_prompt = parse_prompt_template.format(raw_output=raw_output)

            structured_result = parser_llm.invoke(parse_prompt)

            result_dict = (
                structured_result
                if isinstance(structured_result, dict)
                else structured_result.model_dump()
            )

            num_ports = len(result_dict.get("open_ports", []))
            print(
                f"{Fore.GREEN}[NMAP Agent] Parsing complete - found {num_ports} open ports{Style.RESET_ALL}"
            )

            return result_dict

        except Exception as e:
            print(f"{Fore.RED}[NMAP Agent] Parsing error: {str(e)}{Style.RESET_ALL}")
            return {
                "target": "unknown",
                "open_ports": [],
                "detected_services": [],
                "wordpress_detected": False,
                "web_servers_found": False,
                "os_detection": None,
                "vulnerabilities": [],
                "host_up": True,
                "scan_summary": f"Failed to parse nmap output: {str(e)}",
            }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities this agent can perform"""
        return [
            "EXECUTES real nmap commands",
            "Port scanning (TCP, UDP, SYN, etc.) - with actual results",
            "Service version detection - real detection",
            "Operating system detection - actual fingerprinting",
            "Network discovery - real network sweeps",
            "Vulnerability scanning with NSE scripts - actual execution",
            "Shows real command output with [DEBUG] logs",
            "All scans are REAL, not simulated",
        ]
