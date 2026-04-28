import os
from typing import List, Dict, Any
from uuid import uuid4

from langchain.agents import create_agent
from colorama import init, Fore, Style
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.masscan_tool import execute_masscan
from models.structured_results import MasscanResult
from llm_factory import create_llm
from prompts import PromptProvider
from agents.hitl_helpers import (
    build_hitl,
    describe_masscan,
    get_checkpointer,
    handle_interrupt_loop,
)

init(autoreset=True)

MASSCAN_AGENT_PROMPT = PromptProvider.get_agent_prompt("masscan", "system")


class MasscanAgent:
    """Specialized agent for masscan operations - ALWAYS executes real commands"""

    def __init__(self, llm=None):
        """Initialize the masscan execution agent"""
        print(
            f"{Fore.GREEN}[MASSCAN Agent] Initializing MASSCAN Execution Agent{Style.RESET_ALL}"
        )

        if llm is None:
            self.llm = create_llm(temperature=0.1)
        else:
            self.llm = llm

        self.tools = [execute_masscan]
        print(f"{Fore.BLUE}[MASSCAN Agent] Tool loaded: execute_masscan{Style.RESET_ALL}")

        system_prompt = MASSCAN_AGENT_PROMPT.format(
            skill=PromptProvider.get_skill("masscan"),
            tool_names="execute_masscan",
            tools="execute_masscan: Executes real masscan commands and returns actual output",
            input="",
            agent_scratchpad="",
        )

        self.agent_executor = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            middleware=[build_hitl("masscan_executor", describe_masscan)],
            checkpointer=get_checkpointer(),
        )

    def process_request(self, request: str) -> Dict[str, Any]:
        """
        Process a masscan scanning request - ALWAYS EXECUTES REAL COMMANDS

        Args:
            request: Scanning request that WILL BE EXECUTED

        Returns:
            Dictionary containing actual scan results from real execution
        """
        print(f"{Fore.CYAN}[MASSCAN Agent] ========================================")
        print(f"{Fore.YELLOW}[MASSCAN Agent] Processing request: {Fore.WHITE}{request}")
        print(
            f"{Fore.CYAN}[MASSCAN Agent] ========================================{Style.RESET_ALL}"
        )

        try:
            execution_request = f"""
MANDATORY COMMAND EXECUTION TASK:
{request}

YOU MUST:
1. Use the execute_masscan tool RIGHT NOW
2. Pass the appropriate masscan command to it (remember: -p<ports> <target> --rate=N)
3. The tool will show [DEBUG] output with the real results
4. Return those real results

DO NOT just explain - USE THE TOOL!
If this is about scanning, construct and EXECUTE the masscan command.
If this is about masscan help, EXECUTE 'masscan --help'.

EXECUTE THE COMMAND NOW using execute_masscan tool!
"""

            print(
                f"{Fore.MAGENTA}[MASSCAN Agent] Forcing tool execution...{Style.RESET_ALL}"
            )

            print(
                f"{Fore.YELLOW}[MASSCAN Agent] Invoking agent executor...{Style.RESET_ALL}"
            )
            thread_id = uuid4().hex
            response = handle_interrupt_loop(
                self.agent_executor.invoke,
                initial_input={"messages": [("user", execution_request)]},
                config={"configurable": {"thread_id": thread_id}},
                thread_id=thread_id,
            )

            if isinstance(response, dict) and "messages" in response:
                final_message = response["messages"][-1]
                content = (
                    final_message.content
                    if hasattr(final_message, "content")
                    else str(final_message)
                )
            else:
                content = str(response)

            response_text = str(response)
            rejected_by_operator = "OPERATOR REJECTED" in response_text
            executed = True
            if rejected_by_operator:
                executed = False
            elif "[DEBUG]" not in response_text and "masscan_executor" not in response_text:
                executed = False
                print(
                    f"{Fore.RED}[MASSCAN Agent] WARNING: No tool execution detected!{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}[MASSCAN Agent] Attempting direct tool execution...{Style.RESET_ALL}"
                )

                request_lower = request.lower()
                cidr_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b"
                ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                cidrs = re.findall(cidr_pattern, request)
                ips = re.findall(ip_pattern, request)
                target = cidrs[0] if cidrs else (ips[0] if ips else None)

                if "help" in request_lower and not target:
                    fallback_result = execute_masscan.invoke({"command": "masscan --help"})
                elif target:
                    fallback_result = execute_masscan.invoke(
                        {"command": f"masscan -p1-65535 {target} --rate=1000"}
                    )
                    executed = True
                else:
                    fallback_result = execute_masscan.invoke({"command": "masscan --help"})

                content = f"Direct execution result:\n{fallback_result}"

            print(f"{Fore.GREEN}[MASSCAN Agent] Execution complete{Style.RESET_ALL}")
            print(
                f"{Fore.CYAN}[MASSCAN Agent] ========================================{Style.RESET_ALL}"
            )

            return {
                "success": True,
                "result": content,
                "request": request,
                "executed": executed,
            }

        except Exception as e:
            print(f"{Fore.RED}[MASSCAN Agent] Error: {str(e)}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": str(e),
                "request": request,
                "executed": False,
            }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw masscan output into structured format using LLM

        Args:
            raw_output: Raw masscan command output

        Returns:
            Dictionary with structured, parsed data
        """
        print(
            f"{Fore.CYAN}[MASSCAN Agent] Parsing output into structured format...{Style.RESET_ALL}"
        )

        try:
            parser_llm = self.llm.with_structured_output(MasscanResult)

            parse_prompt_template = PromptProvider.get_agent_prompt("masscan", "parsing")
            parse_prompt = parse_prompt_template.format(raw_output=raw_output)

            structured_result = parser_llm.invoke(parse_prompt)

            result_dict = (
                structured_result
                if isinstance(structured_result, dict)
                else structured_result.model_dump()
            )

            num_ports = len(result_dict.get("open_ports", []))
            print(
                f"{Fore.GREEN}[MASSCAN Agent] Parsing complete - found {num_ports} open ports{Style.RESET_ALL}"
            )

            return result_dict

        except Exception as e:
            print(f"{Fore.RED}[MASSCAN Agent] Parsing error: {str(e)}{Style.RESET_ALL}")
            return {
                "target": "unknown",
                "open_ports": [],
                "rate": None,
                "total_open": 0,
                "host_up": False,
                "scan_summary": f"Failed to parse masscan output: {str(e)}",
            }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities this agent can perform"""
        return [
            "EXECUTES real masscan commands",
            "Internet-scale port sweeps - fast packet-rate scanning",
            "Large-CIDR discovery - covers /16 and bigger ranges quickly",
            "Single-host or range port discovery - real results",
            "Complements nmap by finding open ports first; nmap drills down",
            "Shows real command output with [DEBUG] logs",
            "All scans are REAL, not simulated",
        ]
