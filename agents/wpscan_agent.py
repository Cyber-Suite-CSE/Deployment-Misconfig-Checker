import os
from typing import List, Dict, Any
from uuid import uuid4

from langchain.agents import create_agent
from colorama import init, Fore, Style
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.wpscan_tool import execute_wpscan
from models.structured_results import WPScanResult, PluginInfo, ThemeInfo
from llm_factory import create_llm
from prompts import PromptProvider
from agents.hitl_helpers import (
    build_hitl,
    describe_wpscan,
    get_checkpointer,
    handle_interrupt_loop,
)

init(autoreset=True)

WPSCAN_AGENT_PROMPT = PromptProvider.get_agent_prompt("wpscan", "system")


class WpscanAgent:
    """Specialized agent for WPScan operations - ALWAYS executes real commands"""

    def __init__(self, llm=None):
        """Initialize the WPScan execution agent"""
        print(
            f"{Fore.GREEN}[WPSCAN Agent] Initializing WPScan Execution Agent{Style.RESET_ALL}"
        )

        if llm is None:
            self.llm = create_llm(temperature=0.1)
        else:
            self.llm = llm

        self.tools = [execute_wpscan]
        print(f"{Fore.BLUE}[WPSCAN Agent] Tool loaded: execute_wpscan{Style.RESET_ALL}")

        system_prompt = WPSCAN_AGENT_PROMPT.format(
            tool_names="execute_wpscan",
            tools="execute_wpscan: Executes real wpscan commands and returns actual output",
            input="",
            agent_scratchpad="",
        )

        self.agent_executor = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            middleware=[build_hitl("wpscan_executor", describe_wpscan)],
            checkpointer=get_checkpointer(),
        )

    def process_request(self, request: str) -> Dict[str, Any]:
        """
        Process a WordPress scanning request - ALWAYS EXECUTES REAL COMMANDS

        Args:
            request: Scanning request that WILL BE EXECUTED

        Returns:
            Dictionary containing actual scan results from real execution
        """
        print(f"{Fore.CYAN}[WPSCAN Agent] ========================================")
        print(f"{Fore.YELLOW}[WPSCAN Agent] Processing request: {Fore.WHITE}{request}")
        print(
            f"{Fore.CYAN}[WPSCAN Agent] ========================================{Style.RESET_ALL}"
        )

        try:
            execution_request = f"""
MANDATORY COMMAND EXECUTION TASK:
{request}

YOU MUST:
1. Use the execute_wpscan tool RIGHT NOW
2. Pass the appropriate wpscan command to it
3. The tool will show [DEBUG] output with the real results
4. Return those real results

DO NOT just explain - USE THE TOOL!
If this is about WordPress scanning, construct and EXECUTE the wpscan command.
If this is about wpscan help, EXECUTE 'wpscan --help'.

EXECUTE THE COMMAND NOW using execute_wpscan tool!
"""

            print(
                f"{Fore.MAGENTA}[WPSCAN Agent] Forcing tool execution...{Style.RESET_ALL}"
            )

            print(
                f"{Fore.YELLOW}[WPSCAN Agent] Invoking agent executor...{Style.RESET_ALL}"
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
            if "[DEBUG]" not in response_text and "wpscan_executor" not in response_text:
                executed = False
                print(
                    f"{Fore.RED}[WPSCAN Agent] WARNING: No tool execution detected!{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}[WPSCAN Agent] Attempting direct tool execution...{Style.RESET_ALL}"
                )

                if (
                    "scan" in request.lower()
                    or "wordpress" in request.lower()
                    or "wp" in request.lower()
                ):
                    url_pattern = r"https?://[^\s]+"
                    urls = re.findall(url_pattern, request)
                    if urls:
                        fallback_result = execute_wpscan.invoke(
                            {"command": f"wpscan --url {urls[0]}"}
                        )
                    elif "help" in request.lower():
                        fallback_result = execute_wpscan.invoke({"command": "wpscan --help"})
                    else:
                        fallback_result = execute_wpscan.invoke({"command": "wpscan --help"})
                else:
                    fallback_result = execute_wpscan.invoke({"command": "wpscan --help"})

                content = f"Direct execution result:\n{fallback_result}"
            else:
                executed = True
                print(f"{Fore.GREEN}[WPSCAN Agent] Execution complete{Style.RESET_ALL}")
                print(
                    f"{Fore.CYAN}[WPSCAN Agent] ========================================{Style.RESET_ALL}"
                )

            return {
                "success": True,
                "result": content,
                "request": request,
                "executed": executed,
            }

        except Exception as e:
            print(f"{Fore.RED}[WPSCAN Agent] Error: {str(e)}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": str(e),
                "request": request,
                "executed": False,
            }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw WPScan output into structured format using LLM

        Args:
            raw_output: Raw wpscan command output

        Returns:
            Dictionary with structured, parsed data
        """
        print(
            f"{Fore.CYAN}[WPSCAN Agent] Parsing output into structured format...{Style.RESET_ALL}"
        )

        try:
            parser_llm = self.llm.with_structured_output(WPScanResult)

            parse_prompt_template = PromptProvider.get_agent_prompt("wpscan", "parsing")
            parse_prompt = parse_prompt_template.format(raw_output=raw_output)

            structured_result = parser_llm.invoke(parse_prompt)

            result_dict = (
                structured_result
                if isinstance(structured_result, dict)
                else structured_result.model_dump()
            )

            num_plugins = len(result_dict.get("plugins_found", []))
            num_vulns = len(result_dict.get("vulnerabilities", []))
            print(
                f"{Fore.GREEN}[WPSCAN Agent] Parsing complete - {num_plugins} plugins, {num_vulns} vulnerabilities{Style.RESET_ALL}"
            )

            return result_dict

        except Exception as e:
            print(f"{Fore.RED}[WPSCAN Agent] Parsing error: {str(e)}{Style.RESET_ALL}")
            return {
                "target_url": "unknown",
                "wordpress_version": None,
                "wordpress_confirmed": False,
                "plugins_found": [],
                "themes_found": [],
                "users_enumerated": [],
                "vulnerabilities": [],
                "interesting_findings": [],
                "scan_summary": f"Failed to parse WPScan output: {str(e)}",
            }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities this agent can perform"""
        return [
            "EXECUTES real wpscan commands",
            "WordPress vulnerability scanning - with actual results",
            "Plugin and theme enumeration - real detection",
            "User enumeration - actual discovery",
            "WordPress version detection - real fingerprinting",
            "Security testing of WordPress installations - actual execution",
            "Shows real command output with [DEBUG] logs",
            "All scans are REAL, not simulated",
        ]
