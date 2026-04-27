import os
from typing import List, Dict, Any
from uuid import uuid4

from langchain.agents import create_agent
from colorama import init, Fore, Style
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.nikto_tool import execute_nikto
from models.structured_results import NiktoResult
from llm_factory import create_llm
from prompts import PromptProvider
from agents.hitl_helpers import (
    build_hitl,
    describe_nikto,
    get_checkpointer,
    handle_interrupt_loop,
)

init(autoreset=True)

NIKTO_AGENT_PROMPT = PromptProvider.get_agent_prompt("nikto", "system")


class NiktoAgent:
    """Specialized agent for Nikto operations - ALWAYS executes real commands"""

    def __init__(self, llm=None):
        """Initialize the Nikto execution agent"""
        print(
            f"{Fore.GREEN}[NIKTO Agent] Initializing Nikto Execution Agent{Style.RESET_ALL}"
        )

        if llm is None:
            self.llm = create_llm(temperature=0.1)
        else:
            self.llm = llm

        self.tools = [execute_nikto]
        print(f"{Fore.BLUE}[NIKTO Agent] Tool loaded: execute_nikto{Style.RESET_ALL}")

        system_prompt = NIKTO_AGENT_PROMPT.format(
            tool_names="execute_nikto",
            tools="execute_nikto: Executes real nikto commands and returns actual output",
            input="",
            agent_scratchpad="",
        )

        self.agent_executor = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            middleware=[build_hitl("nikto_executor", describe_nikto)],
            checkpointer=get_checkpointer(),
        )

    def process_request(self, request: str) -> Dict[str, Any]:
        """
        Process a web vulnerability scanning request - ALWAYS EXECUTES REAL COMMANDS

        Args:
            request: Scanning request that WILL BE EXECUTED

        Returns:
            Dictionary containing actual scan results from real execution
        """
        print(f"{Fore.CYAN}[NIKTO Agent] ========================================")
        print(f"{Fore.YELLOW}[NIKTO Agent] Processing request: {Fore.WHITE}{request}")
        print(
            f"{Fore.CYAN}[NIKTO Agent] ========================================{Style.RESET_ALL}"
        )

        try:
            execution_request = f"""
MANDATORY COMMAND EXECUTION TASK:
{request}

YOU MUST:
1. Use the execute_nikto tool RIGHT NOW
2. Pass the appropriate nikto command to it
3. The tool will show [DEBUG] output with the real results
4. Return those real results

DO NOT just explain - USE THE TOOL!
If this is about web vulnerability scanning, construct and EXECUTE the nikto command.
If this is about nikto help, EXECUTE 'nikto -Help'.

EXECUTE THE COMMAND NOW using execute_nikto tool!
"""

            print(
                f"{Fore.MAGENTA}[NIKTO Agent] Forcing tool execution...{Style.RESET_ALL}"
            )

            print(
                f"{Fore.YELLOW}[NIKTO Agent] Invoking agent executor...{Style.RESET_ALL}"
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
            if "[DEBUG]" not in response_text and "nikto_executor" not in response_text:
                executed = False
                print(
                    f"{Fore.RED}[NIKTO Agent] WARNING: No tool execution detected!{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}[NIKTO Agent] Attempting direct tool execution...{Style.RESET_ALL}"
                )

                request_lower = request.lower()

                # Check for explicit URLs
                url_pattern = r"https?://[^\s]+"
                urls = re.findall(url_pattern, request)

                # Check for domain-like strings (e.g., example.com)
                domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
                domains = re.findall(domain_pattern, request)

                if urls:
                    fallback_result = execute_nikto.invoke({"command": f"nikto -h {urls[0]}"})
                    executed = True
                elif domains:
                    fallback_result = execute_nikto.invoke({"command": f"nikto -h {domains[0]}"})
                    executed = True
                elif "help" in request_lower:
                    fallback_result = execute_nikto.invoke({"command": "nikto -Help"})
                    executed = True
                elif "scan" in request_lower or "check" in request_lower:
                    # Attempt to find IP or anything looking like a target
                    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
                    ips = re.findall(ip_pattern, request)
                    if ips:
                        fallback_result = execute_nikto.invoke({"command": f"nikto -h {ips[0]}"})
                        executed = True
                    else:
                        fallback_result = execute_nikto.invoke({"command": "nikto -Help"})
                        executed = False  # Help alone doesn't count as execution
                else:
                    fallback_result = execute_nikto.invoke({"command": "nikto -Help"})
                    executed = False

                content = f"Direct execution result:\n{fallback_result}"

            else:
                executed = True
                print(f"{Fore.GREEN}[NIKTO Agent] Execution complete{Style.RESET_ALL}")
                print(
                    f"{Fore.CYAN}[NIKTO Agent] ========================================{Style.RESET_ALL}"
                )

            return {
                "success": True,
                "result": content,
                "request": request,
                "executed": executed,
            }

        except Exception as e:
            print(f"{Fore.RED}[NIKTO Agent] Error: {str(e)}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": str(e),
                "request": request,
                "executed": False,
            }

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw Nikto output into structured format

        Args:
            raw_output: Raw nikto scan output

        Returns:
            Dictionary containing structured nikto results
        """
        try:
            parsing_llm = create_llm(temperature=0.1)

            structured_llm = parsing_llm.with_structured_output(NiktoResult)

            parsing_prompt_template = PromptProvider.get_agent_prompt(
                "nikto", "parsing"
            )
            parsing_prompt = parsing_prompt_template.format(raw_output=raw_output)

            result = structured_llm.invoke(parsing_prompt)
            result_dict = result if isinstance(result, dict) else result.model_dump()

            num_vulns = len(result_dict.get("vulnerabilities", []))
            print(
                f"{Fore.GREEN}[NIKTO Agent] Parsing complete - found {num_vulns} vulnerabilities{Style.RESET_ALL}"
            )

            return result_dict

        except Exception as e:
            print(f"{Fore.RED}[NIKTO Agent] Parse error: {str(e)}{Style.RESET_ALL}")
            return {
                "target": "unknown",
                "port": 80,
                "server_info": None,
                "wordpress_detected": False,
                "vulnerabilities": [],
                "interesting_findings": [],
                "ssl_info": None,
                "outdated_software": [],
                "misconfigurations": [],
                "scan_summary": "Failed to parse nikto output",
            }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities this agent can perform"""
        return [
            "EXECUTES real nikto commands",
            "Web server vulnerability scanning - with actual results",
            "CGI vulnerability detection - real testing",
            "SSL/TLS configuration testing - actual checks",
            "Server misconfiguration identification - real discovery",
            "Outdated software detection - actual fingerprinting",
            "Common web application vulnerabilities - real scanning",
            "Shows real command output with [DEBUG] logs",
            "All scans are REAL, not simulated",
        ]
