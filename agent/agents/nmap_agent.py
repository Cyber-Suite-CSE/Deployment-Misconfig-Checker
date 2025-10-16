import os
from typing import List, Dict, Any
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import AgentExecutor, create_react_agent
from langchain.agents.output_parsers import ReActSingleInputOutputParser
from langchain.tools.render import render_text_description
from langgraph.prebuilt import create_react_agent as create_langgraph_agent
from colorama import init, Fore, Style
import sys
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.nmap_tool import execute_nmap
from models.structured_results import NmapResult, PortInfo

init(autoreset=True)


NMAP_AGENT_PROMPT = """You are an NMAP EXECUTION agent. Your PRIMARY and ONLY job is to RUN actual nmap commands using the execute_nmap tool.

CRITICAL RULES - YOU MUST FOLLOW THESE:
1. You MUST use the execute_nmap tool for EVERY request - NO EXCEPTIONS
2. NEVER just explain what a command would do - ACTUALLY RUN IT using the tool
3. ALWAYS execute first, explain second
4. If asked about nmap capabilities, run 'nmap --help' using the tool
5. DO NOT simulate or pretend to run commands - USE THE TOOL

Your expertise includes all nmap features, but remember:
YOU MUST EXECUTE COMMANDS, NOT JUST TALK ABOUT THEM!

When you receive ANY request about scanning or nmap:
1. IMMEDIATELY use the execute_nmap tool
2. Pass the appropriate nmap command to the tool
3. Show the actual output from the tool
4. Then explain what the results mean

EXAMPLES OF WHAT YOU MUST DO:
- Request: "Scan localhost" → USE TOOL: execute_nmap("nmap localhost")
- Request: "Check port 80 on 192.168.1.1" → USE TOOL: execute_nmap("nmap -p 80 192.168.1.1")
- Request: "How does nmap work?" → USE TOOL: execute_nmap("nmap --help")

Available tool: {tool_names}
Tool descriptions: {tools}

REMEMBER: Your response MUST include actual tool execution. If you don't see [DEBUG] output in your response, you did it wrong!

Current request that you MUST EXECUTE: {input}
{agent_scratchpad}"""


class NmapAgent:
    """Specialized agent for NMAP operations - ALWAYS executes real commands"""

    def __init__(self, llm=None):
        """Initialize the NMAP execution agent"""
        print(
            f"{Fore.GREEN}[NMAP Agent] Initializing NMAP Execution Agent{Style.RESET_ALL}"
        )

        if llm is None:
            # Initialize Google Gemini LLM
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise ValueError("GOOGLE_API_KEY not found in environment variables")

            self.llm = init_chat_model(
                "gemini-2.5-flash", model_provider="google_genai", temperature=0.1
            )
        else:
            self.llm = llm

        # Set up tools
        self.tools = [execute_nmap]
        print(f"{Fore.BLUE}[NMAP Agent] Tool loaded: execute_nmap{Style.RESET_ALL}")

        # Create the agent using LangGraph with execution focus
        self.agent_executor = create_langgraph_agent(self.llm, self.tools)

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
MANDATORY COMMAND EXECUTION TASK:
{request}

YOU MUST:
1. Use the execute_nmap tool RIGHT NOW
2. Pass the appropriate nmap command to it
3. The tool will show [DEBUG] output with the real results
4. Return those real results

DO NOT just explain - USE THE TOOL!
If this is about scanning, construct and EXECUTE the nmap command.
If this is about nmap help, EXECUTE 'nmap --help'.

EXECUTE THE COMMAND NOW using execute_nmap tool!
"""

            print(
                f"{Fore.MAGENTA}[NMAP Agent] Forcing tool execution...{Style.RESET_ALL}"
            )

            # Create the messages with strong execution focus
            messages = [
                (
                    "system",
                    NMAP_AGENT_PROMPT.format(
                        tool_names="execute_nmap",
                        tools="execute_nmap: Executes real nmap commands and returns actual output",
                        input="",
                        agent_scratchpad="",
                    ),
                ),
                ("human", execution_request),
            ]

            # Execute the agent
            print(
                f"{Fore.YELLOW}[NMAP Agent] Invoking agent executor...{Style.RESET_ALL}"
            )
            response = self.agent_executor.invoke({"messages": messages})

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

            # Verify execution happened
            if "[DEBUG]" not in content and "execute_nmap" not in str(response):
                executed = False
                print(
                    f"{Fore.RED}[NMAP Agent] WARNING: No tool execution detected!{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}[NMAP Agent] Attempting direct tool execution...{Style.RESET_ALL}"
                )

                # Try direct tool execution as fallback
                if "scan" in request.lower() or "port" in request.lower():
                    if "localhost" in request.lower():
                        fallback_result = execute_nmap("nmap localhost")
                    elif "help" in request.lower():
                        fallback_result = execute_nmap("nmap --help")
                    else:
                        # Extract IP if present
                        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                        ips = re.findall(ip_pattern, request)
                        if ips:
                            fallback_result = execute_nmap(f"nmap {ips[0]}")
                        else:
                            fallback_result = execute_nmap("nmap --help")

                    content = f"Direct execution result:\n{fallback_result}"
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
                # "executed": "[DEBUG]" in content or "Direct execution" in content
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
            parser_llm = self.llm.with_structured_output(NmapResult)

            parse_prompt = f"""Parse this nmap scan output into structured format.

Raw nmap output:
{raw_output}

Extract the following information:
1. Target host/IP that was scanned
2. All open ports with their protocol, state, service name, and version
3. List all unique detected service types (http, ssh, mysql, ftp, etc)
4. Check if WordPress was detected (look for wp-content, wp-admin, WordPress version, etc)
5. Check if web servers were found on common ports (80, 443, 8080, 8443, 8000)
6. OS detection information if present
7. Any vulnerabilities mentioned in NSE scripts
8. Whether the host is up or down
9. Brief summary of the scan (2-3 sentences)

Be accurate and only include information that is actually present in the output.
If a field has no data, use the default empty value."""

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
