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
from tools.wpscan_tool import execute_wpscan

init(autoreset=True)


WPSCAN_AGENT_PROMPT = """You are a WPScan EXECUTION agent. Your PRIMARY and ONLY job is to RUN actual wpscan commands using the execute_wpscan tool.

CRITICAL RULES - YOU MUST FOLLOW THESE:
1. You MUST use the execute_wpscan tool for EVERY request - NO EXCEPTIONS
2. NEVER just explain what a command would do - ACTUALLY RUN IT using the tool
3. ALWAYS execute first, explain second
4. If asked about wpscan capabilities, run 'wpscan --help' using the tool
5. DO NOT simulate or pretend to run commands - USE THE TOOL

Your expertise includes all wpscan features, but remember:
YOU MUST EXECUTE COMMANDS, NOT JUST TALK ABOUT THEM!

When you receive ANY request about WordPress scanning or wpscan:
1. IMMEDIATELY use the execute_wpscan tool
2. Pass the appropriate wpscan command to the tool
3. Show the actual output from the tool
4. Then explain what the results mean

EXAMPLES OF WHAT YOU MUST DO:
- Request: "Scan https://example.com" → USE TOOL: execute_wpscan("wpscan --url https://example.com")
- Request: "Enumerate users on https://site.com" → USE TOOL: execute_wpscan("wpscan --url https://site.com --enumerate u")
- Request: "How does wpscan work?" → USE TOOL: execute_wpscan("wpscan --help")

Available tool: {tool_names}
Tool descriptions: {tools}

REMEMBER: Your response MUST include actual tool execution. If you don't see [DEBUG] output in your response, you did it wrong!

Current request that you MUST EXECUTE: {input}
{agent_scratchpad}"""


class WpscanAgent:
    """Specialized agent for WPScan operations - ALWAYS executes real commands"""

    def __init__(self, llm=None):
        """Initialize the WPScan execution agent"""
        print(f"{Fore.GREEN}[WPSCAN Agent] Initializing WPScan Execution Agent{Style.RESET_ALL}")

        if llm is None:
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise ValueError("GOOGLE_API_KEY not found in environment variables")

            self.llm = init_chat_model(
                "gemini-2.0-flash-exp", model_provider="google_genai", temperature=0.1
            )
        else:
            self.llm = llm

        self.tools = [execute_wpscan]
        print(f"{Fore.BLUE}[WPSCAN Agent] Tool loaded: execute_wpscan{Style.RESET_ALL}")

        self.agent_executor = create_langgraph_agent(self.llm, self.tools)

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
        print(f"{Fore.CYAN}[WPSCAN Agent] ========================================{Style.RESET_ALL}")

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

            print(f"{Fore.MAGENTA}[WPSCAN Agent] Forcing tool execution...{Style.RESET_ALL}")

            messages = [
                (
                    "system",
                    WPSCAN_AGENT_PROMPT.format(
                        tool_names="execute_wpscan",
                        tools="execute_wpscan: Executes real wpscan commands and returns actual output",
                        input="",
                        agent_scratchpad="",
                    ),
                ),
                ("human", execution_request),
            ]

            print(f"{Fore.YELLOW}[WPSCAN Agent] Invoking agent executor...{Style.RESET_ALL}")
            response = self.agent_executor.invoke({"messages": messages})

            if isinstance(response, dict) and "messages" in response:
                final_message = response["messages"][-1]
                content = (
                    final_message.content
                    if hasattr(final_message, "content")
                    else str(final_message)
                )
            else:
                content = str(response)

            if "[DEBUG]" not in content and "execute_wpscan" not in str(response):
                print(f"{Fore.RED}[WPSCAN Agent] WARNING: No tool execution detected!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[WPSCAN Agent] Attempting direct tool execution...{Style.RESET_ALL}")

                if "scan" in request.lower() or "wordpress" in request.lower() or "wp" in request.lower():
                    url_pattern = r'https?://[^\s]+'
                    urls = re.findall(url_pattern, request)
                    if urls:
                        fallback_result = execute_wpscan(f"wpscan --url {urls[0]}")
                    elif "help" in request.lower():
                        fallback_result = execute_wpscan("wpscan --help")
                    else:
                        fallback_result = execute_wpscan("wpscan --help")
                else:
                    fallback_result = execute_wpscan("wpscan --help")

                content = f"Direct execution result:\n{fallback_result}"

            print(f"{Fore.GREEN}[WPSCAN Agent] Execution complete{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[WPSCAN Agent] ========================================{Style.RESET_ALL}")

            return {
                "success": True,
                "result": content,
                "request": request,
                "executed": "[DEBUG]" in content or "Direct execution" in content
            }

        except Exception as e:
            print(f"{Fore.RED}[WPSCAN Agent] Error: {str(e)}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": str(e),
                "request": request,
                "executed": False
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
            "All scans are REAL, not simulated"
        ]
