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
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.metasploit_tool import (
    search_and_select_exploit,
    execute_exploit,
    check_sessions,
)
from models.structured_results import (
    MetasploitResult,
    ExploitInfo,
    SessionInfo,
    ModuleResult,
)

init(autoreset=True)


METASPLOIT_AGENT_PROMPT = """You are a Metasploit EXPLOITATION agent that receives vulnerability data from scanning agents and EXPLOITS them.

⚠️ CRITICAL WARNING ⚠️
This agent has REAL EXPLOITATION CAPABILITIES. Only use against authorized targets in controlled environments.

CRITICAL RULES - YOU MUST FOLLOW THESE:
1. You MUST use the Metasploit tools for EVERY request - NO EXCEPTIONS
2. NEVER just explain what a module would do - ACTUALLY RUN IT using the tools
3. ALWAYS execute first, explain second
4. If asked about Metasploit capabilities, use list_exploits or list_payloads tools
5. DO NOT simulate or pretend to run exploits - USE THE TOOLS

Your expertise includes all Metasploit features:
- Exploitation: Running exploit modules against targets
- Payload Generation: Creating custom payloads for various platforms
- Post-Exploitation: Running post modules on compromised sessions
- Session Management: Interacting with active Meterpreter/shell sessions
- Auxiliary Modules: Running scanners, fuzzers, and other auxiliary tools

When you receive ANY request about exploitation or Metasploit:
1. IMMEDIATELY use the appropriate tool
2. Pass the correct parameters to the tool
3. Show the actual output from the tool
4. Then explain what the results mean

EXPLOITATION WORKFLOW:
1. List available exploits if needed (list_exploits)
2. Configure and execute exploit (execute_exploit)
3. Check for sessions (manage_sessions with action=list)
4. Run post modules if session established (run_post_module)

EXAMPLES OF WHAT YOU MUST DO:
- Request: "Exploit EternalBlue on 192.168.1.100" → USE TOOL: execute_exploit("exploit/windows/smb/ms17_010_eternalblue", "192.168.1.100", ...)
- Request: "Generate Windows payload" → USE TOOL: generate_payload("windows/meterpreter/reverse_tcp", ...)
- Request: "List active sessions" → USE TOOL: manage_sessions(action="list")
- Request: "Run hashdump on session 1" → USE TOOL: run_post_module("post/windows/gather/hashdump", "1")
- Request: "Find SMB exploits" → USE TOOL: list_exploits("smb")

Available tools: {tool_names}
Tool descriptions: {tools}

REMEMBER: Your response MUST include actual tool execution. If you don't see [DEBUG] output in your response, you did it wrong!

Current request that you MUST EXECUTE: {input}
{agent_scratchpad}"""


class MetasploitAgent:
    """MVP Agent for exploiting vulnerabilities found by scanning agents"""

    def __init__(self, llm=None):
        """Initialize the Metasploit agent with LLM"""
        print(f"{Fore.GREEN}[MetasploitAgent] Initializing Metasploit Exploitation Agent{Style.RESET_ALL}")

        if llm is None:
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise ValueError("GOOGLE_API_KEY not found in environment variables")

            self.llm = init_chat_model(
                "gemini-2.0-flash-exp", model_provider="google_genai", temperature=0.1
            )
        else:
            self.llm = llm

        # Initialize tools
        self.tools = [
            search_and_select_exploit,
            execute_exploit,
            check_sessions,
        ]
        print(f"{Fore.BLUE}[MetasploitAgent] Tools loaded: {[t.name for t in self.tools]}{Style.RESET_ALL}")

        # Create agent executor using LangGraph
        self.agent_executor = create_langgraph_agent(self.llm, self.tools)
        
        print(f"{Fore.RED}[MetasploitAgent] EXPLOITATION MODE - Will execute real exploits{Style.RESET_ALL}")

    def process_request(self, user_request: str, vulnerability_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process an exploitation request based on vulnerability data from scanning agents

        Args:
            user_request: The exploitation task description
            vulnerability_data: Dict containing target IP and vulnerabilities found

        Returns:
            Dictionary containing exploitation results
        """
        print(f"{Fore.RED}[MetasploitAgent] ========================================")
        print(f"{Fore.YELLOW}[MetasploitAgent] EXPLOITATION REQUEST: {Fore.WHITE}{user_request}")
        print(f"{Fore.RED}[MetasploitAgent] ========================================{Style.RESET_ALL}")

        try:
            # Extract target and vulnerability info
            target_ip = self._extract_target_ip(user_request, vulnerability_data)
            vuln_info = self._extract_vulnerability_info(user_request, vulnerability_data)

            print(f"{Fore.CYAN}[MetasploitAgent] Target: {target_ip}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[MetasploitAgent] Vulnerabilities: {vuln_info}{Style.RESET_ALL}")

            # Build enhanced request with context
            execution_request = f"""
MANDATORY EXPLOITATION TASK:
{user_request}

TARGET INFORMATION:
- Target: {target_ip}
- Vulnerabilities Found: {vuln_info}

YOU MUST:
1. Use search_and_select_exploit tool to find appropriate exploit module for: {vuln_info}
2. Use execute_exploit tool to run the selected exploit against {target_ip}
3. Use check_sessions tool to verify if exploitation was successful
4. **IMPORTANT: If the exploitation fails (no sessions created), try a maximum of 2 more alternative exploits, then STOP and report failure. Do NOT retry the same exploit multiple times.**

CRITICAL: For WordPress targets, search for:
- WordPress exploits (exploit/unix/webapp/wp_*)
- WordPress plugin exploits
- WordPress admin panel exploits
- Generic web application exploits

For Apache targets, search for:
- Apache version-specific exploits
- Apache module exploits

EXECUTE THESE TOOLS IN ORDER NOW!
"""

            print(f"{Fore.MAGENTA}[MetasploitAgent] Invoking agent executor with tools...{Style.RESET_ALL}")

            messages = [
                (
                    "system",
                    METASPLOIT_AGENT_PROMPT.format(
                        tool_names=", ".join([t.name for t in self.tools]),
                        tools="\n".join([f"{t.name}: {t.description}" for t in self.tools]),
                        input="",
                        agent_scratchpad="",
                    ),
                ),
                ("human", execution_request),
            ]

            response = self.agent_executor.invoke(
                {"messages": messages},
                config={"recursion_limit": 50}
            )

            # Extract content from response and check for tool calls
            tool_calls_detected = False
            content = ""
            
            if isinstance(response, dict) and "messages" in response:
                # Check all messages for tool calls
                for msg in response["messages"]:
                    # Check if message has tool_calls attribute (ToolMessage or AIMessage with tool_calls)
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        tool_calls_detected = True
                        print(f"{Fore.GREEN}[MetasploitAgent] Tool calls detected: {len(msg.tool_calls)}{Style.RESET_ALL}")
                    
                    # Check if it's a ToolMessage (response from a tool)
                    if hasattr(msg, "type") and msg.type == "tool":
                        tool_calls_detected = True
                        print(f"{Fore.GREEN}[MetasploitAgent] Tool execution confirmed{Style.RESET_ALL}")
                
                # Get final content
                final_message = response["messages"][-1]
                content = (
                    final_message.content
                    if hasattr(final_message, "content")
                    else str(final_message)
                )
                
                # Also concatenate all message content for full context
                full_content = "\n".join([
                    str(msg.content) if hasattr(msg, "content") else str(msg)
                    for msg in response["messages"]
                ])
            else:
                content = str(response)
                full_content = content

            # Verify execution - check both tool calls and content markers
            execution_detected = tool_calls_detected or self._verify_execution(full_content)

            if not execution_detected:
                print(f"{Fore.RED}[MetasploitAgent] WARNING: No tool execution detected in agent response!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[MetasploitAgent] ✓ Tool execution verified{Style.RESET_ALL}")

            print(f"{Fore.GREEN}[MetasploitAgent] Agent execution complete{Style.RESET_ALL}")
            print(f"{Fore.RED}[MetasploitAgent] ========================================{Style.RESET_ALL}")

            # Create structured result
            structured_result = self._parse_to_structured_result(content, user_request)

            return {
                "success": True,
                "executed": execution_detected,
                "result": content,
                "request": user_request,
                "structured_result": structured_result,
            }

        except Exception as e:
            error_msg = f"Error in MetasploitAgent: {str(e)}"
            print(f"{Fore.RED}[MetasploitAgent] {error_msg}{Style.RESET_ALL}")
            import traceback
            print(f"{Fore.RED}[MetasploitAgent] Traceback: {traceback.format_exc()}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": error_msg,
                "result": str(e),
                "executed": False,
                "request": user_request,
            }

    def _extract_target_ip(self, user_request: str, vulnerability_data: Dict[str, Any] = None) -> str:
        """Extract target IP from request or vulnerability data"""
        import re

        # Try to get from vulnerability_data first
        if vulnerability_data and "target" in vulnerability_data:
            return vulnerability_data["target"]

        # Try to extract IP from user_request
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        matches = re.findall(ip_pattern, user_request)
        if matches:
            return matches[0]

        # Try to extract URL and convert to IP
        url_pattern = r'https?://([^/]+)'
        url_matches = re.findall(url_pattern, user_request)
        if url_matches:
            return url_matches[0]

        return "127.0.0.1"  # Default to localhost

    def _extract_vulnerability_info(self, user_request: str, vulnerability_data: Dict[str, Any] = None) -> str:
        """Extract vulnerability information from request or vulnerability data"""
        vuln_info = []

        # Get from vulnerability_data if provided
        if vulnerability_data:
            if "vulnerabilities" in vulnerability_data:
                vuln_info.extend(vulnerability_data["vulnerabilities"])
            if "service_info" in vulnerability_data:
                vuln_info.append(vulnerability_data["service_info"])
            if "wordpress_version" in vulnerability_data:
                vuln_info.append(f"WordPress {vulnerability_data['wordpress_version']}")
            if "plugins" in vulnerability_data:
                for plugin in vulnerability_data["plugins"]:
                    vuln_info.append(f"WordPress Plugin: {plugin}")

        # Also parse from user_request
        request_lower = user_request.lower()
        if "wordpress" in request_lower:
            vuln_info.append("WordPress")
        if "social warfare" in request_lower:
            vuln_info.append("Social Warfare plugin")
        if "ms17-010" in request_lower or "eternalblue" in request_lower:
            vuln_info.append("MS17-010 EternalBlue")
        if "apache" in request_lower:
            vuln_info.append("Apache")
        if "rce" in request_lower:
            vuln_info.append("Remote Code Execution")

        return ", ".join(vuln_info) if vuln_info else "General vulnerabilities"

    def _parse_exploit_from_result(self, search_result: str) -> str:
        """Parse the selected exploit module from search result"""
        import re

        # Look for patterns like "Selected Exploit: exploit/..."
        pattern = r'Selected Exploit:\s*([^\n]+)'
        matches = re.findall(pattern, search_result)
        if matches:
            return matches[0].strip()

        # Look for patterns like "exploit/..."
        pattern = r'(exploit/[^\s\n]+)'
        matches = re.findall(pattern, search_result)
        if matches:
            return matches[0].strip()

        # Look for patterns like "auxiliary/..."
        pattern = r'(auxiliary/[^\s\n]+)'
        matches = re.findall(pattern, search_result)
        if matches:
            return matches[0].strip()

        return None

    # Removed old workflow methods - no longer needed for MVP







    def _verify_execution(self, response: str) -> bool:
        """Verify if actual Metasploit commands were executed"""
        execution_markers = [
            # Tool output markers
            "[DEBUG]",
            "EXECUTING EXPLOIT:",
            "EXPLOIT FOUND",
            "NO METASPLOIT EXPLOIT AVAILABLE",
            "Selected Exploit:",
            "Selected exploit:",
            "Exploit execution result:",
            "No active sessions",
            "Active sessions:",
            "EXPLOITATION SUCCESSFUL",
            
            # Metasploit output markers
            "[+]",
            "[*]",
            "[-]",
            "msf",
            "meterpreter",
            "Session",
            
            # Other execution indicators
            "Executing exploit:",
            "Running auxiliary module:",
            "Generating payload:",
            "Post module output:",
            "Error executing exploit:",
            "Error searching exploits:",
        ]
        return any(marker in response for marker in execution_markers)

    def _parse_to_structured_result(
        self, raw_output: str, request: str
    ) -> MetasploitResult:
        """Parse raw output into structured MetasploitResult"""
        # Extract exploits if listed
        exploits = []
        if "exploit/" in raw_output:
            exploit_lines = [
                line for line in raw_output.split("\n") if "exploit/" in line
            ]
            for line in exploit_lines[:5]:  # Limit to 5
                if "•" in line:
                    name = line.split("•")[1].strip().split()[0]
                    exploits.append(
                        ExploitInfo(
                            name=name,
                            description=(
                                line.split(name)[1].strip() if name in line else ""
                            ),
                        )
                    )

        # Extract session info
        sessions = []
        if "Session" in raw_output and ("Type:" in raw_output or "Info:" in raw_output):
            session_blocks = re.findall(
                r"Session (\d+):.*?(?:Type|Info): ([^\n]+)", raw_output, re.DOTALL
            )
            for sid, stype in session_blocks:
                sessions.append(
                    SessionInfo(
                        session_id=sid,
                        session_type=stype.strip(),
                        target="",  # Would need more parsing
                        info="",
                    )
                )

        # Detect if exploitation was attempted
        exploitation_attempted = any(
            term in raw_output.lower()
            for term in ["executing exploit", "launching exploit", "exploit -j"]
        )

        # Detect if payload was generated
        payload_generated = (
            "Payload generation output:" in raw_output or "msfvenom" in raw_output
        )

        # Detect if post module was run
        post_exploitation = "Post module output:" in raw_output or "post/" in raw_output

        # Create summary
        if exploitation_attempted:
            summary = "Exploitation attempt executed"
        elif payload_generated:
            summary = "Payload generated successfully"
        elif post_exploitation:
            summary = "Post-exploitation module executed"
        elif sessions:
            summary = f"Found {len(sessions)} active session(s)"
        elif exploits:
            summary = f"Listed {len(exploits)} available exploit(s)"
        else:
            summary = "Metasploit operation completed"

        return MetasploitResult(
            request=request,
            exploits_found=exploits,
            sessions_active=sessions,
            exploitation_attempted=exploitation_attempted,
            payload_generated=payload_generated,
            post_exploitation_performed=post_exploitation,
            module_results=(
                [
                    ModuleResult(
                        module_type="unknown",
                        module_name="",
                        success=True,
                        output=raw_output[:500],  # First 500 chars
                    )
                ]
                if raw_output
                else []
            ),
            scan_summary=summary,
        )

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw output into structured format (for orchestrator compatibility)

        Args:
            raw_output: Raw output from Metasploit operations

        Returns:
            Dictionary with structured MetasploitResult data
        """
        # Use the existing parser with a generic request
        structured = self._parse_to_structured_result(raw_output, "Metasploit operation")
        # Convert to dict if it's a Pydantic model
        if hasattr(structured, 'model_dump'):
            return structured.model_dump()
        return structured
