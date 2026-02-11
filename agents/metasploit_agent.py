import os
from typing import List, Dict, Any
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
from llm_factory import create_llm
from prompts import PromptProvider

init(autoreset=True)

METASPLOIT_AGENT_PROMPT = PromptProvider.get_agent_prompt("metasploit", "system")


class MetasploitAgent:
    """MVP Agent for exploiting vulnerabilities found by scanning agents"""

    def __init__(self, llm=None):
        """Initialize the Metasploit agent with LLM"""
        print(
            f"{Fore.GREEN}[MetasploitAgent] Initializing Metasploit Exploitation Agent{Style.RESET_ALL}"
        )

        if llm is None:
            self.llm = create_llm(temperature=0.1)
        else:
            self.llm = llm

        print(
            f"{Fore.RED}[MetasploitAgent] EXPLOITATION MODE - Will execute real exploits{Style.RESET_ALL}"
        )

    def process_request(
        self, user_request: str, vulnerability_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Process an exploitation request based on vulnerability data from scanning agents

        Args:
            user_request: The exploitation task description
            vulnerability_data: Dict containing target IP and vulnerabilities found

        Returns:
            Dictionary containing exploitation results
        """
        print(f"{Fore.RED}[MetasploitAgent] ========================================")
        print(
            f"{Fore.YELLOW}[MetasploitAgent] EXPLOITATION REQUEST: {Fore.WHITE}{user_request}"
        )
        print(
            f"{Fore.RED}[MetasploitAgent] ========================================{Style.RESET_ALL}"
        )

        try:
            # Extract target and vulnerability info
            target_ip = self._extract_target_ip(user_request, vulnerability_data)
            vuln_info = self._extract_vulnerability_info(
                user_request, vulnerability_data
            )

            print(f"{Fore.CYAN}[MetasploitAgent] Target: {target_ip}{Style.RESET_ALL}")
            print(
                f"{Fore.CYAN}[MetasploitAgent] Vulnerabilities: {vuln_info}{Style.RESET_ALL}"
            )

            # Step 1: Search for appropriate exploit
            print(
                f"{Fore.YELLOW}[MetasploitAgent] Step 1: Searching for exploits...{Style.RESET_ALL}"
            )
            search_result = search_and_select_exploit(vuln_info)

            # Parse the selected exploit from result
            exploit_module = self._parse_exploit_from_result(search_result)

            if not exploit_module:
                return {
                    "success": False,
                    "executed": False,
                    "result": f"No exploit found for vulnerabilities: {vuln_info}\n{search_result}",
                    "request": user_request,
                }

            # Step 2: Execute the exploit
            print(
                f"{Fore.RED}[MetasploitAgent] Step 2: EXECUTING EXPLOIT: {exploit_module}{Style.RESET_ALL}"
            )
            exploit_result = execute_exploit(exploit_module, target_ip)

            # Step 3: Check for sessions
            print(
                f"{Fore.YELLOW}[MetasploitAgent] Step 3: Checking for sessions...{Style.RESET_ALL}"
            )
            session_result = check_sessions()

            # Combine results
            final_result = f"=== EXPLOITATION ATTEMPT ==="
            final_result += f"\nTarget: {target_ip}"
            final_result += f"\nVulnerabilities: {vuln_info}"
            final_result += f"\n\n=== EXPLOIT SELECTION ==="
            final_result += f"\n{search_result}"
            final_result += f"\n\n=== EXPLOIT EXECUTION ==="
            final_result += f"\n{exploit_result}"
            final_result += f"\n\n=== SESSION STATUS ==="
            final_result += f"\n{session_result}"

            # Check if exploitation was successful
            success = (
                "EXPLOITATION SUCCESSFUL" in session_result
                or "Session" in session_result
            )

            print(
                f"{Fore.GREEN if success else Fore.RED}[MetasploitAgent] Exploitation {'SUCCESSFUL' if success else 'FAILED'}{Style.RESET_ALL}"
            )
            print(
                f"{Fore.RED}[MetasploitAgent] ========================================{Style.RESET_ALL}"
            )

            # Create structured result
            structured_result = self._parse_to_structured_result(
                final_result, user_request
            )

            return {
                "success": True,
                "executed": True,
                "exploitation_successful": success,
                "result": final_result,
                "request": user_request,
                "structured_result": structured_result,
            }

        except Exception as e:
            error_msg = f"Error in MetasploitAgent: {str(e)}"
            print(f"{Fore.RED}[MetasploitAgent] {error_msg}{Style.RESET_ALL}")
            return {
                "success": False,
                "error": error_msg,
                "result": str(e),
                "executed": False,
                "request": user_request,
            }

    def _extract_target_ip(
        self, user_request: str, vulnerability_data: Dict[str, Any] = None
    ) -> str:
        """Extract target IP from request or vulnerability data"""
        import re

        # Try to get from vulnerability_data first
        if vulnerability_data and "target" in vulnerability_data:
            return vulnerability_data["target"]

        # Try to extract IP from user_request
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        matches = re.findall(ip_pattern, user_request)
        if matches:
            return matches[0]

        # Try to extract URL and convert to IP
        url_pattern = r"https?://([^/]+)"
        url_matches = re.findall(url_pattern, user_request)
        if url_matches:
            return url_matches[0]

        return "127.0.0.1"  # Default to localhost

    def _extract_vulnerability_info(
        self, user_request: str, vulnerability_data: Dict[str, Any] = None
    ) -> str:
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
        pattern = r"Selected Exploit:\s*([^\n]+)"
        matches = re.findall(pattern, search_result)
        if matches:
            return matches[0].strip()

        # Look for patterns like "exploit/..."
        pattern = r"(exploit/[^\s\n]+)"
        matches = re.findall(pattern, search_result)
        if matches:
            return matches[0].strip()

        # Look for patterns like "auxiliary/..."
        pattern = r"(auxiliary/[^\s\n]+)"
        matches = re.findall(pattern, search_result)
        if matches:
            return matches[0].strip()

        return None

    # Removed old workflow methods - no longer needed for MVP

    def _verify_execution(self, response: str) -> bool:
        """Verify if actual Metasploit commands were executed"""
        execution_markers = [
            "[DEBUG]",
            "Executing exploit:",
            "Running auxiliary module:",
            "Generating payload:",
            "Active sessions:",
            "Post module output:",
            "[+]",
            "[*]",
            "msf",
            "meterpreter",
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
        structured = self._parse_to_structured_result(
            raw_output, "Metasploit operation"
        )
        # Convert to dict if it's a Pydantic model
        if hasattr(structured, "model_dump"):
            return structured.model_dump()
        return structured
