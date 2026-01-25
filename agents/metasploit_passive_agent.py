import os
from typing import List, Dict, Any
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate
from langgraph.prebuilt import create_react_agent as create_langgraph_agent
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

init(autoreset=True)

try:
    from langchain_core.messages import ToolMessage
except ImportError:  # Fallback for older langchain versions
    ToolMessage = None


METASPLOIT_PASSIVE_AGENT_PROMPT = """You are a Metasploit RECONNAISSANCE agent that identifies potential exploits WITHOUT executing them.

CRITICAL: You are in PASSIVE/SAFE MODE - you ONLY list and analyze exploits, NEVER execute them.

Your role:
1. Analyze vulnerability data from scanning agents
2. Search for relevant Metasploit exploits
3. Provide detailed information about potential exploits
4. Recommend exploitation strategies
5. NEVER actually run or execute exploits

IMPORTANT RULES:
1. You MUST use the tools for EVERY request - NO EXCEPTIONS
2. ALWAYS search for exploits using the provided tools
3. Provide detailed, actionable information
4. Make it clear that you are NOT executing exploits
5. Focus on reconnaissance and planning, not execution

Your expertise includes:
- Exploit database search and matching
- Vulnerability to exploit mapping  
- Exploit option analysis
- Payload recommendations
- Target platform assessment

When you receive vulnerability data:
1. IMMEDIATELY use list_available_exploits with relevant keywords
2. For specific exploits, use get_exploit_details
3. For CVE identifiers, use search_exploits_by_cve
4. Analyze and present the results clearly
5. Recommend the best exploitation approach

EXAMPLES OF WHAT YOU MUST DO:
- Request: "Find exploits for WordPress Social Warfare" → USE TOOL: list_available_exploits("wordpress social warfare")
- Request: "Details on ms17-010" → USE TOOL: get_exploit_details("exploit/windows/smb/ms17_010_eternalblue")
- Request: "Exploits for CVE-2019-0708" → USE TOOL: search_exploits_by_cve("CVE-2019-0708")

Available tools: {tool_names}
Tool descriptions: {tools}

REMEMBER: You are in PASSIVE mode - search and analyze only, NEVER execute!

Current request: {input}
{agent_scratchpad}"""


class MetasploitPassiveAgent:
    """Passive Metasploit agent for exploit reconnaissance without execution"""

    def __init__(self, llm=None):
        """Initialize the passive Metasploit agent with LLM"""
        print(f"{Fore.GREEN}[MetasploitPassiveAgent] Initializing Metasploit Reconnaissance Agent (PASSIVE MODE){Style.RESET_ALL}")

        if llm is None:
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                raise ValueError("GOOGLE_API_KEY not found in environment variables")

            self.llm = init_chat_model(
                "gemini-2.5-flash", model_provider="google_genai", temperature=0.1
            )
        else:
            self.llm = llm

        self.tools = [list_available_exploits, get_exploit_details, search_exploits_by_cve]
        
        print(f"{Fore.BLUE}[MetasploitPassiveAgent] Tools loaded: list_available_exploits, get_exploit_details, search_exploits_by_cve{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[MetasploitPassiveAgent] PASSIVE MODE - Will NOT execute any exploits{Style.RESET_ALL}")

        self.agent_executor = create_langgraph_agent(self.llm, self.tools)

    def process_request(self, user_request: str, vulnerability_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Process a reconnaissance request to find potential exploits

        Args:
            user_request: The exploitation reconnaissance task
            vulnerability_data: Dict containing target IP and vulnerabilities found

        Returns:
            Dictionary containing exploit recommendations
        """
        print(f"{Fore.CYAN}[MetasploitPassiveAgent] ========================================")
        print(f"{Fore.YELLOW}[MetasploitPassiveAgent] RECONNAISSANCE REQUEST: {Fore.WHITE}{user_request}")
        print(f"{Fore.CYAN}[MetasploitPassiveAgent] ========================================{Style.RESET_ALL}")

        try:
            enriched_request = user_request
            
            if vulnerability_data:
                enriched_request += "\n\n=== VULNERABILITY DATA ==="
                
                if "target" in vulnerability_data:
                    enriched_request += f"\nTarget: {vulnerability_data['target']}"
                
                if "vulnerabilities" in vulnerability_data and vulnerability_data["vulnerabilities"]:
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

            print(f"{Fore.CYAN}[MetasploitPassiveAgent] Processing with enriched context...{Style.RESET_ALL}")

            result_messages = []
            tool_used = False

            def _record_message(msg):
                nonlocal tool_used
                if msg is None:
                    return
                result_messages.append(msg)
                msg_type = getattr(msg, "type", "")
                if msg_type == "tool":
                    tool_used = True
                if ToolMessage and isinstance(msg, ToolMessage):
                    tool_used = True

            for event in self.agent_executor.stream({"messages": [("user", enriched_request)]}):
                for _, value in event.items():
                    if isinstance(value, dict) and "messages" in value:
                        for msg in value["messages"]:
                            _record_message(msg)
                    elif isinstance(value, (list, tuple)):
                        for msg in value:
                            _record_message(msg)
                    elif hasattr(value, "type") or hasattr(value, "content"):
                        _record_message(value)
                if "tool" in event:
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
                "[DEBUG]" in str(getattr(msg, "content", ""))
                for msg in result_messages
            )
            executed = tool_used or debug_detected

            print(f"{Fore.GREEN}[MetasploitPassiveAgent] Reconnaissance complete!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[MetasploitPassiveAgent] ========================================{Style.RESET_ALL}")

            structured_result = self._parse_to_structured_result(final_response, user_request)

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

    def _parse_to_structured_result(self, raw_output: str, request: str) -> MetasploitResult:
        """Parse raw output into structured MetasploitResult"""
        exploits = []
        exploit_pattern = r'(exploit/[^\s\n]+|auxiliary/[^\s\n]+)'
        exploit_matches = re.findall(exploit_pattern, raw_output)
        
        for exploit_path in set(exploit_matches):
            desc_pattern = f"{re.escape(exploit_path)}[^\n]*Description:([^\n]+)"
            desc_match = re.search(desc_pattern, raw_output)
            description = desc_match.group(1).strip() if desc_match else ""
            
            exploits.append(ExploitInfo(
                name=exploit_path,
                description=description[:200] if description else "Metasploit exploit module",
            ))

        exploit_count = len(exploits)
        if exploit_count > 0:
            summary = f"Found {exploit_count} potential exploit(s) - PASSIVE reconnaissance only"
        else:
            summary = "Exploit reconnaissance completed - no specific modules identified"

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
        structured = self._parse_to_structured_result(raw_output, "Passive reconnaissance")
        if hasattr(structured, 'model_dump'):
            return structured.model_dump()
        return structured
