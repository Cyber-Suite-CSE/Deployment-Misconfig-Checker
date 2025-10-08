import os
from typing import Dict, Any, List
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage
from colorama import init, Fore, Style
from agents.nmap_agent import NmapAgent
from agents.wpscan_agent import WpscanAgent
from agents.nikto_agent import NiktoAgent

init(autoreset=True)


ORCHESTRATOR_PROMPT = """You are the main orchestrator agent for a cybersecurity toolkit system. Your role is to:

1. Understand user's cybersecurity/pentesting requests
2. Break down complex requests into specific tasks
3. Route tasks to appropriate specialized tool agents
4. Aggregate and present results back to the user

Currently available tool agents:
- NMAP Agent: Specializes in network scanning, port discovery, service detection, OS fingerprinting
- WPScan Agent: Specializes in WordPress vulnerability scanning, plugin/theme enumeration, user discovery
- Nikto Agent: Specializes in web server vulnerability scanning, CGI testing, SSL/TLS configuration, server misconfiguration detection

Your responsibilities:
1. ANALYZE the user's request to understand their intent
2. DECOMPOSE complex requests into specific, actionable tasks
3. DETERMINE which tool agent(s) to use
4. FORMULATE clear, specific requests for each tool agent
5. SYNTHESIZE results from tool agents into a coherent response

Guidelines:
- For network scanning requests → NMAP Agent
- For WordPress security testing → WPScan Agent
- For web server vulnerability scanning → Nikto Agent
- If a request needs multiple tools, break it down into sequential steps
- Always provide context about what you're doing
- Explain results in a user-friendly manner
- Suggest follow-up actions when appropriate

Examples of task decomposition:
- "Scan my network" → "Use NMAP Agent to perform network discovery scan on local subnet"
- "Find web servers" → "Use NMAP Agent to scan for ports 80, 443, 8080, 8443"
- "Check if server is vulnerable" → "Use NMAP Agent for version detection and vulnerability scripts"
- "Scan WordPress site" → "Use WPScan Agent to scan for WordPress vulnerabilities"
- "Find WordPress plugins" → "Use WPScan Agent to enumerate plugins"

Remember: You don't execute tools directly - you delegate to specialized agents."""


class OrchestratorAgent:
    """Main orchestrator agent that routes requests to specialized tool agents"""

    def __init__(self):
        """Initialize the orchestrator with LLM and tool agents"""
        # Initialize Google Gemini LLM
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")

        self.llm = init_chat_model(
            "gemini-2.0-flash", model_provider="google_genai", temperature=0.3
        )

        # Initialize tool agents
        self.tool_agents = {
            "nmap": NmapAgent(llm=self.llm),
            "wpscan": WpscanAgent(llm=self.llm),
            "nikto": NiktoAgent(llm=self.llm)
        }

        self.tool_capabilities = {
            "nmap": [
                "network scanning",
                "port scanning",
                "service detection",
                "OS detection",
                "vulnerability scanning",
                "host discovery",
            ],
            "wpscan": [
                "WordPress vulnerability scanning",
                "plugin enumeration",
                "theme enumeration",
                "user enumeration",
                "WordPress version detection",
                "security testing",
            ],
            "nikto": [
                "web server vulnerability scanning",
                "CGI vulnerability detection",
                "SSL/TLS configuration testing",
                "server misconfiguration identification",
                "outdated software detection",
                "common web application vulnerabilities",
            ]
        }

    def _analyze_request(self, user_request: str) -> Dict[str, Any]:
        """
        Analyze user request to determine required tools and approach

        Args:
            user_request: The user's natural language request

        Returns:
            Analysis containing tool selection and task breakdown
        """
        analysis_prompt = f"""Analyze this cybersecurity request and determine:
1. What is the user trying to accomplish?
2. Which tool agent(s) should be used?
3. What specific task(s) should be given to each agent?

User request: "{user_request}"

Available agents: {list(self.tool_agents.keys())}

Respond in this format:
INTENT: [brief description of user's goal]
TOOLS_NEEDED: [list of tool agents needed]
TASKS:
- [specific task 1 for agent X]
- [specific task 2 for agent Y]
"""

        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=analysis_prompt),
        ]

        response = self.llm.invoke(messages)
        return {"analysis": response.content, "original_request": user_request}

    def _route_to_agent(self, agent_name: str, task: str) -> Dict[str, Any]:
        """
        Route a specific task to the appropriate agent

        Args:
            agent_name: Name of the agent to use
            task: Specific task for the agent

        Returns:
            Result from the agent
        """
        if agent_name not in self.tool_agents:
            return {
                "success": False,
                "error": f"Agent '{agent_name}' not found",
                "executed": False,
            }

        agent = self.tool_agents[agent_name]
        result = agent.process_request(task)

        # Verify execution
        if result.get("executed"):
            print(
                f"{Fore.GREEN}[Orchestrator] Command execution verified!{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.RED}[Orchestrator] WARNING: No execution detected!{Style.RESET_ALL}"
            )

        return result

    def process_user_request(self, user_request: str) -> str:
        """
        Main method to process user requests

        Args:
            user_request: Natural language request from user

        Returns:
            Final response to user
        """
        try:
            analysis = self._analyze_request(user_request)

            analysis_text = analysis['analysis'].lower()
            if "wordpress" in user_request.lower() or "wpscan" in user_request.lower() or "wp" in user_request.lower():
                agent_name = "wpscan"
                task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

Create a specific, actionable task for the WPScan agent. Be precise about:
- What URL to scan
- What to enumerate (plugins, themes, users, etc.)
- Any specific scan options needed

Respond with ONLY the task description, nothing else."""
                
                print(f"\n{Fore.MAGENTA}[Orchestrator] Task for WPScan Agent:{Style.RESET_ALL}")
            elif "nikto" in user_request.lower() or "web" in user_request.lower() or ("http" in user_request.lower() and "wordpress" not in user_request.lower()):
                agent_name = "nikto"
                task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

Create a specific, actionable task for the Nikto agent. Be precise about:
- What URL/host to scan
- What port to use
- Any specific scan options needed

Respond with ONLY the task description, nothing else."""
                
                print(f"\n{Fore.MAGENTA}[Orchestrator] Task for Nikto Agent:{Style.RESET_ALL}")
            else:
                agent_name = "nmap"
                task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

Create a specific, actionable task for the NMAP agent. Be precise about:
- What to scan (targets)
- What information to gather (ports, services, OS, etc.)
- Any specific scan techniques needed

Respond with ONLY the task description, nothing else."""
                
                print(f"\n{Fore.MAGENTA}[Orchestrator] Task for NMAP Agent:{Style.RESET_ALL}")

            messages = [
                SystemMessage(content=ORCHESTRATOR_PROMPT),
                HumanMessage(content=task_prompt),
            ]

            task_response = self.llm.invoke(messages)
            specific_task = task_response.content

            if (
                "EXECUTE" not in specific_task.upper()
                and "RUN" not in specific_task.upper()
            ):
                specific_task = f"EXECUTE IMMEDIATELY: {specific_task}"

            print(f"{Fore.WHITE}{specific_task}{Style.RESET_ALL}\n")

            result = self._route_to_agent(agent_name, specific_task)

            if result["success"]:
                if result.get("executed"):
                    print(
                        f"{Fore.GREEN}[Orchestrator] Execution successful!{Style.RESET_ALL}"
                    )

                    synthesis_prompt = f"""Format these REAL EXECUTION RESULTS for the user:

Original request: "{user_request}"
Task executed: "{specific_task}"
ACTUAL COMMAND OUTPUT:
{result['result']}

Create a clear response that:
1. Confirms the command was ACTUALLY EXECUTED
2. Shows the key findings from the REAL output
3. Explains what the results mean
4. Suggests follow-up if appropriate

Start with: "I executed the following command..." """

                    messages = [
                        SystemMessage(content=ORCHESTRATOR_PROMPT),
                        HumanMessage(content=synthesis_prompt),
                    ]

                    final_response = self.llm.invoke(messages)
                    return final_response.content
                else:
                    return f"Result:\n{result['result']}"
            else:
                return f"❌ Execution failed: {result.get('error', 'Unknown error')}"

        except Exception as e:
            error_msg = f"Orchestrator error: {str(e)}"
            print(f"{Fore.RED}[Orchestrator] {error_msg}{Style.RESET_ALL}")
            return f"❌ {error_msg}"

    def get_available_capabilities(self) -> str:
        """Return a formatted string of available capabilities"""
        capabilities = []
        for agent_name, caps in self.tool_capabilities.items():
            capabilities.append(f"\n{agent_name.upper()} Agent capabilities:")
            for cap in caps:
                capabilities.append(f"  - {cap}")
        return "\n".join(capabilities)
