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

        if result.get("executed"):
            print(
                f"{Fore.GREEN}[Orchestrator] Command execution verified!{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.RED}[Orchestrator] WARNING: No execution detected!{Style.RESET_ALL}"
            )

        return result

    def _extract_pure_output(self, result: Dict[str, Any]) -> str:
        """
        Extract pure command output from agent result, removing debug/formatting

        Args:
            result: Result dictionary from agent

        Returns:
            Pure command output string
        """
        if not result.get("success"):
            return f"Error: {result.get('error', 'Unknown error')}"

        content = result.get("result", "")
        
        import re
        lines = str(content).split('\n')
        pure_lines = []
        
        for line in lines:
            if '[DEBUG]' in line or '[NMAP' in line or '[WPScan' in line or '[Nikto' in line:
                continue
            if line.strip().startswith('==='):
                continue
            pure_lines.append(line)
        
        pure_output = '\n'.join(pure_lines).strip()
        return pure_output if pure_output else str(content)

    def _analyze_next_steps(self, user_request: str, execution_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze execution history to determine if more agents are needed

        Args:
            user_request: Original user request
            execution_history: List of previous executions

        Returns:
            Dictionary with next_agent, task, and done flag
        """
        if not execution_history:
            return {"done": True, "reason": "No execution history"}

        history_summary = "\n".join([
            f"Agent: {exec['agent']}\nTask: {exec['task']}\nOutput Summary: {exec['output'][:500]}..."
            for exec in execution_history
        ])

        analysis_prompt = f"""Analyze the execution results and determine next steps.

Original user request: "{user_request}"

Execution history:
{history_summary}

Available agents:
- nmap: Network scanning, port discovery, service detection, OS fingerprinting
- wpscan: WordPress vulnerability scanning, plugin/theme/user enumeration
- nikto: Web server vulnerability scanning, CGI testing, SSL/TLS configuration

Determine if we need to run additional agents based on the results. For example:
- If nmap found web servers (port 80/443/8080), suggest nikto to scan for web vulnerabilities
- If nmap or nikto found WordPress, suggest wpscan for WordPress-specific scanning
- If the original request is already satisfied, mark as done

Respond ONLY in this exact format:
DONE: [yes/no]
NEXT_AGENT: [agent name or "none"]
REASONING: [brief explanation]
TASK: [specific task for next agent, or "none"]"""

        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=analysis_prompt),
        ]

        response = self.llm.invoke(messages)
        content = str(response.content)

        done = "DONE: yes" in content or "DONE:yes" in content
        
        next_agent = "none"
        task = "none"
        
        if "NEXT_AGENT:" in content:
            agent_match = str(content.split("NEXT_AGENT:")[1].split("\n")[0]).strip().lower()
            if agent_match in self.tool_agents:
                next_agent = agent_match
        
        if "TASK:" in content and not done:
            task_match = str(content.split("TASK:")[1]).strip()
            if task_match.lower() != "none":
                task = task_match

        return {
            "done": done,
            "next_agent": next_agent,
            "task": task,
            "analysis": content
        }

    def _determine_initial_agent(self, user_request: str, analysis: Dict[str, Any]) -> tuple:
        """
        Determine the first agent to use based on user request

        Args:
            user_request: Original user request
            analysis: Initial analysis result

        Returns:
            Tuple of (agent_name, task_description)
        """
        analysis_text = str(analysis['analysis']).lower()
        
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
            
            print(f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: WPScan{Style.RESET_ALL}")
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
            
            print(f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: Nikto{Style.RESET_ALL}")
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
            
            print(f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: NMAP{Style.RESET_ALL}")

        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=task_prompt),
        ]

        task_response = self.llm.invoke(messages)
        specific_task = str(task_response.content)

        if "EXECUTE" not in str(specific_task).upper() and "RUN" not in str(specific_task).upper():
            specific_task = f"EXECUTE IMMEDIATELY: {specific_task}"

        return agent_name, specific_task

    def process_user_request(self, user_request: str) -> str:
        """
        Main method to process user requests with multi-agent workflow support

        Args:
            user_request: Natural language request from user

        Returns:
            Final response to user
        """
        try:
            print(f"{Fore.CYAN}[Orchestrator] Starting multi-agent workflow{Style.RESET_ALL}")
            
            execution_history = []
            max_iterations = 5
            
            analysis = self._analyze_request(user_request)
            
            agent_name, specific_task = self._determine_initial_agent(user_request, analysis)
            
            print(f"{Fore.WHITE}Task: {specific_task}{Style.RESET_ALL}\n")
            
            for iteration in range(max_iterations):
                print(f"{Fore.YELLOW}[Orchestrator] Iteration {iteration + 1}/{max_iterations}{Style.RESET_ALL}")
                
                result = self._route_to_agent(agent_name, specific_task)
                
                if not result.get("success"):
                    print(f"{Fore.RED}[Orchestrator] Agent execution failed{Style.RESET_ALL}")
                    break
                
                if not result.get("executed"):
                    print(f"{Fore.RED}[Orchestrator] No actual execution detected{Style.RESET_ALL}")
                    break
                
                print(f"{Fore.GREEN}[Orchestrator] Agent execution successful!{Style.RESET_ALL}")
                
                pure_output = self._extract_pure_output(result)
                
                execution_history.append({
                    "agent": agent_name,
                    "task": specific_task,
                    "output": pure_output,
                    "raw_result": result.get("result", "")
                })
                
                next_steps = self._analyze_next_steps(user_request, execution_history)
                
                print(f"{Fore.MAGENTA}[Orchestrator] Analysis: {next_steps.get('analysis', '')[:200]}...{Style.RESET_ALL}")
                
                if next_steps["done"] or next_steps["next_agent"] == "none":
                    print(f"{Fore.GREEN}[Orchestrator] Workflow complete - all tasks finished{Style.RESET_ALL}")
                    break
                
                agent_name = next_steps["next_agent"]
                specific_task = next_steps["task"]
                
                print(f"\n{Fore.MAGENTA}[Orchestrator] Next Agent: {agent_name.upper()}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}Task: {specific_task}{Style.RESET_ALL}\n")
            
            return self._synthesize_results(user_request, execution_history)
        
        except Exception as e:
            error_msg = f"Orchestrator error: {str(e)}"
            print(f"{Fore.RED}[Orchestrator] {error_msg}{Style.RESET_ALL}")
            return f"❌ {error_msg}"

    def _synthesize_results(self, user_request: str, execution_history: List[Dict[str, Any]]) -> str:
        """
        Synthesize results from multiple agent executions into coherent response

        Args:
            user_request: Original user request
            execution_history: List of all agent executions

        Returns:
            Final synthesized response
        """
        if not execution_history:
            return "❌ No agents were executed successfully"
        
        history_details = "\n\n".join([
            f"Agent: {exec['agent'].upper()}\nTask: {exec['task']}\nOutput:\n{exec['raw_result'][:1000]}..."
            for exec in execution_history
        ])
        
        synthesis_prompt = f"""Synthesize these multi-agent execution results for the user:

Original request: "{user_request}"

Execution history ({len(execution_history)} agent(s) executed):
{history_details}

Create a comprehensive response that:
1. Confirms all commands were ACTUALLY EXECUTED
2. Summarizes key findings from each agent
3. Explains what the combined results mean
4. Highlights important security findings or issues
5. Suggests follow-up actions if appropriate

Start with: "I executed {len(execution_history)} security scan(s)..." """
        
        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=synthesis_prompt),
        ]
        
        final_response = self.llm.invoke(messages)
        return str(final_response.content)

    def get_available_capabilities(self) -> str:
        """Return a formatted string of available capabilities"""
        capabilities = []
        for agent_name, caps in self.tool_capabilities.items():
            capabilities.append(f"\n{agent_name.upper()} Agent capabilities:")
            for cap in caps:
                capabilities.append(f"  - {cap}")
        return "\n".join(capabilities)
