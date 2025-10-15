import os
from typing import Dict, Any, List
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage
from colorama import init, Fore, Style
from agents.nmap_agent import NmapAgent
from agents.wpscan_agent import WpscanAgent
from agents.nikto_agent import NiktoAgent
from agents.metasploit_agent import MetasploitAgent

init(autoreset=True)


ORCHESTRATOR_PROMPT = """You are the main orchestrator agent for a cybersecurity toolkit system. Your role is to:

1. First determine if the user is asking for information or requesting tool execution
2. For information queries: Answer directly without executing tools
3. For execution requests: Route to appropriate specialized tool agents
4. Aggregate and present results back to the user

CRITICAL DECISION POINT:
- Information Query: User asks ABOUT capabilities, how things work, what tools do, help
- Execution Request: User wants to ACTUALLY scan, exploit, or test something

Information query indicators:
- "What can this system do?"
- "How does X work?"
- "What are your capabilities?"
- "Can you explain..."
- "What tools are available?"
- "Help"

Execution request indicators:
- "Scan..."
- "Exploit..."
- "Check..."
- "Find vulnerabilities..."
- "Test..."
- Contains specific IPs, URLs, or targets

Currently available tool agents:
- NMAP Agent: Specializes in network scanning, port discovery, service detection, OS fingerprinting, vulnerability detection
- WPScan Agent: Specializes in WordPress vulnerability scanning, plugin/theme enumeration, user discovery
- Nikto Agent: Specializes in web server vulnerability scanning, CGI testing, SSL/TLS configuration, server misconfiguration detection
- Metasploit Agent: Specializes in exploitation, payload generation, post-exploitation, session management, privilege escalation

Your responsibilities:
1. ANALYZE the user's request to understand their intent
2. DECOMPOSE complex requests into specific, actionable tasks
3. DETERMINE which tool agent(s) to use
4. FORMULATE clear, specific requests for each tool agent
5. SYNTHESIZE results from tool agents into a coherent response

CRITICAL WORKFLOW RULES FOR METASPLOIT:
- Metasploit is a SECONDARY agent that requires vulnerability data from scanning tools
- NEVER use Metasploit as the initial/first agent
- Metasploit should ONLY be called AFTER vulnerabilities All the Scanning tools are done collecting vulnerabilitites.
- The proper workflow is ALWAYS: Scan → Identify Vulnerabilities → Then Exploit

Guidelines:
- For network scanning requests → NMAP Agent (ALWAYS start here for recon)
- For WordPress security testing → WPScan Agent (after identifying WordPress)
- For web server vulnerability scanning → Nikto Agent (after finding web servers)
- For exploitation → Metasploit Agent (ONLY after vulnerabilities are found)
- For payload generation → Metasploit Agent (when specifically requested or after finding exploitable services)
- For post-exploitation tasks → Metasploit Agent (only after successful exploitation)
- If a request needs multiple tools, break it down into sequential steps
- Always provide context about what you're doing
- Explain results in a user-friendly manner
- Suggest follow-up actions when appropriate

Examples of CORRECT task decomposition:
- "Scan my network" → "Use NMAP Agent to perform network discovery scan on local subnet"
- "Find web servers" → "Use NMAP Agent to scan for ports 80, 443, 8080, 8443"
- "Check if server is vulnerable" → "Use NMAP Agent for version detection and vulnerability scripts"
- "Scan WordPress site" → "Use WPScan Agent to scan for WordPress vulnerabilities"

Remember: You don't execute tools directly - you delegate to specialized agents. ALWAYS scan first, find vulnerabilities, THEN exploit."""


class OrchestratorAgent:
    """Main orchestrator agent that routes requests to specialized tool agents"""

    def __init__(self):
        """Initialize the orchestrator with LLM and tool agents"""
        # Initialize Google Gemini LLM
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")

        self.llm = init_chat_model(
            "gemini-2.5-flash", model_provider="google_genai", temperature=0.3
        )

        # Initialize tool agents
        self.tool_agents = {
            "nmap": NmapAgent(llm=self.llm),
            "wpscan": WpscanAgent(llm=self.llm),
            "nikto": NiktoAgent(llm=self.llm),
            "metasploit": MetasploitAgent(llm=self.llm),
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
            ],
            "metasploit": [
                "exploitation",
                "vulnerability exploitation",
                "payload generation",
                "post-exploitation",
                "session management",
                "privilege escalation",
                "penetration testing",
                "exploit development",
                "meterpreter sessions",
                "auxiliary modules",
            ],
        }

    def _is_information_query(self, user_request: str) -> bool:
        """
        Determine if the user is asking for information vs requesting execution

        Args:
            user_request: The user's input

        Returns:
            True if this is an information query, False if execution is needed
        """
        request_lower = user_request.lower()

        # Information query keywords
        info_keywords = [
            "what can",
            "how do",
            "how does",
            "what are your",
            "capabilities",
            "help",
            "explain",
            "tell me about",
            "what tools",
            "what agents",
            "how to use",
            "can you",
            "is it possible",
            "what is",
            "describe",
            "list the",
            "show me what",
            "available",
            "supports",
            "does this",
        ]

        # Execution keywords that override info queries
        execution_keywords = [
            "scan ",
            "exploit ",
            "attack ",
            "test ",
            "check ",
            "find vulnerabilities",
            "enumerate",
            "run ",
            "execute",
            "compromise",
            "hack",
            "pentest",
            "assess",
        ]

        # Check for specific IPs or URLs (likely execution)
        import re

        has_ip = bool(
            re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", user_request)
        )
        has_url = bool(re.search(r"https?://|www\.", user_request))

        # If has target (IP/URL) and execution keyword, it's execution
        if (has_ip or has_url) and any(
            keyword in request_lower for keyword in execution_keywords
        ):
            return False

        # Check for information query patterns
        is_info = any(keyword in request_lower for keyword in info_keywords)

        # Check for execution patterns
        is_exec = any(keyword in request_lower for keyword in execution_keywords)

        # If only info keywords, it's an info query
        if is_info and not is_exec:
            return True

        # If only exec keywords, it's execution
        if is_exec and not is_info:
            return False

        # If both or neither, use LLM to determine
        analysis_prompt = f"""Determine if this is an INFORMATION query or EXECUTION request:

User request: "{user_request}"

An INFORMATION query asks about capabilities, features, or how to use the system.
An EXECUTION request wants to actually run tools to scan, test, or exploit something.

Respond with ONLY one word: INFO or EXEC"""

        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=analysis_prompt),
        ]

        response = self.llm.invoke(messages)
        content = str(response.content).upper()

        return "INFO" in content

    def _answer_information_query(self, user_request: str) -> str:
        """
        Answer information queries about the system without executing tools

        Args:
            user_request: The user's question

        Returns:
            Informative response about system capabilities
        """
        request_lower = user_request.lower()

        # Check what type of information is being requested
        if (
            "capabilities" in request_lower
            or "what can" in request_lower
            or "help" in request_lower
        ):
            return self.get_available_capabilities()

        # Use LLM to generate appropriate response
        info_prompt = f"""Answer this question about our cybersecurity system:

User question: "{user_request}"

Available tools and their capabilities:
- NMAP: Network scanning, port discovery, service detection, OS fingerprinting
- WPScan: WordPress vulnerability scanning, plugin/theme/user enumeration
- Nikto: Web server vulnerability scanning, SSL/TLS testing, misconfiguration detection
- Metasploit: Exploitation, payload generation, post-exploitation, session management

Be helpful and informative. Explain what the system can do and how to use it.
If they're asking about a specific tool, explain its capabilities in detail.
Include example commands they could use.

Do NOT say you will execute anything - just provide information."""

        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=info_prompt),
        ]

        response = self.llm.invoke(messages)
        return str(response.content)

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

    def _route_to_agent(self, agent_name: str, task: str, vulnerability_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Route a specific task to the appropriate agent

        Args:
            agent_name: Name of the agent to use
            task: Specific task for the agent
            vulnerability_data: Vulnerability data to pass to Metasploit agent

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

        # Special handling for Metasploit agent - pass vulnerability data
        if agent_name == "metasploit" and vulnerability_data:
            print(f"{Fore.MAGENTA}[Orchestrator] Passing vulnerability data to Metasploit agent{Style.RESET_ALL}")
            result = agent.process_request(task, vulnerability_data)
        else:
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

        lines = str(content).split("\n")
        pure_lines = []

        for line in lines:
            if (
                "[DEBUG]" in line
                or "[NMAP" in line
                or "[WPScan" in line
                or "[Nikto" in line
            ):
                continue
            if line.strip().startswith("==="):
                continue
            pure_lines.append(line)

        pure_output = "\n".join(pure_lines).strip()
        return pure_output if pure_output else str(content)

    def _collect_vulnerability_data(self, execution_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Collect vulnerability data from execution history for Metasploit agent

        Args:
            execution_history: List of previous executions

        Returns:
            Dictionary containing vulnerability data for exploitation
        """
        vulnerability_data = {
            "vulnerabilities": [],
            "target": None,
            "services": [],
            "wordpress_version": None,
            "plugins": [],
        }

        import re

        for exec in execution_history:
            agent = exec["agent"]
            structured_data = exec.get("structured_data", {})
            task = exec.get("task", "")

            # Extract target IP
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            ip_matches = re.findall(ip_pattern, task)
            if ip_matches and not vulnerability_data["target"]:
                vulnerability_data["target"] = ip_matches[0]

            # Collect vulnerabilities from each agent
            if agent == "nmap" and structured_data:
                if "vulnerabilities" in structured_data:
                    vulnerability_data["vulnerabilities"].extend(structured_data.get("vulnerabilities", []))
                if "detected_services" in structured_data:
                    vulnerability_data["services"].extend(structured_data.get("detected_services", []))

            elif agent == "wpscan" and structured_data:
                if "wordpress_version" in structured_data:
                    vulnerability_data["wordpress_version"] = structured_data.get("wordpress_version")
                if "vulnerabilities" in structured_data:
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_data["vulnerabilities"].append(vuln.get("title", "Unknown"))
                        else:
                            vulnerability_data["vulnerabilities"].append(str(vuln))
                if "plugins_found" in structured_data:
                    for plugin in structured_data.get("plugins_found", []):
                        if isinstance(plugin, dict):
                            plugin_name = plugin.get("name", "Unknown")
                            plugin_version = plugin.get("version", "")
                            vulnerability_data["plugins"].append(f"{plugin_name} {plugin_version}".strip())
                            # Add plugin vulnerabilities
                            for vuln in plugin.get("vulnerabilities", []):
                                vulnerability_data["vulnerabilities"].append(f"Plugin {plugin_name}: {vuln}")

            elif agent == "nikto" and structured_data:
                if "vulnerabilities" in structured_data:
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_data["vulnerabilities"].append(vuln.get("description", "Unknown"))
                        else:
                            vulnerability_data["vulnerabilities"].append(str(vuln))
                if "misconfigurations" in structured_data:
                    vulnerability_data["vulnerabilities"].extend(structured_data.get("misconfigurations", []))

        # Remove duplicates
        vulnerability_data["vulnerabilities"] = list(set(vulnerability_data["vulnerabilities"]))
        vulnerability_data["services"] = list(set(vulnerability_data["services"]))
        vulnerability_data["plugins"] = list(set(vulnerability_data["plugins"]))

        return vulnerability_data

    def _check_vulnerabilities_found(
        self, execution_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Check if any vulnerabilities have been found in the execution history

        Args:
            execution_history: List of previous executions

        Returns:
            Dictionary containing vulnerability status and details
        """
        vulnerabilities_found = False
        vulnerability_details = []
        exploitable_services = []

        for exec in execution_history:
            agent = exec["agent"]
            structured_data = exec.get("structured_data", {})

            # Check NMAP results for vulnerabilities
            if agent == "nmap" and structured_data:
                if "vulnerabilities" in structured_data and structured_data.get(
                    "vulnerabilities"
                ):
                    vulnerabilities_found = True
                    vulnerability_details.extend(
                        [
                            f"NMAP: {v}"
                            for v in structured_data.get("vulnerabilities", [])
                        ]
                    )

                # Check for known vulnerable services/versions
                if "detected_services" in structured_data:
                    for service in structured_data.get("detected_services", []):
                        # Check for services often associated with exploits
                        if any(
                            vuln_svc in str(service).lower()
                            for vuln_svc in [
                                "ms17-010",
                                "eternalblue",
                                "smbv1",
                                "apache/2.2",
                                "iis/6.0",
                                "vsftpd 2.3.4",
                                "unrealircd",
                            ]
                        ):
                            exploitable_services.append(service)

            # Check WPScan results for vulnerabilities
            elif agent == "wpscan" and structured_data:
                if "vulnerabilities" in structured_data and structured_data.get(
                    "vulnerabilities"
                ):
                    vulnerabilities_found = True
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_details.append(
                                f"WPScan: {vuln.get('title', 'Unknown vulnerability')}"
                            )
                        else:
                            vulnerability_details.append(f"WPScan: {vuln}")

                # Check for vulnerable plugins/themes
                if "plugins_found" in structured_data:
                    for plugin in structured_data.get("plugins_found", []):
                        if isinstance(plugin, dict):
                            plugin_vulns = plugin.get("vulnerabilities", [])
                            if plugin_vulns:
                                vulnerabilities_found = True
                                plugin_name = plugin.get("name", "Unknown")
                                vulnerability_details.append(
                                    f"WPScan Plugin {plugin_name}: {', '.join(plugin_vulns)}"
                                )

                if "themes_found" in structured_data:
                    for theme in structured_data.get("themes_found", []):
                        if isinstance(theme, dict):
                            theme_vulns = theme.get("vulnerabilities", [])
                            if theme_vulns:
                                vulnerabilities_found = True
                                theme_name = theme.get("name", "Unknown")
                                vulnerability_details.append(
                                    f"WPScan Theme {theme_name}: {', '.join(theme_vulns)}"
                                )

            # Check Nikto results for vulnerabilities
            elif agent == "nikto" and structured_data:
                if "vulnerabilities" in structured_data and structured_data.get(
                    "vulnerabilities"
                ):
                    vulnerabilities_found = True
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_details.append(
                                f"Nikto: {vuln.get('description', str(vuln))}"
                            )
                        else:
                            vulnerability_details.append(f"Nikto: {vuln}")

                # Check for critical misconfigurations
                if "misconfigurations" in structured_data and structured_data.get(
                    "misconfigurations"
                ):
                    for misconfig in structured_data.get("misconfigurations", []):
                        if any(
                            critical in str(misconfig).lower()
                            for critical in [
                                "sql injection",
                                "remote code execution",
                                "rce",
                                "command injection",
                                "directory traversal",
                                "lfi",
                                "rfi",
                            ]
                        ):
                            vulnerabilities_found = True
                            vulnerability_details.append(f"Nikto Critical: {misconfig}")

        return {
            "vulnerabilities_found": vulnerabilities_found,
            "vulnerability_details": vulnerability_details,
            "exploitable_services": exploitable_services,
            "total_vulnerabilities": len(vulnerability_details)
            + len(exploitable_services),
        }

    def _analyze_next_steps(
        self, user_request: str, execution_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
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

        import json

        # Check if vulnerabilities have been found
        vuln_check = self._check_vulnerabilities_found(execution_history)

        history_summary = ""
        for exec in execution_history:
            history_summary += f"\n--- Agent: {exec['agent']} ---\n"
            history_summary += f"Task: {exec['task']}\n"
            history_summary += f"Structured Results:\n{json.dumps(exec.get('structured_data', {}), indent=2)}\n"

        # Build the analysis prompt with vulnerability awareness
        vulnerability_context = ""
        if vuln_check["vulnerabilities_found"]:
            vulnerability_context = f"""
VULNERABILITIES DETECTED:
- Total vulnerabilities found: {vuln_check['total_vulnerabilities']}
- Details: {', '.join(vuln_check['vulnerability_details'][:5])}  # Show first 5
- Exploitable services: {', '.join(vuln_check['exploitable_services'])}

Since vulnerabilities have been found, Metasploit agent CAN now be used for exploitation if the user requested it."""
        else:
            vulnerability_context = """
NO VULNERABILITIES DETECTED YET:
- No exploitable vulnerabilities have been identified
- Metasploit should NOT be suggested unless more scanning finds vulnerabilities
- Consider additional scanning with different tools or options"""

        analysis_prompt = f"""Analyze the execution results and determine next steps.

Original user request: "{user_request}"

Execution history:
{history_summary}

{vulnerability_context}

Available agents:
- nmap: Network scanning, port discovery, service detection, OS fingerprinting
- wpscan: WordPress vulnerability scanning, plugin/theme/user enumeration
- nikto: Web server vulnerability scanning, CGI testing, SSL/TLS configuration
- metasploit: Exploitation (ONLY use if vulnerabilities were found above)

CRITICAL RULES:
1. Metasploit can ONLY be suggested if vulnerabilities_found = True
2. If user wants exploitation but no vulnerabilities found, suggest more scanning
3. Follow the proper workflow: Scan → Find Vulnerabilities → Then Exploit

Determine if we need to run additional agents based on the results:
- If nmap found web servers (port 80/443/8080), suggest nikto to scan for web vulnerabilities
- If nmap or nikto found WordPress, suggest wpscan for WordPress-specific scanning
- If vulnerabilities were found AND user wants exploitation, suggest metasploit
- If NO vulnerabilities found but user wants exploitation, suggest more aggressive scanning
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
            agent_match = (
                str(content.split("NEXT_AGENT:")[1].split("\n")[0]).strip().lower()
            )
            if agent_match in self.tool_agents:
                # Additional check: if Metasploit is suggested, verify vulnerabilities exist
                if (
                    agent_match == "metasploit"
                    and not vuln_check["vulnerabilities_found"]
                ):
                    print(
                        f"{Fore.YELLOW}[Orchestrator] Metasploit suggested but no vulnerabilities found - skipping{Style.RESET_ALL}"
                    )
                    return {
                        "done": True,
                        "next_agent": "none",
                        "task": "none",
                        "analysis": "Cannot use Metasploit - no vulnerabilities found to exploit",
                    }
                next_agent = agent_match

        if "TASK:" in content and not done:
            task_match = str(content.split("TASK:")[1]).strip()
            if task_match.lower() != "none":
                task = task_match

        return {
            "done": done,
            "next_agent": next_agent,
            "task": task,
            "analysis": content,
            "vulnerabilities_found": vuln_check["vulnerabilities_found"],
            "vulnerability_count": vuln_check["total_vulnerabilities"],
        }

    def _determine_initial_agent(
        self, user_request: str, analysis: Dict[str, Any]
    ) -> tuple:
        """
        Determine the first agent to use based on user request

        IMPORTANT: Metasploit should NEVER be the initial agent.
        Always start with scanning tools to identify vulnerabilities first.

        Args:
            user_request: Original user request
            analysis: Initial analysis result

        Returns:
            Tuple of (agent_name, task_description)
        """
        analysis_text = str(analysis["analysis"]).lower()
        request_lower = user_request.lower()

        # Check for exploitation/compromise requests - route to scanning first
        if any(
            keyword in request_lower
            for keyword in [
                "exploit",
                "payload",
                "meterpreter",
                "metasploit",
                "reverse shell",
                "post-exploitation",
                "hashdump",
                "privilege escalation",
                "session",
                "compromise",
                "hack",
                "attack",
            ]
        ):
            # For exploitation requests, ALWAYS start with reconnaissance
            if "wordpress" in request_lower or "wp" in request_lower:
                agent_name = "wpscan"
                task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

The user wants to exploit/compromise a system. First, we need to scan for vulnerabilities.
Create a specific task for the WPScan agent to identify WordPress vulnerabilities that could be exploited.

Be precise about:
- What URL to scan
- Aggressive enumeration for plugins, themes, users
- Include vulnerability detection

Respond with ONLY the task description, nothing else."""

                print(
                    f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: WPScan (scanning for vulnerabilities before exploitation){Style.RESET_ALL}"
                )
            elif (
                "web" in request_lower
                or "http" in request_lower
                or "server" in request_lower
            ):
                agent_name = "nikto"
                task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

The user wants to exploit/compromise a system. First, we need to scan for vulnerabilities.
Create a specific task for the Nikto agent to identify web server vulnerabilities that could be exploited.

Be precise about:
- What URL/host to scan
- Comprehensive vulnerability scanning
- Include checks for exploitable issues

Respond with ONLY the task description, nothing else."""

                print(
                    f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: Nikto (scanning for vulnerabilities before exploitation){Style.RESET_ALL}"
                )
            else:
                # Default to NMAP for general exploitation requests
                agent_name = "nmap"
                task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

The user wants to exploit/compromise a system. First, we need reconnaissance.
Create a specific task for the NMAP agent to identify services and vulnerabilities that could be exploited.

Be precise about:
- What to scan (targets)
- Include service version detection
- Include vulnerability scripts (--script vuln)
- Look for exploitable services

Respond with ONLY the task description, nothing else."""

                print(
                    f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: NMAP (reconnaissance before exploitation){Style.RESET_ALL}"
                )
        elif (
            "wordpress" in request_lower
            or "wpscan" in request_lower
            or "wp" in request_lower
        ):
            agent_name = "wpscan"
            task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

Create a specific, actionable task for the WPScan agent. Be precise about:
- What URL to scan
- What to enumerate (plugins, themes, users, etc.)
- Any specific scan options needed

Respond with ONLY the task description, nothing else."""

            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: WPScan{Style.RESET_ALL}"
            )
        elif (
            "nikto" in request_lower
            or ("web" in request_lower and "server" in request_lower)
            or ("ssl" in request_lower and "configuration" in request_lower)
            or ("cgi" in request_lower)
            or ("http" in request_lower and "wordpress" not in request_lower)
        ):
            agent_name = "nikto"
            task_prompt = f"""Based on this analysis:
{analysis['analysis']}

Original user request: "{user_request}"

Create a specific, actionable task for the Nikto agent. Be precise about:
- What URL/host to scan
- What port to use
- Any specific scan options needed

Respond with ONLY the task description, nothing else."""

            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: Nikto{Style.RESET_ALL}"
            )
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

            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Initial Agent: NMAP{Style.RESET_ALL}"
            )

        messages = [
            SystemMessage(content=ORCHESTRATOR_PROMPT),
            HumanMessage(content=task_prompt),
        ]

        task_response = self.llm.invoke(messages)
        specific_task = str(task_response.content)

        if (
            "EXECUTE" not in str(specific_task).upper()
            and "RUN" not in str(specific_task).upper()
        ):
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
            # First check if this is an information query
            if self._is_information_query(user_request):
                print(
                    f"{Fore.CYAN}[Orchestrator] Information query detected - answering without tool execution{Style.RESET_ALL}"
                )
                return self._answer_information_query(user_request)

            # It's an execution request - proceed with tool execution
            print(
                f"{Fore.CYAN}[Orchestrator] Execution request detected - starting multi-agent workflow{Style.RESET_ALL}"
            )

            execution_history = []
            max_iterations = 50

            analysis = self._analyze_request(user_request)

            agent_name, specific_task = self._determine_initial_agent(
                user_request, analysis
            )

            print(f"{Fore.WHITE}Task: {specific_task}{Style.RESET_ALL}\n")

            for iteration in range(max_iterations):
                print(
                    f"{Fore.YELLOW}[Orchestrator] Iteration {iteration + 1}/{max_iterations}{Style.RESET_ALL}"
                )

                # Prepare vulnerability data for Metasploit agent
                vulnerability_data = None
                if agent_name == "metasploit" and execution_history:
                    vulnerability_data = self._collect_vulnerability_data(execution_history)
                    print(f"{Fore.YELLOW}[Orchestrator] Collected vulnerability data for exploitation{Style.RESET_ALL}")

                result = self._route_to_agent(agent_name, specific_task, vulnerability_data)

                if not result.get("success"):
                    print(
                        f"{Fore.RED}[Orchestrator] Agent execution failed{Style.RESET_ALL}"
                    )
                    break

                if not result.get("executed"):
                    print(
                        f"{Fore.RED}[Orchestrator] No actual execution detected{Style.RESET_ALL}"
                    )
                    break

                print(
                    f"{Fore.GREEN}[Orchestrator] Agent execution successful!{Style.RESET_ALL}"
                )

                pure_output = self._extract_pure_output(result)

                print(
                    f"{Fore.BLUE}[Orchestrator] Parsing agent output into structured format...{Style.RESET_ALL}"
                )
                structured_data = self.tool_agents[agent_name].parse_output(
                    result.get("result", "")
                )

                execution_history.append(
                    {
                        "agent": agent_name,
                        "task": specific_task,
                        "structured_data": structured_data,
                        "raw_result": result.get("result", ""),
                    }
                )

                next_steps = self._analyze_next_steps(user_request, execution_history)

                print(
                    f"{Fore.MAGENTA}[Orchestrator] Analysis: {next_steps.get('analysis', '')[:200]}...{Style.RESET_ALL}"
                )

                if next_steps["done"] or next_steps["next_agent"] == "none":
                    print(
                        f"{Fore.GREEN}[Orchestrator] Workflow complete - all tasks finished{Style.RESET_ALL}"
                    )
                    break

                agent_name = next_steps["next_agent"]
                specific_task = next_steps["task"]

                print(
                    f"\n{Fore.MAGENTA}[Orchestrator] Next Agent: {agent_name.upper()}{Style.RESET_ALL}"
                )
                print(f"{Fore.WHITE}Task: {specific_task}{Style.RESET_ALL}\n")

            return self._synthesize_results(user_request, execution_history)

        except Exception as e:
            error_msg = f"Orchestrator error: {str(e)}"
            print(f"{Fore.RED}[Orchestrator] {error_msg}{Style.RESET_ALL}")
            return f"❌ {error_msg}"

    def _synthesize_results(
        self, user_request: str, execution_history: List[Dict[str, Any]]
    ) -> str:
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

        import json

        history_details = ""
        for exec in execution_history:
            history_details += f"\n--- Agent: {exec['agent'].upper()} ---\n"
            history_details += f"Task: {exec['task']}\n"
            history_details += f"Structured Results:\n{json.dumps(exec.get('structured_data', {}), indent=2)}\n"

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
