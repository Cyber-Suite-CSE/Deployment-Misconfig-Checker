import json
import os
import re
import sys
from typing import Any, Dict, List, Optional
from uuid import uuid4

from colorama import Fore, Style, init
from langchain.agents import create_agent
from langchain_core.tools import tool

from agents.hitl_helpers import get_checkpointer
from agents.metasploit_passive_agent import MetasploitPassiveAgent
from agents.nikto_agent import NiktoAgent
from agents.nmap_agent import NmapAgent
from agents.wpscan_agent import WpscanAgent
from llm_factory import create_llm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from prompts import PromptProvider

init(autoreset=True)

ORCHESTRATOR_SYSTEM_PROMPT = PromptProvider.get_orchestrator_prompt("system")

_DISPATCHER_GUIDANCE = """
Reminder: each dispatcher tool returns a JSON string. Parse it mentally, then decide whether to call another dispatcher or to write the final synthesis. Stop calling tools as soon as you can answer the original request.
"""


class OrchestratorAgent:
    """Supervisor agent that delegates to specialized sub-agents via dispatcher tools.

    Sub-agents own their own HITL middleware and SqliteSaver checkpointer; the supervisor
    only sees clean tool results. The supervisor itself uses the same SqliteSaver for
    conversation persistence so a session can be inspected/resumed across restarts.
    """

    def __init__(self, orchestrator_model=None, sub_agent_model=None, temperature=0.0):
        self.llm = create_llm(temperature=temperature, model=orchestrator_model)

        if sub_agent_model is not None:
            sub_agent_llm = create_llm(temperature=temperature, model=sub_agent_model)
        else:
            sub_agent_llm = self.llm

        self.tool_agents = {
            "nmap": NmapAgent(llm=sub_agent_llm),
            "wpscan": WpscanAgent(llm=sub_agent_llm),
            "nikto": NiktoAgent(llm=sub_agent_llm),
            "metasploit": MetasploitPassiveAgent(llm=sub_agent_llm),
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
                "exploit reconnaissance",
                "exploit module search",
                "CVE to exploit lookup",
                "exploit details and metadata",
                "passive exploitation analysis",
            ],
        }

        # Per-request execution log; reset at the start of every public entry point.
        self._execution_history: List[Dict[str, Any]] = []
        self._progress_callback = None
        self._step_started_callback = None

        self.supervisor = create_agent(
            model=self.llm,
            tools=self._build_dispatcher_tools(),
            system_prompt=f"{ORCHESTRATOR_SYSTEM_PROMPT}\n\n{_DISPATCHER_GUIDANCE}",
            checkpointer=get_checkpointer(),
        )

    # ------------------------------------------------------------------
    # Dispatcher tools — each closes over self so it can record execution
    # history and forward results back to the supervisor as JSON.
    # ------------------------------------------------------------------
    def _announce(self, agent: str, task: str) -> None:
        """Notify the TUI (if any) that a new agent step is about to start."""
        if self._step_started_callback:
            self._step_started_callback(
                {
                    "agent": agent,
                    "task": task,
                    "step": len(self._execution_history) + 1,
                }
            )

    def _build_dispatcher_tools(self):
        agents = self.tool_agents

        def _record(agent_name: str, task: str, result: Dict[str, Any]) -> Dict[str, Any]:
            structured = agents[agent_name].parse_output(result.get("result", ""))
            entry = {
                "agent": agent_name,
                "task": task,
                "structured_data": structured,
                "raw_result": result.get("result", ""),
                "executed": result.get("executed", False),
                "success": result.get("success", False),
            }
            self._execution_history.append(entry)
            if self._progress_callback:
                self._progress_callback(
                    {**entry, "step": len(self._execution_history)}
                )
            return structured

        @tool("run_nmap_agent")
        def run_nmap_agent(task: str) -> str:
            """Run network scanning, port discovery, service version detection, OS fingerprinting,
            or NSE vulnerability scripts. Use this FIRST for any reconnaissance task. Pass a
            specific scanning instruction (target + what to look for) as the task argument.
            Returns a JSON string with structured findings (open_ports, detected_services,
            vulnerabilities, etc.)."""
            self._announce("nmap", task)
            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Routing to NMAP{Style.RESET_ALL}"
            )
            print(f"{Fore.WHITE}Task: {task}{Style.RESET_ALL}")
            result = agents["nmap"].process_request(task)
            if not result.get("executed"):
                print(
                    f"{Fore.RED}[Orchestrator] WARNING: nmap did not execute{Style.RESET_ALL}"
                )
            structured = _record("nmap", task, result)
            return json.dumps(structured, default=str)

        @tool("run_wpscan_agent")
        def run_wpscan_agent(task: str) -> str:
            """Run WordPress vulnerability scanning, plugin/theme/user enumeration, or version
            detection. Use after a target has been confirmed to run WordPress. Pass a specific
            scanning instruction including the WordPress URL. Returns a JSON string with
            wordpress_version, plugins_found, themes_found, users_enumerated, vulnerabilities."""
            self._announce("wpscan", task)
            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Routing to WPSCAN{Style.RESET_ALL}"
            )
            print(f"{Fore.WHITE}Task: {task}{Style.RESET_ALL}")
            result = agents["wpscan"].process_request(task)
            if not result.get("executed"):
                print(
                    f"{Fore.RED}[Orchestrator] WARNING: wpscan did not execute{Style.RESET_ALL}"
                )
            structured = _record("wpscan", task, result)
            return json.dumps(structured, default=str)

        @tool("run_nikto_agent")
        def run_nikto_agent(task: str) -> str:
            """Run generic web server vulnerability scanning (CGI, SSL/TLS, server misconfiguration,
            outdated software). Use for non-WordPress web servers, or in addition to WPScan.
            Pass a specific scanning instruction including the URL/host. Returns a JSON string
            with server_info, vulnerabilities, ssl_info, misconfigurations, outdated_software."""
            self._announce("nikto", task)
            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Routing to NIKTO{Style.RESET_ALL}"
            )
            print(f"{Fore.WHITE}Task: {task}{Style.RESET_ALL}")
            result = agents["nikto"].process_request(task)
            if not result.get("executed"):
                print(
                    f"{Fore.RED}[Orchestrator] WARNING: nikto did not execute{Style.RESET_ALL}"
                )
            structured = _record("nikto", task, result)
            return json.dumps(structured, default=str)

        @tool("run_msf_passive_agent")
        def run_msf_passive_agent(task: str) -> str:
            """Look up potential Metasploit exploit modules for vulnerabilities found in earlier
            scans. PASSIVE only — does not execute exploits. NEVER call this first; only after
            at least one scan has produced vulnerabilities or service information. Pass the
            vulnerability summary as the task argument. Returns a JSON string with exploits_found
            and a scan_summary."""
            self._announce("metasploit", task)
            print(
                f"\n{Fore.MAGENTA}[Orchestrator] Routing to METASPLOIT (passive){Style.RESET_ALL}"
            )
            print(f"{Fore.WHITE}Task: {task}{Style.RESET_ALL}")
            vulnerability_data = self._collect_vulnerability_data(self._execution_history)
            print(
                f"{Fore.YELLOW}[Orchestrator] Passing vulnerability data to Metasploit agent{Style.RESET_ALL}"
            )
            result = agents["metasploit"].process_request(task, vulnerability_data)
            if not result.get("executed"):
                print(
                    f"{Fore.RED}[Orchestrator] WARNING: msf passive did not execute{Style.RESET_ALL}"
                )
            structured = _record("metasploit", task, result)
            return json.dumps(structured, default=str)

        return [
            run_nmap_agent,
            run_wpscan_agent,
            run_nikto_agent,
            run_msf_passive_agent,
        ]

    # ------------------------------------------------------------------
    # Helpers retained for FastAPI/run_workflow callers
    # ------------------------------------------------------------------
    def _collect_vulnerability_data(
        self, execution_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Collect vulnerability data from execution history for Metasploit agent."""
        vulnerability_data = {
            "vulnerabilities": [],
            "target": None,
            "services": [],
            "wordpress_version": None,
            "plugins": [],
        }

        for exec_entry in execution_history:
            agent = exec_entry["agent"]
            structured_data = exec_entry.get("structured_data", {}) or {}
            task = exec_entry.get("task", "")

            ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            ip_matches = re.findall(ip_pattern, task)
            if ip_matches and not vulnerability_data["target"]:
                vulnerability_data["target"] = ip_matches[0]

            if agent == "nmap" and structured_data:
                if "vulnerabilities" in structured_data:
                    vulnerability_data["vulnerabilities"].extend(
                        structured_data.get("vulnerabilities", [])
                    )
                if "detected_services" in structured_data:
                    vulnerability_data["services"].extend(
                        structured_data.get("detected_services", [])
                    )

            elif agent == "wpscan" and structured_data:
                if "wordpress_version" in structured_data:
                    vulnerability_data["wordpress_version"] = structured_data.get(
                        "wordpress_version"
                    )
                if "vulnerabilities" in structured_data:
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_data["vulnerabilities"].append(
                                vuln.get("title", "Unknown")
                            )
                        else:
                            vulnerability_data["vulnerabilities"].append(str(vuln))
                if "plugins_found" in structured_data:
                    for plugin in structured_data.get("plugins_found", []):
                        if isinstance(plugin, dict):
                            plugin_name = plugin.get("name", "Unknown")
                            plugin_version = plugin.get("version", "")
                            vulnerability_data["plugins"].append(
                                f"{plugin_name} {plugin_version}".strip()
                            )
                            for vuln in plugin.get("vulnerabilities", []):
                                vulnerability_data["vulnerabilities"].append(
                                    f"Plugin {plugin_name}: {vuln}"
                                )

            elif agent == "nikto" and structured_data:
                if "vulnerabilities" in structured_data:
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_data["vulnerabilities"].append(
                                vuln.get("description", "Unknown")
                            )
                        else:
                            vulnerability_data["vulnerabilities"].append(str(vuln))
                if "misconfigurations" in structured_data:
                    vulnerability_data["vulnerabilities"].extend(
                        structured_data.get("misconfigurations", [])
                    )

        # Remove duplicates while preserving order
        vulnerability_data["vulnerabilities"] = list(
            dict.fromkeys(vulnerability_data["vulnerabilities"])
        )
        vulnerability_data["services"] = list(dict.fromkeys(vulnerability_data["services"]))
        vulnerability_data["plugins"] = list(dict.fromkeys(vulnerability_data["plugins"]))

        return vulnerability_data

    def _check_vulnerabilities_found(
        self, execution_history: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check if any vulnerabilities have been found in the execution history."""
        vulnerabilities_found = False
        vulnerability_details: List[str] = []
        exploitable_services: List[str] = []

        for exec_entry in execution_history:
            agent = exec_entry["agent"]
            structured_data = exec_entry.get("structured_data", {}) or {}

            if agent == "nmap" and structured_data:
                if structured_data.get("vulnerabilities"):
                    vulnerabilities_found = True
                    vulnerability_details.extend(
                        [f"NMAP: {v}" for v in structured_data.get("vulnerabilities", [])]
                    )
                for service in structured_data.get("detected_services", []) or []:
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

            elif agent == "wpscan" and structured_data:
                if structured_data.get("vulnerabilities"):
                    vulnerabilities_found = True
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_details.append(
                                f"WPScan: {vuln.get('title', 'Unknown vulnerability')}"
                            )
                        else:
                            vulnerability_details.append(f"WPScan: {vuln}")

                for plugin in structured_data.get("plugins_found", []) or []:
                    if isinstance(plugin, dict):
                        plugin_vulns = plugin.get("vulnerabilities", [])
                        if plugin_vulns:
                            vulnerabilities_found = True
                            plugin_name = plugin.get("name", "Unknown")
                            vulnerability_details.append(
                                f"WPScan Plugin {plugin_name}: {', '.join(plugin_vulns)}"
                            )
                for theme in structured_data.get("themes_found", []) or []:
                    if isinstance(theme, dict):
                        theme_vulns = theme.get("vulnerabilities", [])
                        if theme_vulns:
                            vulnerabilities_found = True
                            theme_name = theme.get("name", "Unknown")
                            vulnerability_details.append(
                                f"WPScan Theme {theme_name}: {', '.join(theme_vulns)}"
                            )

            elif agent == "nikto" and structured_data:
                if structured_data.get("vulnerabilities"):
                    vulnerabilities_found = True
                    for vuln in structured_data.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            vulnerability_details.append(
                                f"Nikto: {vuln.get('description', str(vuln))}"
                            )
                        else:
                            vulnerability_details.append(f"Nikto: {vuln}")
                for misconfig in structured_data.get("misconfigurations", []) or []:
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
            "total_vulnerabilities": len(vulnerability_details) + len(exploitable_services),
        }

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def process_user_request(
        self,
        user_request: str,
        progress_callback=None,
        step_started_callback=None,
    ) -> str:
        """Drive the supervisor agent end-to-end and return its final synthesis text."""
        try:
            self._execution_history = []
            self._progress_callback = progress_callback
            self._step_started_callback = step_started_callback
            print(
                f"{Fore.CYAN}[Orchestrator] Supervisor processing request{Style.RESET_ALL}"
            )

            thread_id = uuid4().hex
            config = {"configurable": {"thread_id": thread_id}}
            response = self.supervisor.invoke(
                {"messages": [("user", user_request)]},
                config=config,
            )

            messages = response.get("messages", []) if isinstance(response, dict) else []
            final_text = ""
            for msg in reversed(messages):
                content = getattr(msg, "content", None)
                if isinstance(content, str) and content.strip():
                    final_text = content
                    break

            if not self._execution_history:
                print(
                    f"{Fore.YELLOW}[Orchestrator] No dispatcher tools were called. "
                    f"Final LLM text: {final_text[:240]!r}{Style.RESET_ALL}"
                )

            print(
                f"{Fore.GREEN}[Orchestrator] Workflow complete - {len(self._execution_history)} agent step(s){Style.RESET_ALL}"
            )
            return final_text or "(no synthesis produced)"

        except Exception as e:
            error_msg = f"Orchestrator error: {str(e)}"
            print(f"{Fore.RED}[Orchestrator] {error_msg}{Style.RESET_ALL}")
            return f"❌ {error_msg}"
        finally:
            self._progress_callback = None
            self._step_started_callback = None

    def run_workflow(
        self,
        user_request: str,
        max_iterations: int = 50,  # kept for backwards compat; supervisor self-paces
        progress_callback=None,
    ) -> Dict[str, Any]:
        """Programmatic entry point used by the FastAPI backend.

        Returns a structured dict with execution_history, response synthesis, and
        a vulnerabilities summary built from the recorded agent steps.
        """
        try:
            self._execution_history = []
            self._progress_callback = progress_callback

            thread_id = uuid4().hex
            config = {"configurable": {"thread_id": thread_id}}
            response = self.supervisor.invoke(
                {"messages": [("user", user_request)]},
                config=config,
            )

            messages = response.get("messages", []) if isinstance(response, dict) else []
            final_text = ""
            for msg in reversed(messages):
                content = getattr(msg, "content", None)
                if isinstance(content, str) and content.strip():
                    final_text = content
                    break

            workflow_type = "execution" if self._execution_history else "information"

            return {
                "success": True,
                "type": workflow_type,
                "response": final_text or "",
                "execution_history": self._execution_history,
                "vulnerabilities": self._check_vulnerabilities_found(
                    self._execution_history
                ),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "execution_history": []}
        finally:
            self._progress_callback = None

    def get_available_capabilities(self) -> str:
        """Return a formatted string of available capabilities."""
        capabilities: List[str] = []
        for agent_name, caps in self.tool_capabilities.items():
            capabilities.append(f"\n{agent_name.upper()} Agent capabilities:")
            for cap in caps:
                capabilities.append(f"  - {cap}")
        return "\n".join(capabilities)
