import json
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

colorama_stub = types.SimpleNamespace(
    Fore=types.SimpleNamespace(CYAN="", WHITE="", YELLOW="", GREEN="", RED="", BLUE="", MAGENTA=""),
    Style=types.SimpleNamespace(RESET_ALL=""),
    init=lambda autoreset=True: None,
)
sys.modules.setdefault("colorama", colorama_stub)

langchain_tools_module = types.ModuleType("langchain_core.tools")


def _identity_tool(*decorator_args, **decorator_kwargs):
    if decorator_args and callable(decorator_args[0]) and len(decorator_args) == 1 and not decorator_kwargs:
        fn = decorator_args[0]
        fn.name = getattr(fn, "__name__", "tool")
        return fn

    def _decorate(fn):
        fn.name = decorator_args[0] if decorator_args and isinstance(decorator_args[0], str) else getattr(fn, "__name__", "tool")
        return fn

    return _decorate


langchain_tools_module.tool = _identity_tool
sys.modules.setdefault("langchain_core.tools", langchain_tools_module)

llm_factory_stub = types.ModuleType("llm_factory")
llm_factory_stub.create_llm = lambda temperature=0.1: None
sys.modules.setdefault("llm_factory", llm_factory_stub)

deepagents_module = types.ModuleType("deepagents")


class FakeFilesystemPermission:
    def __init__(self, operations, paths, mode="allow"):
        self.operations = operations
        self.paths = paths
        self.mode = mode


def _unused_create_deep_agent(**kwargs):
    raise AssertionError("Tests should inject a fake agent_factory instead of using create_deep_agent")


deepagents_module.FilesystemPermission = FakeFilesystemPermission
deepagents_module.create_deep_agent = _unused_create_deep_agent
sys.modules.setdefault("deepagents", deepagents_module)

deepagents_backends_module = types.ModuleType("deepagents.backends")


class FakeStateBackend:
    pass


deepagents_backends_module.StateBackend = FakeStateBackend
sys.modules.setdefault("deepagents.backends", deepagents_backends_module)

from v2.orchestrator import V2DeepOrchestrator
from v2.models import WebScanResult
from v2.parsers import merge_service_discovery_results, parse_masscan_output
from v2.tools.masscan_tool import execute_masscan, validate_masscan_installed


def subagent_message(name, payload, task):
    return SimpleNamespace(
        name=name,
        type="tool",
        tool_call_id=f"call_{name}",
        content=json.dumps(payload),
        metadata={"lc_agent_name": name, "task": task},
    )


class FakeAgent:
    def __init__(self, name, responses):
        self.name = name
        self.responses = responses

    def stream(self, payload, stream_mode=None, subgraphs=None, version=None):
        for chunk in self.responses[self.name]:
            yield chunk


class FakeAgentFactory:
    def __init__(self, responses):
        self.responses = responses

    def __call__(self, **kwargs):
        return FakeAgent(kwargs.get("name", "default"), self.responses)


class V2OrchestratorTests(unittest.TestCase):
    def build_orchestrator(self, responses):
        return V2DeepOrchestrator(
            llm=object(),
            agent_factory=FakeAgentFactory(responses),
        )

    def make_stream_response(self, subagent_specs, final_text):
        chunks = []

        if subagent_specs:
            tool_calls = []
            for call_id, name, task, payload in subagent_specs:
                tool_calls.append(
                    {
                        "id": call_id,
                        "name": "task",
                        "args": {
                            "subagent_type": name,
                            "description": task,
                        },
                    }
                )

            chunks.append(
                {
                    "type": "updates",
                    "ns": (),
                    "data": {
                        "model_request": {
                            "messages": [SimpleNamespace(type="ai", tool_calls=tool_calls, content="")]
                        }
                    },
                }
            )

            for call_id, name, task, payload in subagent_specs:
                chunks.append(
                    {
                        "type": "updates",
                        "ns": (f"tools:{call_id}",),
                        "data": {"model_request": {"messages": []}},
                    }
                )

            tool_messages = []
            for call_id, name, task, payload in subagent_specs:
                tool_messages.append(
                    SimpleNamespace(
                        type="tool",
                        name="task",
                        tool_call_id=call_id,
                        content=json.dumps(payload),
                    )
                )

            chunks.append(
                {
                    "type": "updates",
                    "ns": (),
                    "data": {"tools": {"messages": tool_messages}},
                }
            )

        chunks.append(
            {
                "type": "updates",
                "ns": (),
                "data": {
                    "model_request": {
                        "messages": [SimpleNamespace(type="ai", content=final_text, tool_calls=[])]
                    }
                },
            }
        )
        return chunks

    def test_generic_target_starts_with_service_discovery(self):
        responses = {
            "v2-supervisor-agent": self.make_stream_response(
                [
                    (
                        "call_service_1",
                        "service_discover_agent",
                        "Discover services on 192.168.1.10",
                        {
                            "target": "192.168.1.10",
                            "host_up": True,
                            "open_ports": [],
                            "detected_services": [],
                            "web_targets": [],
                            "wordpress_detected": False,
                            "discovery_sources": ["nmap"],
                            "vulnerabilities": [],
                            "scan_summary": "Basic discovery completed",
                        },
                    )
                ],
                "Discovery completed.",
            )
        }
        orchestrator = self.build_orchestrator(responses)
        result = orchestrator.run_workflow("Scan 192.168.1.10 for services")
        self.assertTrue(result["success"])
        self.assertEqual(result["execution_history"][0]["agent"], "service_discover_agent")

    def test_web_request_can_include_web_scan(self):
        responses = {
            "v2-supervisor-agent": self.make_stream_response(
                [
                    (
                        "call_service_1",
                        "service_discover_agent",
                        "Perform service discovery on example.com",
                        {
                            "target": "example.com",
                            "host_up": True,
                            "open_ports": [
                                {
                                    "port": "80",
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": "http",
                                    "version": "nginx",
                                }
                            ],
                            "detected_services": ["http"],
                            "web_targets": ["http://example.com:80"],
                            "wordpress_detected": False,
                            "discovery_sources": ["nmap"],
                            "vulnerabilities": [],
                            "scan_summary": "Web exposure found",
                        },
                    ),
                    (
                        "call_web_1",
                        "web_scan_agent",
                        "Assess the discovered web target http://example.com:80",
                        {
                            "target": "http://example.com:80",
                            "wordpress_detected": False,
                            "nikto_result": None,
                            "wpscan_result": None,
                            "vulnerabilities": ["Missing security headers"],
                            "misconfigurations": ["TRACE method enabled"],
                            "scan_summary": "Web findings identified",
                        },
                    ),
                ],
                "Web scan completed.",
            )
        }
        orchestrator = self.build_orchestrator(responses)
        result = orchestrator.run_workflow("Assess https://example.com for web vulnerabilities")
        agents = [entry["agent"] for entry in result["execution_history"]]
        self.assertEqual(agents, ["service_discover_agent", "web_scan_agent"])

    def test_exploit_recon_absent_when_supervisor_does_not_delegate_it(self):
        responses = {
            "v2-supervisor-agent": self.make_stream_response(
                [
                    (
                        "call_service_1",
                        "service_discover_agent",
                        "Scan example.com",
                        {
                            "target": "example.com",
                            "host_up": True,
                            "open_ports": [],
                            "detected_services": [],
                            "web_targets": [],
                            "wordpress_detected": False,
                            "discovery_sources": ["nmap"],
                            "vulnerabilities": [],
                            "scan_summary": "No findings",
                        },
                    )
                ],
                "No further delegation needed.",
            )
        }
        orchestrator = self.build_orchestrator(responses)
        result = orchestrator.run_workflow("Scan example.com")
        agents = [entry["agent"] for entry in result["execution_history"]]
        self.assertNotIn("exploit_recon_agent", agents)

    def test_run_workflow_preserves_legacy_contract_shape(self):
        responses = {
            "v2-supervisor-agent": self.make_stream_response(
                [
                    (
                        "call_service_1",
                        "service_discover_agent",
                        "Scan example.com",
                        {
                            "target": "example.com",
                            "host_up": True,
                            "open_ports": [],
                            "detected_services": [],
                            "web_targets": [],
                            "wordpress_detected": False,
                            "discovery_sources": ["nmap"],
                            "vulnerabilities": [],
                            "scan_summary": "Basic discovery completed",
                        },
                    )
                ],
                "Done.",
            )
        }
        orchestrator = self.build_orchestrator(responses)
        result = orchestrator.run_workflow("Scan example.com")
        self.assertIn("success", result)
        self.assertIn("type", result)
        self.assertIn("response", result)
        self.assertIn("execution_history", result)
        self.assertIn("vulnerabilities", result)
        history_entry = result["execution_history"][0]
        self.assertIn("agent", history_entry)
        self.assertIn("task", history_entry)
        self.assertIn("structured_data", history_entry)
        self.assertIn("raw_result", history_entry)
        self.assertIn("timestamp", history_entry)

    def test_masscan_fallback_when_not_installed(self):
        with patch("v2.tools.masscan_tool.validate_masscan_installed", return_value=False):
            result = execute_masscan("masscan 10.0.0.0/24 -p80")
        self.assertIn("MASSCAN_NOT_INSTALLED", result)

    def test_masscan_validate_accepts_version_banner_with_nonzero_exit(self):
        fake_result = SimpleNamespace(
            returncode=1,
            stdout="Masscan version 1.3.2\n",
            stderr="",
        )
        with patch("v2.tools.masscan_tool.subprocess.run", return_value=fake_result):
            self.assertTrue(validate_masscan_installed())

    def test_masscan_parser_extracts_open_ports(self):
        parsed = parse_masscan_output(
            "Discovered open port 80/tcp on 10.0.0.5\nDiscovered open port 443/tcp on 10.0.0.5"
        )
        self.assertEqual(parsed["target"], "10.0.0.5")
        self.assertEqual(len(parsed["open_ports"]), 2)

    def test_web_scan_result_normalizes_string_nikto_vulnerabilities(self):
        result = WebScanResult.model_validate(
            {
                "target": "http://192.168.48.4",
                "wordpress_detected": False,
                "nikto_result": {
                    "target": "http://192.168.48.4",
                    "port": 80,
                    "server_info": "Apache",
                    "vulnerabilities": [
                        "Apache/2.4.57 appears to be outdated",
                        "PHP/8.2.17 appears to be outdated",
                    ],
                    "misconfigurations": [],
                },
                "vulnerabilities": [],
                "misconfigurations": [],
            }
        )
        self.assertTrue(result.scan_summary)
        self.assertTrue(result.nikto_result.scan_summary)
        self.assertEqual(
            result.nikto_result.vulnerabilities[0].description,
            "Apache/2.4.57 appears to be outdated",
        )

    def test_service_discovery_merge_normalizes_web_targets(self):
        merged = merge_service_discovery_results(
            nmap_data={
                "target": "example.com",
                "open_ports": [
                    {
                        "port": "80",
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "nginx",
                    }
                ],
                "detected_services": ["http"],
                "wordpress_detected": False,
                "vulnerabilities": [],
                "host_up": True,
            },
            masscan_data={
                "target": "example.com",
                "open_ports": [
                    {
                        "port": "443",
                        "protocol": "tcp",
                        "state": "open",
                        "service": None,
                        "version": None,
                    }
                ],
                "detected_services": [],
                "host_up": True,
            },
            fallback_target="example.com",
        )
        self.assertTrue(merged["web_targets"])

    def test_full_chain_service_web_exploit_recon(self):
        responses = {
            "v2-supervisor-agent": self.make_stream_response(
                [
                    (
                        "call_service_1",
                        "service_discover_agent",
                        "Perform service discovery on example.com",
                        {
                            "target": "example.com",
                            "host_up": True,
                            "open_ports": [
                                {
                                    "port": "80",
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": "http",
                                    "version": "nginx",
                                }
                            ],
                            "detected_services": ["http"],
                            "web_targets": ["http://example.com:80"],
                            "wordpress_detected": False,
                            "discovery_sources": ["nmap"],
                            "vulnerabilities": [],
                            "scan_summary": "Web exposure found",
                        },
                    ),
                    (
                        "call_web_1",
                        "web_scan_agent",
                        "Assess the discovered web target http://example.com:80",
                        {
                            "target": "http://example.com:80",
                            "wordpress_detected": False,
                            "nikto_result": None,
                            "wpscan_result": None,
                            "vulnerabilities": ["Missing security headers"],
                            "misconfigurations": ["TRACE method enabled"],
                            "scan_summary": "Web findings identified",
                        },
                    ),
                    (
                        "call_exploit_1",
                        "exploit_recon_agent",
                        "Assess exploitability for example.com based on prior findings",
                        {
                            "target": "example.com",
                            "candidate_modules": [
                                {
                                    "module": "exploit/example/module",
                                    "confidence": 0.8,
                                    "rationale": "Matched service fingerprint",
                                    "matched_findings": ["Missing security headers"],
                                }
                            ],
                            "matched_services": ["http"],
                            "matched_vulnerabilities": ["Missing security headers"],
                            "recommended_next_steps": ["Validate version match manually"],
                            "scan_summary": "Identified one candidate module",
                        },
                    ),
                ],
                "Full assessment completed.",
            )
        }
        orchestrator = self.build_orchestrator(responses)
        result = orchestrator.run_workflow(
            "Assess https://example.com and evaluate exploitability"
        )
        agents = [entry["agent"] for entry in result["execution_history"]]
        self.assertEqual(
            agents,
            ["service_discover_agent", "web_scan_agent", "exploit_recon_agent"],
        )

    def test_progress_callback_streams_completed_subagents(self):
        responses = {
            "v2-supervisor-agent": self.make_stream_response(
                [
                    (
                        "call_service_1",
                        "service_discover_agent",
                        "Perform service discovery on example.com",
                        {
                            "target": "example.com",
                            "host_up": True,
                            "open_ports": [],
                            "detected_services": ["http"],
                            "web_targets": ["http://example.com:80"],
                            "wordpress_detected": False,
                            "discovery_sources": ["nmap"],
                            "vulnerabilities": [],
                            "scan_summary": "Discovery complete",
                        },
                    ),
                    (
                        "call_web_1",
                        "web_scan_agent",
                        "Assess the discovered web target http://example.com:80",
                        {
                            "target": "http://example.com:80",
                            "wordpress_detected": False,
                            "nikto_result": None,
                            "wpscan_result": None,
                            "vulnerabilities": ["Missing security headers"],
                            "misconfigurations": [],
                            "scan_summary": "Web scan complete",
                        },
                    ),
                ],
                "Assessment completed.",
            )
        }
        orchestrator = self.build_orchestrator(responses)
        progress_events = []
        result = orchestrator.run_workflow(
            "Assess example.com",
            progress_callback=lambda step: progress_events.append(step),
        )
        self.assertEqual(len(progress_events), 2)
        self.assertEqual(progress_events[0]["agent"], "service_discover_agent")
        self.assertEqual(progress_events[0]["step"], 1)
        self.assertEqual(progress_events[1]["agent"], "web_scan_agent")
        self.assertEqual(progress_events[1]["step"], 2)
        self.assertEqual(len(result["execution_history"]), 2)


if __name__ == "__main__":
    unittest.main()
