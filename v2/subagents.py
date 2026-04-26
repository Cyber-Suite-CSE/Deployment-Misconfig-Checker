from typing import Any, Dict, Optional

from tools.nikto_tool import execute_nikto
from tools.nmap_tool import execute_nmap
from tools.wpscan_tool import execute_wpscan
from v2.models import ExploitReconResult, ServiceDiscoveryResult, WebScanResult
from v2.prompts import (
    EXPLOIT_RECON_SYSTEM_PROMPT,
    SERVICE_DISCOVER_SYSTEM_PROMPT,
    WEB_SCAN_SYSTEM_PROMPT,
)
from v2.tools import (
    execute_masscan,
    get_exploit_details,
    list_available_exploits,
    search_exploits_by_cve,
)


class BaseSubagentSpec:
    """Configuration wrapper for a Deep Agents subagent."""

    name: str
    description: str
    system_prompt: str
    response_format: Any

    def __init__(self, llm: Any) -> None:
        self.llm = llm

    def get_tools(self):
        raise NotImplementedError

    def as_supervisor_config(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "system_prompt": self.system_prompt,
            "tools": self.get_tools(),
            "model": self.llm,
            "response_format": self.response_format,
        }


class ServiceDiscoverSubagent(BaseSubagentSpec):
    name = "service_discover_agent"
    description = "Performs host discovery, fast port discovery, service fingerprinting, and target normalization."
    system_prompt = SERVICE_DISCOVER_SYSTEM_PROMPT
    response_format = ServiceDiscoveryResult

    def get_tools(self):
        return [execute_nmap, execute_masscan]


class WebScanSubagent(BaseSubagentSpec):
    name = "web_scan_agent"
    description = "Performs web and WordPress security scans for confirmed or likely web targets."
    system_prompt = WEB_SCAN_SYSTEM_PROMPT
    response_format = WebScanResult

    def get_tools(self):
        return [execute_nikto, execute_wpscan]


class ExploitReconSubagent(BaseSubagentSpec):
    name = "exploit_recon_agent"
    description = "Performs recon-only exploitability correlation using passive Metasploit search, CVE matching, and exploit detail lookup."
    system_prompt = EXPLOIT_RECON_SYSTEM_PROMPT
    response_format = ExploitReconResult

    def get_tools(self):
        return [list_available_exploits, search_exploits_by_cve, get_exploit_details]
