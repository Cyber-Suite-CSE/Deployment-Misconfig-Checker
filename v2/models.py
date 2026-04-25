from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from models.structured_results import NiktoResult, PortInfo, WPScanResult


class ServiceDiscoveryResult(BaseModel):
    """Merged service discovery findings from nmap and masscan."""

    target: str = Field(description="Target host, CIDR, or URL under test")
    host_up: bool = Field(default=True, description="Whether the target appears reachable")
    open_ports: List[PortInfo] = Field(default_factory=list, description="Merged open port list")
    detected_services: List[str] = Field(default_factory=list, description="Unique detected services")
    web_targets: List[str] = Field(default_factory=list, description="Derived web targets or ports")
    wordpress_detected: bool = Field(default=False, description="Whether WordPress evidence was found")
    discovery_sources: List[str] = Field(default_factory=list, description="Tools that contributed findings")
    vulnerabilities: List[str] = Field(default_factory=list, description="Discovery-stage vulnerabilities")
    scan_summary: str = Field(description="Short summary of discovery findings")


class WebScanResult(BaseModel):
    """Supervisor-level view of web scanning results."""

    target: str = Field(description="Web target scanned")
    wordpress_detected: bool = Field(default=False, description="Whether WordPress was confirmed or suspected")
    nikto_result: Optional[NiktoResult] = Field(default=None, description="Nikto findings when available")
    wpscan_result: Optional[WPScanResult] = Field(default=None, description="WPScan findings when available")
    vulnerabilities: List[str] = Field(default_factory=list, description="Flattened web vulnerabilities")
    misconfigurations: List[str] = Field(default_factory=list, description="Flattened web misconfigurations")
    scan_summary: str = Field(description="Short summary of web findings")


class ExploitReconCandidate(BaseModel):
    """A Metasploit module or exploit hypothesis matched during recon."""

    module: str = Field(description="Candidate Metasploit module path or identifier")
    confidence: float = Field(default=0.0, description="Confidence score between 0 and 1")
    rationale: str = Field(description="Why this module appears relevant")
    matched_findings: List[str] = Field(default_factory=list, description="Findings that support this candidate")


class ExploitReconResult(BaseModel):
    """Recon-only exploitability assessment."""

    target: str = Field(description="Target host or application")
    candidate_modules: List[ExploitReconCandidate] = Field(default_factory=list, description="Potential modules")
    matched_services: List[str] = Field(default_factory=list, description="Services relevant to exploit matching")
    matched_vulnerabilities: List[str] = Field(default_factory=list, description="Vulnerabilities relevant to exploit matching")
    recommended_next_steps: List[str] = Field(default_factory=list, description="Non-executing follow-up recommendations")
    scan_summary: str = Field(description="Short summary of exploit recon findings")


class V2ExecutionRecord(BaseModel):
    """Execution history item for legacy-compatible workflow results."""

    agent: str
    task: str
    structured_data: Dict
    raw_result: str
    timestamp: str
    tool_name: Optional[str] = None
    target: Optional[str] = None
