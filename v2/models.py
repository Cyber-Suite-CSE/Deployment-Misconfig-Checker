from typing import Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from models.structured_results import NiktoResult, PortInfo, WPScanResult


class ServiceDiscoveryResult(BaseModel):
    """Merged service discovery findings from nmap and masscan."""

    target: str = Field(description="Target host, CIDR, or URL under test")
    host_up: bool = Field(default=True, description="Whether the target appears reachable")
    open_ports: List[PortInfo] = Field(default_factory=list, description="Merged open port list")
    detected_services: List[str] = Field(default_factory=list, description="Unique detected services")
    web_targets: List[str] = Field(default_factory=list, description="Derived web targets or ports")
    wordpress_detected: bool = Field(default=False, description="Whether WordPress evidence was found")
    wordpress_indicators: List[str] = Field(default_factory=list, description="Concrete WordPress clues such as paths, banners, or strings")
    http_paths_found: List[str] = Field(default_factory=list, description="Interesting HTTP paths or endpoints discovered during enumeration")
    server_banners: List[str] = Field(default_factory=list, description="Observed server banners or version strings")
    discovery_sources: List[str] = Field(default_factory=list, description="Tools that contributed findings")
    vulnerabilities: List[str] = Field(default_factory=list, description="Discovery-stage vulnerabilities")
    recommended_followups: List[str] = Field(default_factory=list, description="Recommended next reconnaissance steps")
    scan_summary: str = Field(default="", description="Short summary of discovery findings")

    @model_validator(mode="before")
    @classmethod
    def _ensure_summary(cls, data):
        if not isinstance(data, dict):
            return data
        if data.get("scan_summary"):
            return data

        open_ports = data.get("open_ports", []) or []
        detected_services = data.get("detected_services", []) or []
        if open_ports:
            data["scan_summary"] = f"Identified {len(open_ports)} open ports during service discovery."
        elif detected_services:
            data["scan_summary"] = "Service discovery detected reachable services."
        else:
            data["scan_summary"] = "Service discovery completed."

        data.setdefault("wordpress_indicators", [])
        data.setdefault("http_paths_found", [])
        data.setdefault("server_banners", [])
        data.setdefault("recommended_followups", [])
        return data


class WebScanResult(BaseModel):
    """Supervisor-level view of web scanning results."""

    target: str = Field(description="Web target scanned")
    wordpress_detected: bool = Field(default=False, description="Whether WordPress was confirmed or suspected")
    wordpress_indicators: List[str] = Field(default_factory=list, description="Concrete WordPress clues or confirmations")
    server_banners: List[str] = Field(default_factory=list, description="Observed server banners or software versions")
    nikto_result: Optional[NiktoResult] = Field(default=None, description="Nikto findings when available")
    wpscan_result: Optional[WPScanResult] = Field(default=None, description="WPScan findings when available")
    vulnerabilities: List[str] = Field(default_factory=list, description="Flattened web vulnerabilities")
    misconfigurations: List[str] = Field(default_factory=list, description="Flattened web misconfigurations")
    recommended_followups: List[str] = Field(default_factory=list, description="Recommended next reconnaissance steps")
    scan_summary: str = Field(default="", description="Short summary of web findings")

    @model_validator(mode="before")
    @classmethod
    def _normalize_nested_results(cls, data):
        if not isinstance(data, dict):
            return data

        nikto_result = data.get("nikto_result")
        if isinstance(nikto_result, dict):
            vulnerabilities = nikto_result.get("vulnerabilities", []) or []
            normalized_vulnerabilities = []
            for vuln in vulnerabilities:
                if isinstance(vuln, str):
                    normalized_vulnerabilities.append({"description": vuln})
                else:
                    normalized_vulnerabilities.append(vuln)
            nikto_result["vulnerabilities"] = normalized_vulnerabilities

            if not nikto_result.get("scan_summary"):
                if normalized_vulnerabilities:
                    nikto_result["scan_summary"] = (
                        f"Nikto identified {len(normalized_vulnerabilities)} findings."
                    )
                else:
                    nikto_result["scan_summary"] = "Nikto scan completed."

        wpscan_result = data.get("wpscan_result")
        if isinstance(wpscan_result, dict) and not wpscan_result.get("scan_summary"):
            if wpscan_result.get("vulnerabilities"):
                wpscan_result["scan_summary"] = (
                    f"WPScan identified {len(wpscan_result.get('vulnerabilities', []))} findings."
                )
            else:
                wpscan_result["scan_summary"] = "WPScan completed."

        if not data.get("scan_summary"):
            findings = len(data.get("vulnerabilities", []) or [])
            misconfigs = len(data.get("misconfigurations", []) or [])
            if findings or misconfigs:
                data["scan_summary"] = (
                    f"Web scan completed with {findings} vulnerabilities and {misconfigs} misconfigurations."
                )
            else:
                data["scan_summary"] = "Web scan completed."

        data.setdefault("wordpress_indicators", [])
        data.setdefault("server_banners", [])
        data.setdefault("recommended_followups", [])

        return data


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
    scan_summary: str = Field(default="", description="Short summary of exploit recon findings")

    @model_validator(mode="before")
    @classmethod
    def _ensure_summary(cls, data):
        if not isinstance(data, dict):
            return data
        if data.get("scan_summary"):
            return data

        candidates = data.get("candidate_modules", []) or []
        if candidates:
            data["scan_summary"] = (
                f"Exploit recon identified {len(candidates)} candidate modules."
            )
        else:
            data["scan_summary"] = "Exploit recon completed."
        return data


class V2ExecutionRecord(BaseModel):
    """Execution history item for legacy-compatible workflow results."""

    agent: str
    task: str
    structured_data: Dict
    raw_result: str
    timestamp: str
    tool_name: Optional[str] = None
    target: Optional[str] = None
