import re
from typing import Any, Dict, List, Optional

from models.structured_results import NiktoResult, NmapResult, PortInfo, WPScanResult
from prompts import PromptProvider
from v2.models import ExploitReconCandidate, ExploitReconResult, ServiceDiscoveryResult, WebScanResult


def _safe_model_dump(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        return result
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return dict(result)


def _invoke_structured_parse(llm: Any, schema: Any, prompt: str) -> Dict[str, Any]:
    if llm is None:
        raise ValueError("An LLM instance is required for structured parsing")
    structured_llm = llm.with_structured_output(schema)
    return _safe_model_dump(structured_llm.invoke(prompt))


def parse_nmap_output(raw_output: str, llm: Any) -> Dict[str, Any]:
    try:
        prompt = PromptProvider.get_agent_prompt("nmap", "parsing").format(
            raw_output=raw_output
        )
        return _invoke_structured_parse(llm, NmapResult, prompt)
    except Exception as exc:
        return {
            "target": "unknown",
            "open_ports": [],
            "detected_services": [],
            "wordpress_detected": False,
            "web_servers_found": False,
            "os_detection": None,
            "vulnerabilities": [],
            "host_up": "down" not in raw_output.lower(),
            "scan_summary": f"Failed to parse nmap output: {exc}",
        }


def parse_wpscan_output(raw_output: str, llm: Any) -> Dict[str, Any]:
    try:
        prompt = PromptProvider.get_agent_prompt("wpscan", "parsing").format(
            raw_output=raw_output
        )
        return _invoke_structured_parse(llm, WPScanResult, prompt)
    except Exception as exc:
        return {
            "target_url": "unknown",
            "wordpress_version": None,
            "wordpress_confirmed": False,
            "plugins_found": [],
            "themes_found": [],
            "users_enumerated": [],
            "vulnerabilities": [],
            "interesting_findings": [],
            "scan_summary": f"Failed to parse WPScan output: {exc}",
        }


def parse_nikto_output(raw_output: str, llm: Any) -> Dict[str, Any]:
    try:
        prompt = PromptProvider.get_agent_prompt("nikto", "parsing").format(
            raw_output=raw_output
        )
        return _invoke_structured_parse(llm, NiktoResult, prompt)
    except Exception as exc:
        return {
            "target": "unknown",
            "port": 80,
            "server_info": None,
            "wordpress_detected": False,
            "vulnerabilities": [],
            "interesting_findings": [],
            "ssl_info": None,
            "outdated_software": [],
            "misconfigurations": [],
            "scan_summary": f"Failed to parse Nikto output: {exc}",
        }


def parse_masscan_output(raw_output: str, fallback_target: str = "unknown") -> Dict[str, Any]:
    target = fallback_target
    open_ports: List[Dict[str, Any]] = []
    detected_services: List[str] = []

    for line in raw_output.splitlines():
        match = re.search(r"Discovered open port (\d+)/(tcp|udp) on ([^\s]+)", line)
        if not match:
            continue
        port, protocol, host = match.groups()
        target = host or target
        open_ports.append(
            {
                "port": port,
                "protocol": protocol,
                "state": "open",
                "service": None,
                "version": None,
            }
        )

    return {
        "target": target,
        "open_ports": open_ports,
        "detected_services": detected_services,
        "host_up": bool(open_ports) or "up" in raw_output.lower(),
        "scan_summary": (
            f"Masscan identified {len(open_ports)} open ports"
            if open_ports
            else "Masscan did not report open ports"
        ),
    }


def _dedupe_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for port in ports:
        key = (port.get("port"), port.get("protocol"))
        if key in seen:
            continue
        deduped.append(port)
        seen.add(key)
    return deduped


def _derive_web_targets(target: str, open_ports: List[Dict[str, Any]], detected_services: List[str]) -> List[str]:
    web_targets: List[str] = []
    web_ports = {"80", "443", "8080", "8443", "8000"}
    web_services = {"http", "https", "ssl/http", "http-proxy"}

    for port in open_ports:
        service = (port.get("service") or "").lower()
        port_number = str(port.get("port"))
        if port_number in web_ports or service in web_services:
            scheme = "https" if port_number in {"443", "8443"} or "https" in service else "http"
            web_targets.append(f"{scheme}://{target}:{port_number}")

    if any(service.lower() in web_services for service in detected_services):
        web_targets.append(target)

    return sorted(set(web_targets))


def merge_service_discovery_results(
    nmap_data: Optional[Dict[str, Any]],
    masscan_data: Optional[Dict[str, Any]],
    fallback_target: str,
) -> Dict[str, Any]:
    nmap_data = nmap_data or {}
    masscan_data = masscan_data or {}

    target = (
        nmap_data.get("target")
        or masscan_data.get("target")
        or fallback_target
        or "unknown"
    )
    merged_ports = _dedupe_ports(
        list(nmap_data.get("open_ports", [])) + list(masscan_data.get("open_ports", []))
    )
    detected_services = sorted(
        {
            service
            for service in list(nmap_data.get("detected_services", []))
            + list(masscan_data.get("detected_services", []))
            if service
        }
    )
    vulnerabilities = list(dict.fromkeys(nmap_data.get("vulnerabilities", [])))
    web_targets = _derive_web_targets(target, merged_ports, detected_services)

    summary_parts = []
    if merged_ports:
        summary_parts.append(f"Identified {len(merged_ports)} open ports")
    if detected_services:
        summary_parts.append(f"Detected services: {', '.join(detected_services[:5])}")
    if web_targets:
        summary_parts.append("Web exposure detected")
    if not summary_parts:
        summary_parts.append("No service discovery findings were extracted")

    return ServiceDiscoveryResult(
        target=target,
        host_up=bool(nmap_data.get("host_up", True) or masscan_data.get("host_up", False)),
        open_ports=[PortInfo(**port) for port in merged_ports],
        detected_services=detected_services,
        web_targets=web_targets,
        wordpress_detected=bool(nmap_data.get("wordpress_detected", False)),
        discovery_sources=[
            source
            for source, data in (("nmap", nmap_data), ("masscan", masscan_data))
            if data
        ],
        vulnerabilities=vulnerabilities,
        scan_summary=". ".join(summary_parts),
    ).model_dump()


def merge_web_scan_results(
    nikto_data: Optional[Dict[str, Any]],
    wpscan_data: Optional[Dict[str, Any]],
    fallback_target: str,
) -> Dict[str, Any]:
    nikto_data = nikto_data or {}
    wpscan_data = wpscan_data or {}

    target = (
        wpscan_data.get("target_url")
        or nikto_data.get("target")
        or fallback_target
        or "unknown"
    )

    vulnerabilities: List[str] = []
    for vuln in nikto_data.get("vulnerabilities", []):
        if isinstance(vuln, dict):
            vulnerabilities.append(vuln.get("description", str(vuln)))
        else:
            vulnerabilities.append(str(vuln))

    for vuln in wpscan_data.get("vulnerabilities", []):
        if isinstance(vuln, dict):
            vulnerabilities.append(vuln.get("title") or vuln.get("description") or str(vuln))
        else:
            vulnerabilities.append(str(vuln))

    misconfigurations = list(nikto_data.get("misconfigurations", []))
    interesting_findings = list(wpscan_data.get("interesting_findings", []))
    if interesting_findings:
        misconfigurations.extend(interesting_findings)

    summary_parts = []
    if nikto_data and nikto_data.get("scan_summary"):
        summary_parts.append(nikto_data["scan_summary"])
    if wpscan_data and wpscan_data.get("scan_summary"):
        summary_parts.append(wpscan_data["scan_summary"])
    if not summary_parts:
        summary_parts.append("Web scan completed without parsed findings")

    return WebScanResult(
        target=target,
        wordpress_detected=bool(
            nikto_data.get("wordpress_detected", False)
            or wpscan_data.get("wordpress_confirmed", False)
        ),
        nikto_result=NiktoResult(**nikto_data) if nikto_data else None,
        wpscan_result=WPScanResult(**wpscan_data) if wpscan_data else None,
        vulnerabilities=list(dict.fromkeys(vulnerabilities)),
        misconfigurations=list(dict.fromkeys(misconfigurations)),
        scan_summary=". ".join(summary_parts),
    ).model_dump()


def parse_exploit_recon_output(
    raw_output: str,
    target: str,
    context_summary: str,
) -> Dict[str, Any]:
    modules = []
    for line in raw_output.splitlines():
        for match in re.findall(r"(exploit/[^\s]+|auxiliary/[^\s]+)", line):
            modules.append(
                ExploitReconCandidate(
                    module=match,
                    confidence=0.6,
                    rationale="Matched from Metasploit search output",
                    matched_findings=[context_summary] if context_summary else [],
                )
            )

    module_list = list({candidate.module: candidate for candidate in modules}.values())
    matched_vulnerabilities = [context_summary] if context_summary else []
    summary = (
        f"Identified {len(module_list)} candidate Metasploit modules"
        if module_list
        else "No Metasploit modules were extracted from recon output"
    )

    return ExploitReconResult(
        target=target or "unknown",
        candidate_modules=module_list,
        matched_services=[],
        matched_vulnerabilities=matched_vulnerabilities,
        recommended_next_steps=[
            "Validate the service and version match before any exploit testing",
            "Confirm legal authorization before enabling exploit execution in a later phase",
        ],
        scan_summary=summary,
    ).model_dump()
