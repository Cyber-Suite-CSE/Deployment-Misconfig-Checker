from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PortInfo(BaseModel):
    """Information about an open port"""
    port: str = Field(description="Port number")
    protocol: str = Field(description="Protocol (tcp/udp)")
    state: str = Field(description="Port state (open/closed/filtered)")
    service: Optional[str] = Field(default=None, description="Service name")
    version: Optional[str] = Field(default=None, description="Service version")


class NmapResult(BaseModel):
    """Structured nmap scan results"""
    target: str = Field(description="Target host/IP that was scanned")
    open_ports: List[PortInfo] = Field(default_factory=list, description="List of open ports with service info")
    detected_services: List[str] = Field(default_factory=list, description="List of detected service types (http, ssh, ftp, etc)")
    wordpress_detected: bool = Field(default=False, description="Whether WordPress was detected on any port")
    web_servers_found: bool = Field(default=False, description="Whether web servers (80/443/8080/8443) were found")
    os_detection: Optional[str] = Field(default=None, description="Detected operating system")
    vulnerabilities: List[str] = Field(default_factory=list, description="List of vulnerabilities found")
    host_up: bool = Field(default=True, description="Whether the host is up")
    scan_summary: str = Field(description="Brief summary of scan results")


class PluginInfo(BaseModel):
    """Information about a WordPress plugin"""
    name: str = Field(description="Plugin name")
    version: Optional[str] = Field(default=None, description="Plugin version")
    vulnerabilities: List[str] = Field(default_factory=list, description="Known vulnerabilities")


class ThemeInfo(BaseModel):
    """Information about a WordPress theme"""
    name: str = Field(description="Theme name")
    version: Optional[str] = Field(default=None, description="Theme version")
    vulnerabilities: List[str] = Field(default_factory=list, description="Known vulnerabilities")


class WPScanResult(BaseModel):
    """Structured WPScan results"""
    target_url: str = Field(description="Target WordPress URL")
    wordpress_version: Optional[str] = Field(default=None, description="Detected WordPress version")
    wordpress_confirmed: bool = Field(default=False, description="Whether WordPress was confirmed")
    plugins_found: List[PluginInfo] = Field(default_factory=list, description="Discovered plugins")
    themes_found: List[ThemeInfo] = Field(default_factory=list, description="Discovered themes")
    users_enumerated: List[str] = Field(default_factory=list, description="Enumerated usernames")
    vulnerabilities: List[Dict[str, str]] = Field(default_factory=list, description="List of vulnerabilities with details")
    interesting_findings: List[str] = Field(default_factory=list, description="Other interesting findings")
    scan_summary: str = Field(description="Brief summary of scan results")


class VulnerabilityInfo(BaseModel):
    """Information about a vulnerability"""
    id: Optional[str] = Field(default=None, description="Vulnerability ID (CVE, OSVDB, etc)")
    description: str = Field(description="Vulnerability description")
    severity: Optional[str] = Field(default=None, description="Severity level")


class NiktoResult(BaseModel):
    """Structured Nikto scan results"""
    target: str = Field(description="Target host/URL")
    port: int = Field(description="Target port")
    server_info: Optional[str] = Field(default=None, description="Web server software and version")
    wordpress_detected: bool = Field(default=False, description="Whether WordPress was detected")
    vulnerabilities: List[VulnerabilityInfo] = Field(default_factory=list, description="List of vulnerabilities found")
    interesting_findings: List[str] = Field(default_factory=list, description="Interesting files, directories, or configurations")
    ssl_info: Optional[Dict[str, str]] = Field(default=None, description="SSL/TLS configuration information")
    outdated_software: List[str] = Field(default_factory=list, description="Outdated software detected")
    misconfigurations: List[str] = Field(default_factory=list, description="Server misconfigurations")
    scan_summary: str = Field(description="Brief summary of scan results")


class ExploitInfo(BaseModel):
    """Information about a Metasploit exploit module"""
    name: str = Field(description="Exploit module name/path")
    description: Optional[str] = Field(default=None, description="Exploit description")
    rank: Optional[str] = Field(default=None, description="Exploit ranking (excellent, great, good, normal, etc)")
    targets: List[str] = Field(default_factory=list, description="Available targets for the exploit")


class PayloadInfo(BaseModel):
    """Information about a Metasploit payload"""
    name: str = Field(description="Payload name/path")
    platform: Optional[str] = Field(default=None, description="Target platform (windows, linux, etc)")
    arch: Optional[str] = Field(default=None, description="Architecture (x86, x64, etc)")
    description: Optional[str] = Field(default=None, description="Payload description")


class SessionInfo(BaseModel):
    """Information about an active Metasploit session"""
    session_id: str = Field(description="Session ID")
    session_type: str = Field(description="Session type (meterpreter, shell, etc)")
    target: str = Field(description="Target host/IP")
    info: Optional[str] = Field(default=None, description="Additional session information")
    via_exploit: Optional[str] = Field(default=None, description="Exploit used to obtain session")


class ModuleResult(BaseModel):
    """Result from running a Metasploit module"""
    module_type: str = Field(description="Module type (exploit, auxiliary, post)")
    module_name: str = Field(description="Module path/name")
    success: bool = Field(description="Whether the module executed successfully")
    output: str = Field(description="Module execution output")
    session_created: Optional[str] = Field(default=None, description="Session ID if created")


class MetasploitResult(BaseModel):
    """Structured Metasploit operation results"""
    request: str = Field(description="Original request/operation")
    exploits_found: List[ExploitInfo] = Field(default_factory=list, description="List of discovered exploits")
    payloads_available: List[PayloadInfo] = Field(default_factory=list, description="Available payloads")
    sessions_active: List[SessionInfo] = Field(default_factory=list, description="Active sessions")
    exploitation_attempted: bool = Field(default=False, description="Whether exploitation was attempted")
    payload_generated: bool = Field(default=False, description="Whether a payload was generated")
    post_exploitation_performed: bool = Field(default=False, description="Whether post-exploitation was performed")
    module_results: List[ModuleResult] = Field(default_factory=list, description="Results from module executions")
    vulnerabilities_exploited: List[str] = Field(default_factory=list, description="Successfully exploited vulnerabilities")
    scan_summary: str = Field(description="Brief summary of Metasploit operations")
