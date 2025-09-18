from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Any, List


class CVEValidator(ABC):
    """Base class for all CVE-specific validators."""
    
    def __init__(self, cve_id: str, cpe: str, cve_data: Dict[str, Any], scan_data: Dict[str, Any]):
        """
        Initialize CVE validator.
        
        Args:
            cve_id: The CVE identifier (e.g., "CVE-2024-3566")
            cpe: The CPE string for the affected software
            cve_data: Full CVE data from NVD including description, severity
            scan_data: Scan data from the target domain (from cpe_response.json)
        """
        self.cve_id = cve_id
        self.cpe = cpe
        self.cve_data = cve_data
        self.scan_data = scan_data
        self.vendor, self.product, self.version = self._parse_cpe(cpe)
    
    def _parse_cpe(self, cpe: str) -> Tuple[str, str, str]:
        """Parse CPE string to extract vendor, product, and version."""
        parts = cpe.split(':')
        if len(parts) >= 6:
            return parts[3], parts[4], parts[5]
        return "", "", ""
    
    def _compare_versions(self, installed_version: str, affected_version: str, operator: str = "<=") -> bool:
        """
        Compare version strings.
        
        Args:
            installed_version: Version found in scan
            affected_version: Version specified in CVE
            operator: Comparison operator ("<=", "<", ">=", ">", "==")
        
        Returns:
            True if comparison holds, False otherwise
        """
        try:
            from packaging import version
            installed = version.parse(installed_version)
            affected = version.parse(affected_version)
            
            if operator == "<=":
                return installed <= affected
            elif operator == "<":
                return installed < affected
            elif operator == ">=":
                return installed >= affected
            elif operator == ">":
                return installed > affected
            elif operator == "==":
                return installed == affected
            else:
                return False
        except:
            # Fallback to string comparison if packaging is not available
            if operator == "<=":
                return installed_version <= affected_version
            elif operator == "==":
                return installed_version == affected_version
            else:
                return False
    
    def is_port_open(self, port: int) -> bool:
        """Check if a specific port is open on the scanned domain."""
        open_ports = self.scan_data.get('services', {}).get('open_ports', {})
        return str(port) in open_ports
    
    def get_service_info(self, port: int) -> Optional[Dict[str, str]]:
        """Get service information for a specific port."""
        open_ports = self.scan_data.get('services', {}).get('open_ports', {})
        return open_ports.get(str(port))
    
    def get_web_server_info(self) -> Optional[str]:
        """Get web server information from scan data."""
        web_tech = self.scan_data.get('web_technologies', {})
        for url, info in web_tech.items():
            if 'server' in info:
                return info['server']
        return None
    
    def get_web_technologies(self) -> Dict[str, Any]:
        """Get all web technologies detected."""
        return self.scan_data.get('web_technologies', {})
    
    def has_technology(self, tech_name: str) -> bool:
        """Check if a specific technology is present in web scan."""
        web_tech = self.get_web_technologies()
        tech_lower = tech_name.lower()
        
        for url, info in web_tech.items():
            # Check server header
            if 'server' in info and tech_lower in info['server'].lower():
                return True
            # Check X-Powered-By header
            if 'x_powered_by' in info and tech_lower in info['x_powered_by'].lower():
                return True
        
        return False
    
    def get_open_ports(self) -> List[int]:
        """Get list of all open ports."""
        open_ports = self.scan_data.get('services', {}).get('open_ports', {})
        return [int(port) for port in open_ports.keys()]
    
    @abstractmethod
    def validate(self) -> Tuple[bool, str]:
        """
        Validate if this CVE applies to the scanned domain.
        
        Returns:
            Tuple of (is_applicable, reason)
        """
        pass
    
    @abstractmethod
    def get_affected_versions(self) -> Dict[str, Optional[str]]:
        """
        Get the version range affected by this CVE.
        
        Returns:
            Dict with 'min' and 'max' version keys
        """
        pass
    
    def get_severity(self) -> str:
        """Get the severity of this CVE."""
        return self.cve_data.get('severity', 'UNKNOWN')
    
    def get_description(self) -> str:
        """Get the description of this CVE."""
        return self.cve_data.get('description', '')