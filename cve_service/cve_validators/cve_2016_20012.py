from typing import Dict, Optional, Tuple
from .base_validator import CVEValidator


class CVE_2016_20012_Validator(CVEValidator):
    """
    Validator for CVE-2016-20012: OpenSSH user enumeration vulnerability.
    
    OpenSSH through 8.7 allows remote attackers, who have a suspicion that a 
    certain combination of username and public key is known to an SSH server, 
    to test whether this suspicion is correct.
    """
    
    def validate(self) -> Tuple[bool, str]:
        """
        Check if this CVE applies to the scanned domain.
        
        Validation checks:
        1. Is OpenSSH installed and version <= 8.7?
        2. Is SSH service (port 22) exposed on the domain?
        """
        # Check if this is an OpenSSH CPE
        if self.product != "openssh":
            return False, "CVE only applies to OpenSSH"
        
        # Check version (affected: through 8.7)
        if self.version:
            version_check = self._compare_versions(self.version, "8.7", "<=")
            if not version_check:
                return False, f"OpenSSH version {self.version} is not affected (only <= 8.7)"
        
        # Check if SSH port (22) is open on the scanned domain
        if not self.is_port_open(22):
            return False, "SSH port 22 is not open on the target domain"
        
        # Check if the SSH service banner matches OpenSSH
        ssh_service = self.get_service_info(22)
        if ssh_service:
            banner = ssh_service.get('banner', '')
            if 'openssh' not in banner.lower():
                return False, f"SSH service banner doesn't indicate OpenSSH: {banner}"
        
        return True, f"Domain is running OpenSSH {self.version} on port 22 which is vulnerable to user enumeration"
    
    def get_affected_versions(self) -> Dict[str, Optional[str]]:
        """OpenSSH versions through 8.7 are affected."""
        return {
            "min": None,  # All versions up to 8.7
            "max": "8.7"
        }