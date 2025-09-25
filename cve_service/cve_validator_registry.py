import os
import importlib
from typing import Dict, Optional, Type
from cve_validators.base_validator import CVEValidator


class CVEValidatorRegistry:
    """Registry for dynamically loading and managing CVE validators."""
    
    def __init__(self):
        self._validators: Dict[str, Type[CVEValidator]] = {}
        self._load_validators()
    
    def _load_validators(self):
        """Dynamically load all CVE validators from the cve_validators directory."""
        validators_dir = os.path.join(os.path.dirname(__file__), 'cve_validators')
        
        for filename in os.listdir(validators_dir):
            if filename.startswith('cve_') and filename.endswith('.py'):
                module_name = filename[:-3]  # Remove .py extension
                cve_id = module_name.replace('_', '-').upper()  # Convert to CVE-YYYY-NNNN format
                
                try:
                    # Import the module
                    module = importlib.import_module(f'cve_validators.{module_name}')
                    
                    # Find the validator class in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, CVEValidator) and 
                            attr != CVEValidator):
                            self._validators[cve_id] = attr
                            break
                
                except Exception as e:
                    print(f"Failed to load validator {module_name}: {e}")
    
    def get_validator(self, cve_id: str, cpe: str, cve_data: dict, scan_data: dict) -> Optional[CVEValidator]:
        """
        Get a validator instance for a specific CVE.
        
        Args:
            cve_id: The CVE identifier
            cpe: The CPE string
            cve_data: CVE data from NVD
            scan_data: Scan data from the target domain
            
        Returns:
            CVEValidator instance or None if no validator exists
        """
        validator_class = self._validators.get(cve_id.upper())
        if validator_class:
            return validator_class(cve_id, cpe, cve_data, scan_data)
        return None
    
    def has_validator(self, cve_id: str) -> bool:
        """Check if a validator exists for a CVE."""
        return cve_id.upper() in self._validators
    
    def list_validators(self) -> list:
        """List all available CVE validators."""
        return list(self._validators.keys())


# Singleton instance
_registry_instance = None


def get_validator_registry() -> CVEValidatorRegistry:
    """Get or create the singleton registry instance."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = CVEValidatorRegistry()
    return _registry_instance


def get_cve_validator(cve_id: str, cpe: str, cve_data: dict, scan_data: dict) -> Optional[CVEValidator]:
    """Convenience function to get a CVE validator."""
    registry = get_validator_registry()
    return registry.get_validator(cve_id, cpe, cve_data, scan_data)