import json
import requests
import urllib3
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
import time

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVICES_JSON_PATH = "data-sources/services.json"

def load_services(path: str) -> List[Dict[str, Any]]:
    """Load services configuration from JSON file"""
    print(f"DEBUG: Loading services from {path}")
    with open(path, "r", encoding="utf-8") as f:
        services = json.load(f)
    print(f"DEBUG: Successfully loaded {len(services)} services")
    
    # Show summary of what we're checking for
    total_fingerprints = 0
    total_detection_fingerprints = 0
    total_exclusions = 0
    
    for service in services:
        fps = service.get("response", {}).get("fingerprints", [])
        det_fps = service.get("response", {}).get("detectionFingerprints", [])
        excl = service.get("response", {}).get("exclusionPatterns", [])
        
        total_fingerprints += len(fps)
        total_detection_fingerprints += len(det_fps)
        total_exclusions += len(excl)
    
    print(f"DEBUG: Total fingerprints: {total_fingerprints}")
    print(f"DEBUG: Total detectionFingerprints: {total_detection_fingerprints}")
    print(f"DEBUG: Total exclusionPatterns: {total_exclusions}")
    
    return services
