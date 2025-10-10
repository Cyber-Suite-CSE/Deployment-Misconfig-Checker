import json
import glob
import os
from typing import List, Dict, Any, Optional


class DataLoader:
    
    def __init__(self, services_dir: str):
        self.services_dir = services_dir
    
    def load_services_from_directory(self) -> List[Dict[str, Any]]:
        all_services = []
        json_files = glob.glob(os.path.join(self.services_dir, "*.json"))
        
        print(f"DEBUG: Loading services from directory: {self.services_dir}")
        print(f"DEBUG: Found {len(json_files)} JSON files")
        
        for json_file in json_files:
            try:
                print(f"DEBUG: Loading {json_file}")
                with open(json_file, "r", encoding="utf-8") as f:
                    services = json.load(f)
                    all_services.extend(services)
                    print(f"DEBUG: Loaded {len(services)} services from {os.path.basename(json_file)}")
            except Exception as e:
                print(f"DEBUG: Error loading {json_file}: {e}")
        
        print(f"DEBUG: Successfully loaded {len(all_services)} total services")
        
        total_fingerprints = 0
        total_detection_fingerprints = 0
        total_exclusions = 0
        
        for service in all_services:
            fps = service.get("response", {}).get("fingerprints", [])
            det_fps = service.get("response", {}).get("detectionFingerprints", [])
            excl = service.get("response", {}).get("exclusionPatterns", [])
            
            total_fingerprints += len(fps)
            total_detection_fingerprints += len(det_fps)
            total_exclusions += len(excl)
        
        print(f"DEBUG: Total fingerprints: {total_fingerprints}")
        print(f"DEBUG: Total detectionFingerprints: {total_detection_fingerprints}")
        print(f"DEBUG: Total exclusionPatterns: {total_exclusions}")
        
        return all_services
    
    def load_services(self) -> List[Dict[str, Any]]:
        return self.load_services_from_directory()
    
    def load_target_data(self, path: str) -> Dict[str, Any]:
        print(f"DEBUG: Loading target data from {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"DEBUG: Successfully loaded target data with keys: {list(data.keys())}")
        return data
