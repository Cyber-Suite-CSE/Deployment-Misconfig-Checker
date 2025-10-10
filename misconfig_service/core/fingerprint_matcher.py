from typing import List, Dict, Any


class FingerprintMatcher:
    
    def check_fingerprints_in_response(
        self, 
        services: List[Dict[str, Any]], 
        response_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        matches = []
        
        if not response_data.get("success"):
            print(f"DEBUG: Skipping fingerprint check for failed request")
            return matches
        
        content = response_data.get("content", "")
        headers = response_data.get("headers", {})
        
        content_text = content
        headers_text = " ".join([f"{k}: {v}" for k, v in headers.items()])
        combined_text = content_text + " " + headers_text
        
        print(f"DEBUG: Checking {len(services)} services for fingerprints...")
        print(f"DEBUG: Content length: {len(content_text)} characters")
        print(f"DEBUG: Headers text length: {len(headers_text)} characters")
        print(f"DEBUG: Response headers: {list(headers.keys())}")
        
        for service in services:
            fingerprints = service.get("response", {}).get("fingerprints", [])
            detection_fingerprints = service.get("response", {}).get("detectionFingerprints", [])
            exclusion_patterns = service.get("response", {}).get("exclusionPatterns", [])
            
            all_fingerprints = set(fingerprints) | set(detection_fingerprints)
            
            service_name = service.get("metadata", {}).get("serviceName", "Unknown")
            print(f"DEBUG: Checking service '{service_name}' with {len(all_fingerprints)} fingerprints and {len(exclusion_patterns)} exclusion patterns")
            
            excluded = False
            for exclusion in exclusion_patterns:
                if exclusion and exclusion in combined_text:
                    print(f"DEBUG: EXCLUSION MATCH! Service: {service_name}, Exclusion pattern: '{exclusion}' - SKIPPING this service")
                    excluded = True
                    break
            
            if excluded:
                continue
            
            matched_fingerprints = []
            found_in_content_any = False
            found_in_headers_any = False
            
            for fp in all_fingerprints:
                if fp:
                    found_in_content = fp in content_text
                    found_in_headers = fp in headers_text
                    found_in_combined = fp in combined_text
                    
                    if found_in_combined:
                        matched_fingerprints.append(fp)
                        if found_in_content:
                            found_in_content_any = True
                        if found_in_headers:
                            found_in_headers_any = True
                        
                        location = []
                        if found_in_content:
                            location.append("content")
                        if found_in_headers:
                            location.append("headers")
                        
                        location_str = " and ".join(location) if location else "combined text"
                        print(f"DEBUG: MATCH FOUND! Service: {service_name}, Fingerprint: '{fp}' (found in: {location_str})")
                    else:
                        print(f"DEBUG: No match for fingerprint '{fp}' in service '{service_name}'")
            
            if matched_fingerprints:
                exploit_type = service.get("metadata", {}).get("exploitType", None)
                
                match_entry = {
                    "url": response_data["url"],
                    "service": service_name,
                    "service_id": service.get("id", "Unknown"),
                    "fingerprints": matched_fingerprints,
                    "fingerprint": matched_fingerprints[0],
                    "description": service.get("metadata", {}).get("description", ""),
                    "references": service.get("metadata", {}).get("references", []),
                    "found_in_content": found_in_content_any,
                    "found_in_headers": found_in_headers_any
                }
                
                if exploit_type:
                    match_entry["exploit_type"] = exploit_type
                    print(f"DEBUG: Added exploitType '{exploit_type}' to match for service '{service_name}'")
                else:
                    print(f"DEBUG: No exploitType defined for service '{service_name}' - exploit matching will use fallback")
                
                matches.append(match_entry)
        
        print(f"DEBUG: Found {len(matches)} fingerprint matches for this response")
        return matches
