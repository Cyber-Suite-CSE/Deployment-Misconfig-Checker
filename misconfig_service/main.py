import json
import requests
import urllib3
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
import time

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVICES_JSON_PATH = "data_sources/services.json"

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

def load_target_data(path: str) -> Dict[str, Any]:
    """Load target data from JSON file"""
    print(f"DEBUG: Loading target data from {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"DEBUG: Successfully loaded target data with keys: {list(data.keys())}")
    return data

def extract_urls_from_target(target_data: Dict[str, Any]) -> Set[str]:
    """Extract all URLs from the target data"""
    urls = set()
    
    print("DEBUG: Extracting URLs from target data...")
    
    # Extract from web_technologies
    if "web_technologies" in target_data:
        web_tech_urls = list(target_data["web_technologies"].keys())
        print(f"DEBUG: Found {len(web_tech_urls)} URLs in web_technologies")
        for url in web_tech_urls:
            urls.add(url)
            print(f"DEBUG: Added web_tech URL: {url}")
    
    # Extract from directories
    if "directories" in target_data:
        dir_count = 0
        for directory in target_data["directories"]:
            if "url" in directory:
                urls.add(directory["url"])
                dir_count += 1
                print(f"DEBUG: Added directory URL: {directory['url']}")
        print(f"DEBUG: Found {dir_count} URLs in directories")
    
    # Extract from api_endpoints
    if "api_endpoints" in target_data:
        api_count = 0
        for endpoint in target_data["api_endpoints"]:
            if "url" in endpoint:
                urls.add(endpoint["url"])
                api_count += 1
                print(f"DEBUG: Added API endpoint URL: {endpoint['url']}")
        print(f"DEBUG: Found {api_count} URLs in api_endpoints")
    
    print(f"DEBUG: Total unique URLs extracted: {len(urls)}")
    return urls

def make_request(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Make HTTP request and return response details"""
    print(f"DEBUG: Making request to {url}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        
        print(f"DEBUG: Request successful - Status: {response.status_code}, Content length: {len(response.text)}")
        
        return {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text,
            "success": True
        }
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Request failed for {url} - Error: {str(e)}")
        return {
            "url": url,
            "error": str(e),
            "success": False
        }

def check_fingerprints_in_response(services: List[Dict[str, Any]], response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for fingerprints in a single response"""
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
        
        for fp in all_fingerprints:
            if fp:
                found_in_content = fp in content_text
                found_in_headers = fp in headers_text
                found_in_combined = fp in combined_text
                
                if found_in_combined:
                    location = []
                    if found_in_content:
                        location.append("content")
                    if found_in_headers:
                        location.append("headers")
                    
                    location_str = " and ".join(location) if location else "combined text"
                    print(f"DEBUG: MATCH FOUND! Service: {service_name}, Fingerprint: '{fp}' (found in: {location_str})")
                    
                    matches.append({
                        "url": response_data["url"],
                        "service": service_name,
                        "service_id": service.get("id", "Unknown"),
                        "fingerprint": fp,
                        "description": service.get("metadata", {}).get("description", ""),
                        "references": service.get("metadata", {}).get("references", []),
                        "found_in_content": found_in_content,
                        "found_in_headers": found_in_headers
                    })
                else:
                    print(f"DEBUG: No match for fingerprint '{fp}' in service '{service_name}'")
    
    print(f"DEBUG: Found {len(matches)} fingerprint matches for this response")
    return matches

def scan_target(services: List[Dict[str, Any]], target_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan all URLs from target data for fingerprints"""
    urls = extract_urls_from_target(target_data)
    all_matches = []
    
    print(f"DEBUG: Starting scan of {len(urls)} URLs...")
    
    for i, url in enumerate(urls, 1):
        print(f"\nDEBUG: === Scanning URL {i}/{len(urls)} ===")
        print(f"DEBUG: Current URL: {url}")
        
        response_data = make_request(url)
        
        if response_data["success"]:
            print(f"DEBUG: Request successful, checking for fingerprints...")
            matches = check_fingerprints_in_response(services, response_data)
            all_matches.extend(matches)
            print(f"DEBUG: Scan complete for {url} - Status: {response_data['status_code']} - Found {len(matches)} fingerprint matches")
        else:
            print(f"DEBUG: Request failed for {url} - Error: {response_data['error']}")
        
        # Small delay to be respectful
        print(f"DEBUG: Waiting 0.5 seconds before next request...")
        time.sleep(0.5)
    
    print(f"\nDEBUG: === SCAN COMPLETE ===")
    print(f"DEBUG: Total fingerprint matches found: {len(all_matches)}")
    return all_matches

def main():
    """Main function"""
    print("DEBUG: Starting fingerprint scanner...")
    try:
        # Load services configuration
        print("DEBUG: Step 1 - Loading services configuration...")
        services = load_services(SERVICES_JSON_PATH)
        print(f"DEBUG: Loaded {len(services)} service fingerprints")
        
        # Get target data file path
        print("DEBUG: Step 2 - Getting target data file...")
        target_file = input("Enter path to target data JSON file: ").strip()
        if not target_file:
            print("DEBUG: No file provided. Exiting.")
            return
        
        # Load target data
        print("DEBUG: Step 3 - Loading target data...")
        target_data = load_target_data(target_file)
        
        # Scan target
        print("DEBUG: Step 4 - Starting target scan...")
        matches = scan_target(services, target_data)
        
        # Display results
        print("DEBUG: Step 5 - Displaying results...")
        if matches:
            print(f"\nDEBUG: === FINGERPRINT SCAN RESULTS ===")
            print(f"DEBUG: Found {len(matches)} total fingerprint matches:\n")
            
            for i, match in enumerate(matches, 1):
                print(f"DEBUG: Match {i}/{len(matches)}:")
                print(f"URL: {match['url']}")
                print(f"Service: {match['service']} (ID: {match['service_id']})")
                print(f"Fingerprint: {match['fingerprint']}")
                print(f"Description: {match['description']}")
                
                # Show where the fingerprint was found
                locations = []
                if match.get('found_in_content'):
                    locations.append("Response Content")
                if match.get('found_in_headers'):
                    locations.append("Response Headers")
                if locations:
                    print(f"Found in: {' and '.join(locations)}")
                
                if match['references']:
                    print(f"References: {', '.join(match['references'])}")
                print("-" * 50)
        else:
            print("\nDEBUG: No fingerprints found in the scanned URLs.")
            
    except FileNotFoundError as e:
        print(f"DEBUG: Error - File not found: {e}")
    except json.JSONDecodeError as e:
        print(f"DEBUG: Error - Invalid JSON format: {e}")
    except Exception as e:
        print(f"DEBUG: Unexpected error: {e}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    main()
