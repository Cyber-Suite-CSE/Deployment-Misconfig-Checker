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
    with open(path, "r", encoding="utf-8") as f:
        services = json.load(f)
    return services

def load_target_data(path: str) -> Dict[str, Any]:
    """Load target data from JSON file"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

def extract_urls_from_target(target_data: Dict[str, Any]) -> Set[str]:
    """Extract all URLs from the target data"""
    urls = set()
    
    # Extract from web_technologies
    if "web_technologies" in target_data:
        for url in target_data["web_technologies"].keys():
            urls.add(url)
    
    # Extract from directories
    if "directories" in target_data:
        for directory in target_data["directories"]:
            if "url" in directory:
                urls.add(directory["url"])
    
    # Extract from api_endpoints
    if "api_endpoints" in target_data:
        for endpoint in target_data["api_endpoints"]:
            if "url" in endpoint:
                urls.add(endpoint["url"])
    
    return urls

def make_request(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Make HTTP request and return response details"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        
        return {
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text,
            "success": True
        }
    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "error": str(e),
            "success": False
        }

def check_fingerprints_in_response(services: List[Dict[str, Any]], response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for fingerprints in a single response"""
    matches = []
    
    if not response_data.get("success"):
        return matches
    
    content = response_data.get("content", "")
    headers = response_data.get("headers", {})
    
    # Create separate search texts for better debugging
    content_text = content
    headers_text = " ".join([f"{k}: {v}" for k, v in headers.items()])
    combined_text = content_text + " " + headers_text
    
    for service in services:
        fingerprints = service.get("response", {}).get("fingerprints", [])
        detection_fingerprints = service.get("response", {}).get("detectionFingerprints", [])
        exclusion_patterns = service.get("response", {}).get("exclusionPatterns", [])
        
        all_fingerprints = set(fingerprints) | set(detection_fingerprints)
        
        service_name = service.get("metadata", {}).get("serviceName", "Unknown")
        
        # First check if any exclusion patterns match
        excluded = False
        for exclusion in exclusion_patterns:
            if exclusion and exclusion in combined_text:
                excluded = True
                break
        
        if excluded:
            continue  # Skip this service entirely if exclusion pattern matches
        
        for fp in all_fingerprints:
            if fp:
                # Check where the fingerprint was found
                found_in_content = fp in content_text
                found_in_headers = fp in headers_text
                found_in_combined = fp in combined_text
                
                if found_in_combined:
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
    
    return matches

def scan_target(services: List[Dict[str, Any]], target_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan all URLs from target data for fingerprints"""
    urls = extract_urls_from_target(target_data)
    all_matches = []
    
    for i, url in enumerate(urls, 1):
        response_data = make_request(url)
        
        if response_data["success"]:
            matches = check_fingerprints_in_response(services, response_data)
            all_matches.extend(matches)
        
        # Small delay to be respectful
        time.sleep(0.5)
    
    return all_matches

def main():
    """Main function"""
    try:
        # Load services configuration
        services = load_services(SERVICES_JSON_PATH)
        
        # Get target data file path
        target_file = input("Enter path to target data JSON file: ").strip()
        if not target_file:
            print("No file provided. Exiting.")
            return
        
        # Load target data
        target_data = load_target_data(target_file)
        
        # Scan target
        matches = scan_target(services, target_data)
        
        # Display results
        if matches:
            print(f"\n=== FINGERPRINT SCAN RESULTS ===")
            print(f"Found {len(matches)} fingerprint matches:\n")
            
            for i, match in enumerate(matches, 1):
                print(f"Match {i}/{len(matches)}:")
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
            print("\nNo fingerprints found in the scanned URLs.")
            
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format - {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
