import json
import os
import requests
import urllib3
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
from dotenv import load_dotenv
import time

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVICES_DIR = "data_sources/services/"

def load_services_from_directory(services_dir: str) -> List[Dict[str, Any]]:
    """Load services configuration from multiple JSON files in a directory"""
    import os
    import glob
    
    all_services = []
    json_files = glob.glob(os.path.join(services_dir, "*.json"))
    
    print(f"DEBUG: Loading services from directory: {services_dir}")
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
    
    # Calculate statistics
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

def load_services(use_directory: bool = True) -> List[Dict[str, Any]]:
    """Load services configuration from modular service files"""
    return load_services_from_directory(SERVICES_DIR)

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

def make_request(url: str, method: str = "GET", custom_headers: List[Dict[str, str]] = None, body: str = None, timeout: int = 10) -> Dict[str, Any]:
    """Make HTTP request and return response details"""
    print(f"DEBUG: Making {method} request to {url}")
    try:
        # Start with default headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # Add custom headers from service definition
        if custom_headers:
            for header_dict in custom_headers:
                headers.update(header_dict)
        
        print(f"DEBUG: Using headers: {headers}")
        if body:
            print(f"DEBUG: Using body: {body}")
        
        # Make request based on method
        method_upper = method.upper()
        if method_upper == "GET":
            response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        elif method_upper == "POST":
            response = requests.post(url, headers=headers, data=body, timeout=timeout, verify=False, allow_redirects=True)
        elif method_upper == "PUT":
            response = requests.put(url, headers=headers, data=body, timeout=timeout, verify=False, allow_redirects=True)
        elif method_upper == "DELETE":
            response = requests.delete(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        elif method_upper == "PATCH":
            response = requests.patch(url, headers=headers, data=body, timeout=timeout, verify=False, allow_redirects=True)
        else:
            print(f"DEBUG: Unsupported HTTP method: {method}")
            return {
                "url": url,
                "error": f"Unsupported HTTP method: {method}",
                "success": False
            }
        
        print(f"DEBUG: Request successful - Status: {response.status_code}, Content length: {len(response.text)}")
        
        return {
            "url": url,
            "method": method_upper,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text,
            "success": True
        }
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Request failed for {url} - Error: {str(e)}")
        return {
            "url": url,
            "method": method.upper() if method else "GET",
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
        
        # Check all fingerprints for this service and collect matches
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
        
        # If any fingerprints matched, create a single match entry for this service
        if matched_fingerprints:
            # Extract exploitType from service metadata for precise exploit matching
            exploit_type = service.get("metadata", {}).get("exploitType", None)
            
            match_entry = {
                "url": response_data["url"],
                "service": service_name,
                "service_id": service.get("id", "Unknown"),
                "fingerprints": matched_fingerprints,  # List of all matched fingerprints
                "fingerprint": matched_fingerprints[0],  # Keep first one for backward compatibility
                "description": service.get("metadata", {}).get("description", ""),
                "references": service.get("metadata", {}).get("references", []),
                "found_in_content": found_in_content_any,
                "found_in_headers": found_in_headers_any
            }
            
            # Add exploitType if available for precise exploit matching
            if exploit_type:
                match_entry["exploit_type"] = exploit_type
                print(f"DEBUG: Added exploitType '{exploit_type}' to match for service '{service_name}'")
            else:
                print(f"DEBUG: No exploitType defined for service '{service_name}' - exploit matching will use fallback")
            
            matches.append(match_entry)
    
    print(f"DEBUG: Found {len(matches)} fingerprint matches for this response")
    return matches

def extract_target_domains(target_data: Dict[str, Any]) -> Set[str]:
    """Extract target domains from target data for service scanning"""
    domains = set()
    
    print("DEBUG: Extracting target domains for service-based scanning...")
    
    # Extract domains from web_technologies URLs
    if "web_technologies" in target_data:
        web_tech_urls = list(target_data["web_technologies"].keys())
        print(f"DEBUG: Found {len(web_tech_urls)} URLs in web_technologies")
        for url in web_tech_urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.replace('www.', '')
                if domain:
                    domains.add(domain)
                    print(f"DEBUG: Extracted domain: {domain}")
            except Exception as e:
                print(f"DEBUG: Error parsing URL {url}: {e}")
    
    # Extract from directories
    if "directories" in target_data:
        dir_count = 0
        for directory in target_data["directories"]:
            if "url" in directory:
                try:
                    parsed = urlparse(directory["url"])
                    domain = parsed.netloc.replace('www.', '')
                    if domain:
                        domains.add(domain)
                        dir_count += 1
                        print(f"DEBUG: Extracted domain from directory: {domain}")
                except Exception as e:
                    print(f"DEBUG: Error parsing directory URL {directory['url']}: {e}")
        print(f"DEBUG: Found {dir_count} domains in directories")
    
    # Extract from api_endpoints
    if "api_endpoints" in target_data:
        api_count = 0
        for endpoint in target_data["api_endpoints"]:
            if "url" in endpoint:
                try:
                    parsed = urlparse(endpoint["url"])
                    domain = parsed.netloc.replace('www.', '')
                    if domain:
                        domains.add(domain)
                        api_count += 1
                        print(f"DEBUG: Extracted domain from API endpoint: {domain}")
                except Exception as e:
                    print(f"DEBUG: Error parsing API URL {endpoint['url']}: {e}")
        print(f"DEBUG: Found {api_count} domains in api_endpoints")
    
    print(f"DEBUG: Total unique target domains extracted: {len(domains)}")
    return domains

def generate_service_requests(services: List[Dict[str, Any]], target_domains: Set[str]) -> List[Dict[str, Any]]:
    """Generate HTTP requests from service definitions and target domains"""
    requests_to_make = []
    
    print(f"DEBUG: Generating requests for {len(services)} services and {len(target_domains)} domains...")
    
    for service in services:
        request_config = service.get("request", {})
        method = request_config.get("method", "GET")
        base_url = request_config.get("baseURL", "")
        paths = request_config.get("path", ["/"])
        headers = request_config.get("headers", [])
        body = request_config.get("body", None)
        
        service_name = service.get("metadata", {}).get("serviceName", f"Service {service.get('id', 'Unknown')}")
        
        for domain in target_domains:
            # Replace {TARGET} placeholder with actual domain
            actual_base_url = base_url.replace("{TARGET}", domain)
            
            if os.getenv("ENVIRONMENT") == "development":
                print(f"DEBUG: Adjusting protocol for domain {domain}")
                actual_base_url = actual_base_url.replace("https://", "http://")

            for path in paths:
                full_url = actual_base_url + path
                
                request_info = {
                    "url": full_url,
                    "method": method,
                    "headers": headers,
                    "body": body,
                    "service": service,
                    "service_name": service_name,
                    "target_domain": domain
                }
                
                requests_to_make.append(request_info)
                print(f"DEBUG: Generated {method} request: {full_url} for service: {service_name}")
    
    print(f"DEBUG: Total requests to make: {len(requests_to_make)}")
    return requests_to_make

def scan_target(services: List[Dict[str, Any]], target_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan target domains using service definitions"""
    target_domains = extract_target_domains(target_data)
    all_matches = []
    
    if not target_domains:
        print("DEBUG: No target domains found!")
        return all_matches
    
    requests_to_make = generate_service_requests(services, target_domains)
    
    # Track detected misconfigurations per domain to avoid duplicate testing
    detected_misconfigs = {}  # {domain: {service_name: True}}
    
    print(f"DEBUG: Starting scan with {len(requests_to_make)} requests...")
    
    for i, request_info in enumerate(requests_to_make, 1):
        target_domain = request_info["target_domain"]
        service_name = request_info["service_name"]
        
        # Check if this misconfiguration has already been detected for this domain
        if target_domain in detected_misconfigs and service_name in detected_misconfigs[target_domain]:
            print(f"\nDEBUG: === Skipping Request {i}/{len(requests_to_make)} ===")
            print(f"DEBUG: {request_info['method']} {request_info['url']}")
            print(f"DEBUG: Service: {service_name}")
            print(f"DEBUG: SKIPPED - This misconfiguration already detected for domain: {target_domain}")
            continue
        
        print(f"\nDEBUG: === Making Request {i}/{len(requests_to_make)} ===")
        print(f"DEBUG: {request_info['method']} {request_info['url']}")
        print(f"DEBUG: Service: {service_name}")
        
        response_data = make_request(
            url=request_info["url"],
            method=request_info["method"],
            custom_headers=request_info["headers"],
            body=request_info["body"]
        )
        
        if response_data["success"]:
            print(f"DEBUG: Request successful, checking for fingerprints...")
            # Check if this specific service matches
            service_matches = check_fingerprints_in_response([request_info["service"]], response_data)
            if service_matches:
                # Mark this misconfiguration as detected for this domain
                if target_domain not in detected_misconfigs:
                    detected_misconfigs[target_domain] = {}
                detected_misconfigs[target_domain][service_name] = True
                
                print(f"DEBUG: MISCONFIGURATION DETECTED! Marking '{service_name}' as detected for domain '{target_domain}'")
                print(f"DEBUG: Future requests for this misconfiguration on this domain will be skipped")
                
                # Add additional context to matches
                for match in service_matches:
                    match["target_domain"] = request_info["target_domain"]
                    match["method"] = request_info["method"]
                all_matches.extend(service_matches)
            print(f"DEBUG: Scan complete - Status: {response_data['status_code']} - Found {len(service_matches)} matches")
        else:
            print(f"DEBUG: Request failed - Error: {response_data['error']}")
        
        time.sleep(0.5)
    
    print(f"\nDEBUG: === SCAN COMPLETE ===")
    print(f"DEBUG: Total fingerprint matches found: {len(all_matches)}")
    return all_matches

def main():
    """Main function"""
    print("DEBUG: Starting fingerprint scanner...")
    try:
        print("DEBUG: Step 1 - Loading services configuration...")
        services = load_services(use_directory=True)
        print(f"DEBUG: Loaded {len(services)} service fingerprints")
        
        print("DEBUG: Step 2 - Getting target data file...")
        target_file = input("Enter path to target data JSON file: ").strip()
        if not target_file:
            print("DEBUG: No file provided. Exiting.")
            return
        
        print("DEBUG: Step 3 - Loading target data...")
        target_data = load_target_data(target_file)
        
        print("DEBUG: Step 4 - Starting target scan...")
        matches = scan_target(services, target_data)
        
        print("DEBUG: Step 5 - Displaying results...")
        if matches:
            print(f"\nDEBUG: === FINGERPRINT SCAN RESULTS ===")
            print(f"DEBUG: Found {len(matches)} total fingerprint matches:\n")
            
            for i, match in enumerate(matches, 1):
                print(f"DEBUG: Match {i}/{len(matches)}:")
                print(f"URL: {match['url']}")
                print(f"Method: {match.get('method', 'GET')}")
                print(f"Target Domain: {match.get('target_domain', 'N/A')}")
                print(f"Service: {match['service']} (ID: {match['service_id']})")
                
                # Show all matched fingerprints
                fingerprints = match.get('fingerprints', [match.get('fingerprint')])
                if len(fingerprints) == 1:
                    print(f"Fingerprint: {fingerprints[0]}")
                else:
                    print(f"Fingerprints: {', '.join(fingerprints)}")
                
                print(f"Description: {match['description']}")
                
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
            
            # Ask user if they want to run exploits
            print(f"\nDEBUG: === EXPLOIT FRAMEWORK ===")
            run_exploits = input("Do you want to run exploit tests on detected vulnerabilities? (y/N): ").strip().lower()
            
            if run_exploits in ['y', 'yes']:
                print("DEBUG: Step 6 - Running exploit framework...")
                try:
                    from exploits import ExploitManager, ExploitSeverity
                    
                    exploit_manager = ExploitManager()
                    
                    # Ask for maximum severity level
                    print("\nAvailable severity levels:")
                    print("1. INFO - Information gathering only")
                    print("2. LOW - Safe reconnaissance") 
                    print("3. MEDIUM - Limited security testing")
                    print("4. HIGH - Comprehensive security testing")
                    print("5. CRITICAL - Advanced penetration testing")
                    
                    severity_choice = input("Choose maximum severity level (1-3 recommended): ").strip()
                    severity_map = {
                        '1': ExploitSeverity.INFO,
                        '2': ExploitSeverity.LOW,
                        '3': ExploitSeverity.MEDIUM,
                        '4': ExploitSeverity.HIGH,
                        '5': ExploitSeverity.CRITICAL
                    }
                    
                    max_severity = severity_map.get(severity_choice, ExploitSeverity.MEDIUM)
                    print(f"Selected maximum severity: {max_severity.value.upper()}")
                    
                    # Execute exploits
                    exploit_results = exploit_manager.execute_exploits(matches, max_severity)
                    
                    # Display exploit results
                    if exploit_results:
                        print(f"\nDEBUG: === EXPLOIT RESULTS ===")
                        print(f"DEBUG: Executed {len(exploit_results)} exploits:\n")
                        
                        for i, result in enumerate(exploit_results, 1):
                            status = "✅ SUCCESS" if result.success else "❌ FAILED"
                            print(f"Exploit {i}/{len(exploit_results)} - {status}")
                            print(f"Name: {result.exploit_name}")
                            print(f"Severity: {result.severity.value.upper()}")
                            print(f"Title: {result.title}")
                            print(f"Description: {result.description}")
                            
                            if result.evidence:
                                print(f"Evidence items: {len(result.evidence)}")
                                # Show key evidence
                                for key, value in list(result.evidence.items())[:3]:
                                    print(f"  - {key}: {str(value)[:100]}{'...' if len(str(value)) > 100 else ''}")
                            
                            if result.recommendations:
                                print(f"Recommendations: {len(result.recommendations)} items")
                                for rec in result.recommendations[:2]:
                                    print(f"  - {rec}")
                            
                            print("-" * 50)
                        
                        # Generate report
                        import os
                        report_dir = "reports"
                        os.makedirs(report_dir, exist_ok=True)
                        
                        from datetime import datetime
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        report_file = os.path.join(report_dir, f"exploit_report_{timestamp}.json")
                        
                        report = exploit_manager.generate_report(report_file)
                        print(f"\nDEBUG: Exploit report generated: {report_file}")
                        print(f"DEBUG: Total exploits executed: {report['total_exploits_executed']}")
                        print(f"DEBUG: Successful exploits: {report['successful_exploits']}")
                    else:
                        print("DEBUG: No applicable exploits found for detected vulnerabilities.")
                        
                except ImportError as e:
                    print(f"DEBUG: Exploit framework not available: {e}")
                except Exception as e:
                    print(f"DEBUG: Error running exploits: {e}")
            else:
                print("DEBUG: Skipping exploit framework.")
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
