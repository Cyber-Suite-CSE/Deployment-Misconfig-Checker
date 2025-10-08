import os
import time
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from .http_client import HTTPClient
from .fingerprint_matcher import FingerprintMatcher


class MisconfigScanner:
    
    def __init__(self, http_client: HTTPClient = None, fingerprint_matcher: FingerprintMatcher = None):
        self.http_client = http_client or HTTPClient()
        self.fingerprint_matcher = fingerprint_matcher or FingerprintMatcher()
    
    def extract_target_domains(self, target_data: Dict[str, Any]) -> Set[str]:
        domains = set()
        
        print("DEBUG: Extracting target domains for service-based scanning...")
        
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
    
    def generate_service_requests(
        self, 
        services: List[Dict[str, Any]], 
        target_domains: Set[str]
    ) -> List[Dict[str, Any]]:
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
    
    def scan_target(self, services: List[Dict[str, Any]], target_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_domains = self.extract_target_domains(target_data)
        all_matches = []
        
        if not target_domains:
            print("DEBUG: No target domains found!")
            return all_matches
        
        requests_to_make = self.generate_service_requests(services, target_domains)
        
        detected_misconfigs = {}
        
        print(f"DEBUG: Starting scan with {len(requests_to_make)} requests...")
        
        for i, request_info in enumerate(requests_to_make, 1):
            target_domain = request_info["target_domain"]
            service_name = request_info["service_name"]
            
            if target_domain in detected_misconfigs and service_name in detected_misconfigs[target_domain]:
                print(f"\nDEBUG: === Skipping Request {i}/{len(requests_to_make)} ===")
                print(f"DEBUG: {request_info['method']} {request_info['url']}")
                print(f"DEBUG: Service: {service_name}")
                print(f"DEBUG: SKIPPED - This misconfiguration already detected for domain: {target_domain}")
                continue
            
            print(f"\nDEBUG: === Making Request {i}/{len(requests_to_make)} ===")
            print(f"DEBUG: {request_info['method']} {request_info['url']}")
            print(f"DEBUG: Service: {service_name}")
            
            response_data = self.http_client.make_request(
                url=request_info["url"],
                method=request_info["method"],
                custom_headers=request_info["headers"],
                body=request_info["body"]
            )
            
            if response_data["success"]:
                print(f"DEBUG: Request successful, checking for fingerprints...")
                service_matches = self.fingerprint_matcher.check_fingerprints_in_response(
                    [request_info["service"]], 
                    response_data
                )
                if service_matches:
                    if target_domain not in detected_misconfigs:
                        detected_misconfigs[target_domain] = {}
                    detected_misconfigs[target_domain][service_name] = True
                    
                    print(f"DEBUG: MISCONFIGURATION DETECTED! Marking '{service_name}' as detected for domain '{target_domain}'")
                    print(f"DEBUG: Future requests for this misconfiguration on this domain will be skipped")
                    
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
