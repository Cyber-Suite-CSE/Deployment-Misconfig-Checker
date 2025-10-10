from typing import List, Dict, Any


def display_fingerprint_results(matches: List[Dict[str, Any]]):
    if matches:
        print(f"\nDEBUG: === FINGERPRINT SCAN RESULTS ===")
        print(f"DEBUG: Found {len(matches)} total fingerprint matches:\n")
        
        for i, match in enumerate(matches, 1):
            print(f"DEBUG: Match {i}/{len(matches)}:")
            print(f"URL: {match['url']}")
            print(f"Method: {match.get('method', 'GET')}")
            print(f"Target Domain: {match.get('target_domain', 'N/A')}")
            print(f"Service: {match['service']} (ID: {match['service_id']})")
            
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
    else:
        print("\nDEBUG: No fingerprints found in the scanned URLs.")


def display_exploit_results(exploit_results: List[Any]):
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
                for key, value in list(result.evidence.items())[:3]:
                    print(f"  - {key}: {str(value)[:100]}{'...' if len(str(value)) > 100 else ''}")
            
            if result.recommendations:
                print(f"Recommendations: {len(result.recommendations)} items")
                for rec in result.recommendations[:2]:
                    print(f"  - {rec}")
            
            print("-" * 50)
    else:
        print("DEBUG: No applicable exploits found for detected vulnerabilities.")
