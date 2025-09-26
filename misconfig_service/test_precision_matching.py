#!/usr/bin/env python3
"""
Test script to verify precise exploit-to-vulnerability matching
This test ensures only specific exploits run for their corresponding vulnerability types
"""

import sys
import os
import json

# Add the misconfig_service directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from exploits import ExploitManager, ExploitSeverity

def test_precision_matching():
    """Test that exploits are precisely matched to vulnerability types"""
    print("=== Testing Precision Exploit Matching ===\n")
    
    # Create test vulnerability matches with different exploitTypes
    test_matches = [
        {
            "url": "http://test-wordpress.com/xmlrpc.php",
            "service": "WordPress XML-RPC Enabled",
            "service_id": "308",
            "exploit_type": "xmlrpc",  # Should only trigger XML-RPC exploit
            "fingerprints": ["XML-RPC server accepts POST requests"],
            "description": "WordPress XML-RPC interface is enabled"
        },
        {
            "url": "http://test-wordpress.com/wp-config.php",
            "service": "WordPress Configuration File Exposed", 
            "service_id": "301",
            "exploit_type": "config_exposure",  # Should only trigger config exploit
            "fingerprints": ["DB_PASSWORD"],
            "description": "WordPress configuration file is publicly accessible"
        },
        {
            "url": "http://test-wordpress.com/wp-json/wp/v2/users",
            "service": "WordPress REST API User Enumeration",
            "service_id": "306", 
            "exploit_type": "user_enumeration",  # Should only trigger user enum exploit
            "fingerprints": ["/wp-json/wp/v2/users"],
            "description": "WordPress REST API allows user enumeration"
        }
    ]
    
    # Initialize exploit manager
    exploit_manager = ExploitManager()
    
    print(f"Loaded {len(exploit_manager.exploits)} total exploits:")
    for exploit_key in exploit_manager.exploits.keys():
        exploit_class = exploit_manager.exploits[exploit_key]
        target_type = getattr(exploit_class, 'target_exploit_type', 'NOT_DEFINED')
        print(f"  - {exploit_key} -> targets: {target_type}")
    print()
    
    # Test each vulnerability type individually
    for i, test_match in enumerate(test_matches, 1):
        print(f"--- Test Case {i}: {test_match['exploit_type'].upper()} ---")
        print(f"Vulnerability: {test_match['service']}")
        print(f"ExploitType: {test_match['exploit_type']}")
        print(f"URL: {test_match['url']}")
        
        # Get applicable exploits for this single vulnerability
        applicable_exploits = exploit_manager.get_applicable_exploits([test_match])
        
        print(f"Applicable exploits found: {len(applicable_exploits)}")
        
        if applicable_exploits:
            for exploit_class, match_data in applicable_exploits:
                exploit_name = getattr(exploit_class, 'name', 'unknown')
                target_type = getattr(exploit_class, 'target_exploit_type', 'undefined')
                print(f"  ✅ {exploit_name} (targets: {target_type})")
        else:
            print("  ❌ No applicable exploits found")
        
        print()
    
    # Test precision: ensure XML-RPC vulnerability only triggers XML-RPC exploit
    print("--- Precision Test: XML-RPC vulnerability should only trigger XML-RPC exploit ---")
    xmlrpc_match = [m for m in test_matches if m['exploit_type'] == 'xmlrpc'][0]
    xmlrpc_exploits = exploit_manager.get_applicable_exploits([xmlrpc_match])
    
    print(f"XML-RPC vulnerability triggered {len(xmlrpc_exploits)} exploits:")
    success = True
    
    for exploit_class, _ in xmlrpc_exploits:
        target_type = getattr(exploit_class, 'target_exploit_type', 'undefined')
        exploit_name = getattr(exploit_class, 'name', 'unknown')
        
        if target_type == 'xmlrpc':
            print(f"  ✅ CORRECT: {exploit_name} (targets: {target_type})")
        else:
            print(f"  ❌ INCORRECT: {exploit_name} (targets: {target_type}) - should not run for XML-RPC!")
            success = False
    
    print(f"\n--- Final Result ---")
    if success and len(xmlrpc_exploits) > 0:
        print("✅ SUCCESS: Precision matching is working correctly!")
        print("   XML-RPC vulnerability only triggers XML-RPC exploits")
    elif len(xmlrpc_exploits) == 0:
        print("⚠️  WARNING: No XML-RPC exploits found - check exploit loading")
    else:
        print("❌ FAILED: XML-RPC vulnerability is triggering incorrect exploits!")
    
    return success

if __name__ == "__main__":
    test_precision_matching()