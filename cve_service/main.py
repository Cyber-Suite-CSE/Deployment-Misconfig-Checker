import json
from cpe_extractor import load_patterns, extract_cpes
from cve_fetcher import get_cves_for_cpes
from html_report import generate_html_report
from cve_validator_registry import get_cve_validator
from mitigation_generator import MitigationGenerator
import os
import datetime
import yaml


def load_config(config_path="config.yaml"):
    """Load configuration from YAML file."""
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {}


def main():
    # Load configuration
    config = load_config()
    
    # Get API keys from config or environment
    gemini_api_key = config.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")
    nvd_api_key = config.get("nvd_api_key")
    
    # Load scan data
    with open("cpe_response.json", "r") as f:
        scan_data = json.load(f)

    # Load CPE patterns
    patterns = load_patterns("cpe_patterns.yaml")

    # Extract CPEs
    cpe_list = extract_cpes(scan_data, patterns)
    if not cpe_list:
        print("No CPEs found in scan data.")
        return

    print("Identified CPEs:")
    for cpe in cpe_list:
        print("  ", cpe)

    # Fetch CVEs for CPEs
    print("\nFetching CVEs from NVD...")
    max_cves = config.get('nvd', {}).get('max_cves_per_cpe', 5)
    cve_results = get_cves_for_cpes(cpe_list, api_key=nvd_api_key, limit=max_cves)
    
    # Initialize mitigation generator
    mitigation_generator = None
    include_mitigation = config.get('report', {}).get('include_mitigation', True)
    if include_mitigation and gemini_api_key:
        print("\nInitializing mitigation generator...")
        mitigation_generator = MitigationGenerator(api_key=gemini_api_key)
    
    # Process results with validation and mitigation
    validated_results = {}
    for cpe, vulns in cve_results.items():
        validated_vulns = []
        print(f"\nCPE: {cpe}")
        
        for v in vulns:
            if "error" in v:
                print(f"  Error: {v['error']}")
                validated_vulns.append(v)
                continue
            
            # Validate CVE if enabled
            is_applicable = True
            validation_reason = "Validation skipped"
            
            check_services = config.get('validation', {}).get('check_services', True)
            check_versions = config.get('validation', {}).get('check_versions', True)
            
            if check_services or check_versions:
                validator = get_cve_validator(v['cve_id'], cpe, v, scan_data)
                if validator:
                    is_applicable, validation_reason = validator.validate()
                    v['validation_performed'] = True
                else:
                    validation_reason = "No validator available"
                    v['validation_performed'] = False
            
            v['applies_to_system'] = is_applicable
            v['validation_reason'] = validation_reason
            
            # Generate mitigation if CVE applies and mitigation is enabled
            if is_applicable and mitigation_generator:
                print(f"  {v['cve_id']} | {v['severity']} | APPLICABLE - {validation_reason}")
                print("    Generating mitigation steps...")
                
                mitigation_result = mitigation_generator.generate_mitigation_steps(
                    cve_id=v['cve_id'],
                    cve_description=v['description'],
                    affected_software=f"{cpe.split(':')[4]} {cpe.split(':')[5]}",
                    severity=v['severity']
                )
                
                if 'error' not in mitigation_result:
                    v['mitigation_steps'] = mitigation_result['steps']
                    print("    Mitigation steps generated:")
                    for i, step in enumerate(mitigation_result['steps'], 1):
                        print(f"      {i}. {step}")
                else:
                    print(f"    Failed to generate mitigation: {mitigation_result['error']}")
            else:
                status = "NOT APPLICABLE" if not is_applicable else "APPLICABLE"
                print(f"  {v['cve_id']} | {v['severity']} | {status} - {validation_reason}")
            
            validated_vulns.append(v)
        
        validated_results[cpe] = validated_vulns

    # Generate HTML dashboard report
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = os.path.join(reports_dir, f"{now_str}_report.html")
    print(f"\nGenerating dashboard report: {report_path}")
    generate_html_report(validated_results, output_path=report_path)
    print(f"Report generated successfully: {report_path}")
    
    # Summary
    print("\n=== SUMMARY ===")
    total_cves = sum(len(vulns) for vulns in validated_results.values())
    applicable_cves = sum(
        1 for vulns in validated_results.values() 
        for v in vulns 
        if v.get('applies_to_system', True) and 'error' not in v
    )
    print(f"Total CVEs found: {total_cves}")
    print(f"Applicable CVEs: {applicable_cves}")
    if mitigation_generator:
        mitigated_cves = sum(
            1 for vulns in validated_results.values() 
            for v in vulns 
            if 'mitigation_steps' in v
        )
        print(f"Mitigations generated: {mitigated_cves}")


if __name__ == "__main__":
    main()