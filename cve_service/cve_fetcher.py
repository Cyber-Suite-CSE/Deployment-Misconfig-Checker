import requests


def get_cves_for_cpes(cpe_list, api_key=None, limit=5):
    """
    Fetch CVEs from NVD for a list of CPEs.
    Args:
        cpe_list (list): list of CPE strings
        api_key (str): optional NVD API key (recommended to avoid rate-limits)
        limit (int): max CVEs per CPE to return
    Returns:
        dict: {cpe: [ {cve_id, description, severity}, ... ]}
    """
    results = {}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for cpe in cpe_list:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
        try:
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code != 200:
                results[cpe] = [{"error": f"HTTP {r.status_code}"}]
                continue
            data = r.json()
            vulns = []
            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve_id = vuln["cve"]["id"]
                desc = vuln["cve"]["descriptions"][0]["value"]
                metrics = vuln["cve"].get("metrics", {})
                severity = None
                if "cvssMetricV31" in metrics:
                    severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV30" in metrics:
                    severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV2" in metrics:
                    severity = metrics["cvssMetricV2"][0]["baseSeverity"]

                vulns.append(
                    {"cve_id": cve_id, "description": desc, "severity": severity}
                )
            results[cpe] = vulns
        except Exception as e:
            results[cpe] = [{"error": str(e)}]

    return results


if __name__ == "__main__":
    cpes = [
        "cpe:2.3:a:openbsd:openssh:8.7",
        "cpe:2.3:a:apache:http_server:2.4.62",
        "cpe:2.3:a:openssl:openssl:3.2.2",
        "cpe:2.3:a:php:php:8.3.21",
    ]

    cve_results = get_cves_for_cpes(cpes, api_key=None, limit=3)

    for cpe, vulns in cve_results.items():
        print(f"\nCPE: {cpe}")
        for v in vulns:
            if "error" in v:
                print("  Error:", v["error"])
            else:
                print(f"  {v['cve_id']} | {v['severity']} | {v['description']}")
