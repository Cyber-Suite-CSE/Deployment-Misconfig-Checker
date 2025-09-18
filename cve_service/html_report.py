import datetime
import html


def generate_html_report(cpe_cve_data, output_path="report.html"):
    """
    Generate a dashboard-style HTML report for CPE and CVE data.
    Args:
        cpe_cve_data (dict): {cpe: [ {cve_id, description, severity, applies_to_system, validation_reason, mitigation_steps}, ... ]}
        output_path (str): Path to write the HTML file.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_cpes = len(cpe_cve_data)
    total_cves = sum(
        len([v for v in vulns if "cve_id" in v]) for vulns in cpe_cve_data.values()
    )
    applicable_cves = sum(
        len([v for v in vulns if "cve_id" in v and v.get("applies_to_system", True)]) 
        for vulns in cpe_cve_data.values()
    )

    def severity_color(severity):
        if severity is None:
            return "#bbb"
        sev = severity.lower()
        if sev == "critical":
            return "#d32f2f"
        if sev == "high":
            return "#f57c00"
        if sev == "medium":
            return "#fbc02d"
        if sev == "low":
            return "#388e3c"
        return "#bbb"

    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "<title>CPE & CVE Dashboard Report</title>",
        "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap' rel='stylesheet'>",
        "<style>",
        "body { font-family: 'Inter', system-ui, sans-serif; background: #f8fafc; margin: 0; padding: 0; color: #18181b; }",
        ".container { max-width: 1200px; margin: 40px auto; background: #fff; border-radius: 16px; box-shadow: 0 4px 24px #0002; padding: 40px 32px 32px 32px; }",
        "h1 { color: #18181b; font-size: 2.5em; font-weight: 700; margin-bottom: 0.2em; letter-spacing: -1px; }",
        ".summary { display: flex; gap: 32px; margin-bottom: 40px; }",
        ".card { background: #f1f5f9; border-radius: 12px; padding: 28px 36px; min-width: 180px; text-align: center; box-shadow: 0 2px 8px #0001; border: 1px solid #e5e7eb; }",
        ".card h2 { margin: 0 0 8px 0; font-size: 2.5em; color: #2563eb; font-weight: 700; }",
        ".card p { margin: 0; color: #64748b; font-size: 1.1em; }",
        ".cpe-section { margin-bottom: 36px; border-radius: 14px; background: #f9fafb; box-shadow: 0 1px 4px #0001; border: 1px solid #e5e7eb; padding: 24px 24px 12px 24px; }",
        ".cpe-title { font-size: 1.15em; color: #2563eb; margin-bottom: 14px; font-weight: 600; letter-spacing: -0.5px; }",
        "table { width: 100%; border-collapse: separate; border-spacing: 0; margin-bottom: 18px; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 4px #0001; }",
        "th, td { padding: 12px 14px; border-bottom: 1px solid #e5e7eb; font-size: 1em; vertical-align: top; }",
        "th { background: #f1f5f9; color: #18181b; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }",
        "tr:last-child td { border-bottom: none; }",
        ".severity { font-weight: 600; padding: 4px 14px; border-radius: 999px; color: #fff; font-size: 0.98em; display: inline-block; letter-spacing: 0.5px; box-shadow: 0 1px 2px #0001; }",
        ".severity-critical { background: linear-gradient(90deg, #ef4444, #b91c1c); }",
        ".severity-high { background: linear-gradient(90deg, #f59e42, #ea580c); }",
        ".severity-medium { background: linear-gradient(90deg, #fbbf24, #f59e42); color: #18181b; }",
        ".severity-low { background: linear-gradient(90deg, #22d3ee, #2563eb); }",
        ".severity-na { background: #a1a1aa; }",
        ".error { color: #ef4444; font-style: italic; font-size: 1.05em; }",
        ".no-cves { color: #64748b; font-style: italic; font-size: 1.05em; }",
        ".applicable { color: #16a34a; font-weight: 600; }",
        ".not-applicable { color: #dc2626; font-weight: 600; }",
        ".validation-reason { color: #64748b; font-size: 0.95em; font-style: italic; }",
        ".mitigation-steps { margin-top: 10px; padding: 12px; background: #f0f9ff; border-radius: 8px; border: 1px solid #bae6fd; }",
        ".mitigation-steps h4 { margin: 0 0 8px 0; color: #0284c7; font-size: 1em; font-weight: 600; }",
        ".mitigation-steps ol { margin: 0; padding-left: 20px; }",
        ".mitigation-steps li { margin: 4px 0; color: #334155; line-height: 1.4; }",
        "@media (max-width: 700px) { .container { padding: 12px; } .summary { flex-direction: column; gap: 16px; } .card { padding: 18px 10px; } }",
        "</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
        "<h1>CPE & CVE Dashboard Report</h1>",
        f"<div style='color:#64748b; margin-bottom:18px; font-size:1.1em;'>Generated: {now}</div>",
        "<div class='summary'>",
        f"<div class='card'><h2>{total_cpes}</h2><p>CPEs Identified</p></div>",
        f"<div class='card'><h2>{total_cves}</h2><p>Total CVEs</p></div>",
        f"<div class='card'><h2>{applicable_cves}</h2><p>Applicable CVEs</p></div>",
        "</div>",
        "<h2 style='font-size:1.5em; margin-bottom:18px; font-weight:600;'>CPEs & Vulnerabilities</h2>",
    ]

    if not cpe_cve_data:
        html_parts.append(
            "<div class='no-cves'>No CPEs or CVEs found in the scan data.</div>"
        )
    else:
        for cpe, vulns in cpe_cve_data.items():
            html_parts.append("<div class='cpe-section'>")
            html_parts.append(
                f"<div class='cpe-title'><b>CPE:</b> {html.escape(cpe)}</div>"
            )
            if not vulns:
                html_parts.append(
                    "<div class='no-cves'>No CVEs found for this CPE.</div>"
                )
            else:
                html_parts.append("<table>")
                html_parts.append(
                    "<tr><th>CVE ID</th><th>Severity</th><th>Status</th><th>Description & Mitigation</th></tr>"
                )
                for v in vulns:
                    if "error" in v:
                        html_parts.append(
                            f"<tr><td colspan='4' class='error'>Error: {html.escape(str(v['error']))}</td></tr>"
                        )
                    else:
                        cve_id = html.escape(v.get("cve_id", ""))
                        severity = v.get("severity")
                        sev_disp = html.escape(severity) if severity else "N/A"
                        desc = html.escape(v.get("description", ""))
                        
                        # Modern badge style for severity
                        sev_class = "severity-"
                        if severity:
                            sev_class += severity.lower()
                        else:
                            sev_class += "na"
                        
                        # Applicability status
                        is_applicable = v.get("applies_to_system", True)
                        validation_reason = v.get("validation_reason", "")
                        status_class = "applicable" if is_applicable else "not-applicable"
                        status_text = "APPLICABLE" if is_applicable else "NOT APPLICABLE"
                        
                        # Build the row
                        html_parts.append(f"<tr>")
                        html_parts.append(f"<td>{cve_id}</td>")
                        html_parts.append(f"<td><span class='severity {sev_class}'>{sev_disp}</span></td>")
                        html_parts.append(f"<td><span class='{status_class}'>{status_text}</span>")
                        if validation_reason:
                            html_parts.append(f"<br><span class='validation-reason'>{html.escape(validation_reason)}</span>")
                        html_parts.append(f"</td>")
                        html_parts.append(f"<td>{desc}")
                        
                        # Add mitigation steps if available
                        if "mitigation_steps" in v and v["mitigation_steps"]:
                            html_parts.append("<div class='mitigation-steps'>")
                            html_parts.append("<h4>Mitigation Steps:</h4>")
                            html_parts.append("<ol>")
                            for step in v["mitigation_steps"]:
                                html_parts.append(f"<li>{html.escape(step)}</li>")
                            html_parts.append("</ol>")
                            html_parts.append("</div>")
                        
                        html_parts.append("</td></tr>")
                html_parts.append("</table>")
            html_parts.append("</div>")

    html_parts.append("</div></body></html>")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))