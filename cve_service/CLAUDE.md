# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
This is a security vulnerability analysis tool that:
1. Extracts CPE (Common Platform Enumeration) identifiers from network/web scan data
2. Queries the NVD (National Vulnerability Database) API for associated CVEs
3. Generates HTML dashboard reports showing vulnerabilities by severity

## Key Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full analysis pipeline
python main.py

# Test individual components
python cpe_extractor.py    # Tests CPE extraction with sample data
python cve_fetcher.py      # Tests CVE fetching with hardcoded CPEs
```

## Architecture & Workflow

1. **Data Flow**: `cpe_response.json` → `cpe_extractor.py` → `cve_fetcher.py` → `html_report.py`

2. **Core Components**:
   - **Pattern Matching**: Uses `cpe_patterns.yaml` to define regex patterns for software identification
   - **CPE Extraction**: Scans service banners and web headers for software versions
   - **CVE Retrieval**: Queries NVD API (rate-limited to 10 requests/minute without API key)
   - **Report Generation**: Creates HTML dashboards with severity color-coding

3. **Data Format**: Expects scan data in JSON format with structure:
   ```json
   {
     "service_scan": {"services": [...]},
     "web_scan": {"technologies": [...]}
   }
   ```

## Important Considerations

- **NVD API Rate Limiting**: Without an API key, limited to 10 requests per minute. Each CPE requires a separate API call.
- **Pattern Extension**: To add new software detection, update `cpe_patterns.yaml` with vendor, product, regex pattern
- **Report Generation**: Currently commented out in `main.py` (lines 41-47). Uncomment to enable HTML report generation
- **Input Data**: The tool expects `cpe_response.json` to exist with scan results. This file contains sample data from online.uom.lk

## Development Notes

- All modules have standalone testing capabilities via `if __name__ == "__main__"` blocks
- The `reports/` directory contains unrelated service configuration files (services.json, updated_services.json)
- No formal test suite exists - testing is done through direct module execution
- The project appears to be part of a PSAD (Program Security and Analysis/Defense) course