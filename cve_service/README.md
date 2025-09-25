# Security Vulnerability Analysis Tool

A comprehensive tool for identifying and analyzing security vulnerabilities in web applications and services. It extracts CPE (Common Platform Enumeration) identifiers from network scan data, queries the NVD (National Vulnerability Database) for associated CVEs, validates their applicability to the target domain, and generates actionable mitigation steps using Google's Gemini AI.

## Features

- **CPE Extraction**: Automatically identifies software versions from service banners and web headers
- **CVE Fetching**: Queries NVD API for vulnerabilities associated with detected software
- **Smart Validation**: Validates if CVEs actually apply to the scanned domain (not just version matching)
- **AI-Powered Mitigation**: Generates practical mitigation steps using Gemini AI for applicable vulnerabilities
- **Beautiful Reports**: Creates HTML dashboard reports with severity color-coding and mitigation guidance

## Prerequisites

- Python 3.8 or higher
- Google Gemini API key (for mitigation generation)
- Optional: NVD API key (for faster CVE queries)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd security-vulnerability-analyzer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The tool requires a `config.yaml` file in the same directory as `main.py`. This file contains all configuration settings:

```yaml
# API Keys
gemini_api_key: "your-gemini-api-key"  # Required for mitigation generation
nvd_api_key: "your-nvd-api-key"        # Optional, but recommended for faster queries

# Mitigation Generation Settings
mitigation:
  model: "gemini-2.5-flash"
  max_tokens: 500
  temperature: 0.3

# Validation Settings
validation:
  check_services: true
  check_versions: true
  strict_mode: false

# Report Settings
report:
  include_non_applicable: true
  include_mitigation: true

# CVE Fetching Settings
nvd:
  rate_limit_delay: 6
  max_cves_per_cpe: 5
```

You can also set the Gemini API key via environment variable:
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```

## Usage

Simply run the main script:
```bash
python main.py
```

The tool will:
1. Load configuration from `config.yaml`
2. Read scan data from `cpe_response.json`
3. Extract CPE identifiers
4. Fetch CVEs from NVD
5. Validate CVEs based on configuration settings
6. Generate mitigation steps (if enabled and API key is provided)
7. Create an HTML report in the `reports/` directory

### Configuration Options

All behavior is controlled via `config.yaml`:
- **Skip validation**: Set `validation.check_services` and `validation.check_versions` to `false`
- **Skip mitigation**: Set `report.include_mitigation` to `false` or don't provide a Gemini API key
- **Adjust CVE limits**: Change `nvd.max_cves_per_cpe` to fetch more/fewer CVEs per software

### Input Data Format

The tool expects a `cpe_response.json` file containing scan results in this format:
```json
{
    "services": {
        "open_ports": {
            "22": {
                "service": "SSH",
                "banner": "SSH-2.0-OpenSSH_8.7"
            }
        }
    },
    "web_technologies": {
        "http://example.com": {
            "server": "Apache/2.4.62",
            "x_powered_by": "PHP/8.3.21"
        }
    }
}
```

## How It Works

1. **Pattern Matching**: Uses regex patterns defined in `cpe_patterns.yaml` to identify software and versions
2. **CVE Lookup**: Queries NVD API for vulnerabilities (rate-limited to 10 req/min without API key)
3. **Validation**: Custom validators check if CVEs apply to the scanned domain by verifying:
   - Open ports match the vulnerable service
   - Service banners confirm the software
   - Web technologies align with the vulnerability
4. **Mitigation Generation**: For applicable CVEs, Gemini AI generates 3-5 actionable mitigation steps
5. **Report Generation**: Creates timestamped HTML reports in the `reports/` directory

## Adding New CVE Validators

Create a new file in `cve_validators/` directory:
```python
# cve_validators/cve_2024_xxxxx.py
from typing import Dict, Optional, Tuple
from .base_validator import CVEValidator

class CVE_2024_XXXXX_Validator(CVEValidator):
    def validate(self) -> Tuple[bool, str]:
        # Check if CVE applies to the scanned domain
        if not self.is_port_open(443):
            return False, "HTTPS port not open"
        return True, "Vulnerable version detected"
    
    def get_affected_versions(self) -> Dict[str, Optional[str]]:
        return {"min": "1.0", "max": "2.5"}
```

## Output

The tool generates:
- Console output with real-time analysis progress
- HTML dashboard report with:
  - Summary statistics
  - Color-coded severity levels
  - Applicability status for each CVE
  - Actionable mitigation steps
  - Validation reasoning

## Architecture

```
├── main.py                 # Main entry point
├── cpe_extractor.py        # Extracts CPEs from scan data
├── cve_fetcher.py          # Queries NVD API for CVEs
├── cve_validator_registry.py # Manages CVE validators
├── mitigation_generator.py  # Generates mitigation via Gemini
├── html_report.py          # Creates HTML reports
├── cpe_patterns.yaml       # Software detection patterns
├── cve_validators/         # CVE-specific validators
│   ├── base_validator.py   # Base validator class
│   └── cve_*.py           # Individual CVE validators
└── reports/               # Generated HTML reports
```

## License

This project is part of the PSAD (Program Security and Defense) course.

## Contributing

1. Add new patterns to `cpe_patterns.yaml` for software detection
2. Create CVE validators for critical vulnerabilities
3. Improve validation logic for better accuracy
4. Submit pull requests with clear descriptions

## Troubleshooting

- **No CVEs found**: Check if `cpe_response.json` contains valid scan data
- **Rate limiting**: Use an NVD API key or add delays between requests
- **Validation errors**: Ensure scan data includes service banners and web headers
- **No mitigations**: Verify Gemini API key is set correctly