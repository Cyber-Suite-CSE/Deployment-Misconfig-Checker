# Deployment-Misconfig-Checker

An AI-driven security analysis platform that automatically detects deployment misconfigurations and CVEs in software projects. Evolved from manual exploit scripting to an intelligent multi-agent system that orchestrates industry-standard security tools through natural language queries.

## Problem Statement

AI-generated code is often deployed with critical misconfigurations. Manual security audits are time-consuming and require writing custom exploit scripts for each vulnerability. This tool automates the entire discovery-to-exploitation workflow using pre-existing exploit databases.

## Architecture: Multi-Agent System

### Orchestrator Agent
Central controller that processes natural language queries (e.g., "check localhost") and manages specialized sub-agents, aggregating results into human-readable security reports.

### Specialized Sub-Agents
Each agent has dedicated tool context and expertise:

- **Nmap Agent**: Network scanning and service discovery
- **Nikto Agent**: Web server vulnerability detection and misconfiguration scanning
- **Metasploit Agent**: Exploit search and verification (passive/active modes)
- **WPScan Agent**: WordPress-specific security analysis

## Operational Workflow

```
User Query → Service Discovery → Vulnerability Scanning → Exploit Search → Report Generation
   (CLI)         (Nmap)              (Nikto)            (Metasploit)     (Orchestrator)
```

1. **Natural Language Input**: User provides query via CLI
2. **Service Discovery**: Nmap identifies running services and open ports
3. **Vulnerability Detection**: Nikto/WPScan scan for specific misconfigurations
4. **Exploit Research**: Metasploit searches database for applicable exploits
5. **Reporting**: Orchestrator generates comprehensive vulnerability report with mitigation strategies

## Deprecated Services

- **CVE Service**: Validates CVEs via NVD API, extracts CPE identifiers, generates AI-powered mitigation strategies
- **Misconfig Service**: Fingerprints configurations and matches against known vulnerability patterns

## Key Features

- Natural language security queries powered by LangChain + Google Gemini
- Automated context switching between discovery, scanning, and exploitation
- Leverages pre-written exploits from Metasploit database (no manual scripting)
- Passive and active exploitation modes
- Human-readable security reports with actionable insights

## Quick Setup

```bash
# Configure environment
cp .env.example .env  # Set GOOGLE_API_KEY, MSF_PASSWORD

# Install dependencies per service
cd agent && pip install -r requirements.txt

# Run the agent system
cd agent && python main.py
```

## Prerequisites

- Python 3.8+
- Security tools: Nmap, Nikto, WPScan, Metasploit Framework
- Google Gemini API key

## Project Evolution

**Initial Approach**: Manual script generation for each CVE exploit  
**Current Approach**: Intelligent agent orchestration utilizing existing exploit databases and automated workflow chaining
