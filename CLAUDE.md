# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Multi-agent cybersecurity system using LangChain and Google Gemini for executing real network security commands. The system uses a hierarchical architecture where an orchestrator agent routes requests to specialized tool agents for network scanning, WordPress security testing, web vulnerability assessment, and penetration testing/exploitation.

## Architecture

```
User Request → OrchestratorAgent → [NmapAgent | WPScanAgent | NiktoAgent | MetasploitAgent] → Tool Execution → Real Command Output
```

**Key Components:**
- `main.py`: CLI interface with colorized output and interactive loop
- `agents/orchestrator_agent.py`: Routes requests to appropriate tool agents based on capability analysis
- `agents/nmap_agent.py`: Specialized agent with intelligent scan splitting, timeout recovery, and result aggregation
- `agents/wpscan_agent.py`: WordPress security scanning agent for vulnerability and enumeration tasks
- `agents/nikto_agent.py`: Web server vulnerability scanning agent for misconfiguration and security testing
- `agents/metasploit_agent.py`: Penetration testing agent for exploitation, payload generation, and post-exploitation
- `tools/nmap_tool.py`: Direct subprocess execution of nmap commands with safety checks
- `tools/wpscan_tool.py`: Direct subprocess execution of wpscan commands for WordPress testing
- `tools/nikto_tool.py`: Direct subprocess execution of nikto commands for web server scanning
- `tools/metasploit_tool.py`: RPC-based integration with Metasploit Framework for exploitation capabilities
- `models/structured_results.py`: Pydantic models for structured results (NmapResult, WPScanResult, NiktoResult, MetasploitResult)

## Development Commands

### Run the System
```bash
python main.py
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Setup Environment
```bash
cp .env.example .env
# Edit .env and add:
# - GOOGLE_API_KEY from https://makersuite.google.com/app/apikey
# - MSF_PASSWORD for Metasploit RPC authentication
```

### Check Dependencies
```bash
# Verify tool installations
nmap --version
wpscan --version
nikto -Version

# Install tools if missing
sudo apt-get install nmap nikto  # Ubuntu/Debian
brew install nmap nikto          # macOS

# WPScan installation (Ruby gem)
gem install wpscan

# Start Metasploit RPC service
msfrpcd -P your_password -p 55553  # Replace with your password
# Or using Docker
docker run -it -p 55553:55553 metasploitframework/metasploit-framework
```

## Key Implementation Details

### Agent Communication Flow
1. **OrchestratorAgent** analyzes user request using Gemini LLM
2. Determines which specialized agent(s) to use based on capability matching
3. Creates specific task descriptions for selected tool agents
4. **Tool Agent** (Nmap/WPScan/Nikto) receives task and uses LangGraph ReAct agent
5. Agent invokes respective tool with actual commands
6. Tool executes via subprocess with 120-second timeout
7. Results parsed into structured Pydantic models and formatted for user

### Agent Capabilities

#### NmapAgent (Network Scanning)
- Port scanning and service detection
- OS fingerprinting
- Network discovery and host enumeration
- Vulnerability scanning with NSE scripts
- **Smart Scan Optimization**: Complex scans automatically split into manageable chunks
- **Progressive Retry**: Failed scans retried with smaller scope (up to 3 attempts)

#### WPScanAgent (WordPress Security)
- WordPress version detection
- Plugin and theme enumeration
- User enumeration
- Vulnerability database checking
- Security misconfiguration detection
- Weak password testing capabilities

#### NiktoAgent (Web Server Vulnerability)
- Web server vulnerability scanning
- CGI and dangerous file detection
- SSL/TLS configuration analysis
- Server misconfiguration identification
- Outdated software detection
- HTTP method testing

#### MetasploitAgent (Penetration Testing & Exploitation)
- **Exploitation**: Run exploit modules against vulnerable services
- **Payload Generation**: Create custom payloads for various platforms
- **Session Management**: Handle Meterpreter and shell sessions
- **Post-Exploitation**: Run post modules for privilege escalation, credential harvesting
- **Auxiliary Modules**: Execute scanners, fuzzers, and other auxiliary tools
- **RPC Connection**: Uses pymetasploit3 for API-based interaction (not subprocess)

### Safety Features
- File output flags (`-oX`, `-oN`, etc.) automatically removed
- Command injection patterns blocked
- Automatic sudo elevation for privileged operations
- 120-second timeout per command execution

## Structured Results Models

The system uses Pydantic models for structured output (`models/structured_results.py`):

- **NmapResult**: Contains port info, detected services, OS detection, vulnerabilities
- **WPScanResult**: WordPress version, plugins/themes found, users enumerated, vulnerabilities
- **NiktoResult**: Server info, vulnerabilities, SSL/TLS config, misconfigurations
- **MetasploitResult**: Exploits found, sessions active, module results, exploitation status
- **Supporting Models**: PortInfo, PluginInfo, ThemeInfo, VulnerabilityInfo, ExploitInfo, SessionInfo, ModuleResult

## Adding New Tools/Agents

To extend with new security tools:

1. **Create Tool** in `tools/` directory:
   - Use `@tool` decorator from langchain_core
   - Implement safety checks and actual command execution
   - Add validation function (e.g., `validate_tool_installed()`)
   - Return real execution output

2. **Create Agent** in `agents/` directory:
   - Initialize with LLM (Gemini)
   - Use LangGraph's `create_langgraph_agent`
   - Implement `process_request()` method
   - Add structured result parsing if needed
   - Include complexity analysis for optimization if applicable

3. **Register in Orchestrator**:
   - Add to `self.tool_agents` dict in `OrchestratorAgent.__init__()`
   - Add capabilities to `self.tool_capabilities`
   - The orchestrator will automatically route based on capability matching

4. **Update Dependencies**:
   - Add tool validation in `main.py`
   - Create Pydantic model in `models/structured_results.py` if needed

## Important Patterns

### Execution Verification
The system verifies actual command execution by checking for `[DEBUG]` markers in output. Fallback direct execution occurs if agent doesn't invoke tools.

### Colorized Output
Uses `colorama` for terminal colors:
- Cyan: System messages
- Yellow: Warnings and processing
- Green: Success
- Red: Errors
- Magenta: Debug information

### Message Formatting
Agent prompts emphasize EXECUTION with explicit instructions to use tools, not just explain commands.

### Example Usage Commands
```bash
# Network Scanning (Nmap)
"Scan localhost"                           # Basic host scan
"Find web servers on 192.168.1.0/24"      # Scan for web servers
"Check services on 192.168.1.1"           # Service version detection
"Stealth scan example.com"                # SYN stealth scan

# WordPress Security (WPScan)
"Scan WordPress site https://example.com"  # Basic WP scan
"Enumerate WordPress users on site.com"    # User enumeration
"Find WordPress plugins on blog.com"       # Plugin discovery
"Check WordPress vulnerabilities"          # Vulnerability scan

# Web Server Scanning (Nikto)
"Scan web server on example.com"          # Basic web scan
"Check SSL configuration on https://site" # SSL/TLS analysis
"Find vulnerabilities on port 8080"       # Custom port scan
"Test for misconfigurations"              # Configuration check

# Penetration Testing (Metasploit)
"Exploit EternalBlue on 192.168.1.100"    # Run exploit module
"Generate Windows reverse shell"           # Create payload
"List active sessions"                    # Session management
"Run hashdump on session 1"              # Post-exploitation
"Find SMB exploits"                      # Search exploits
"Generate meterpreter payload"           # Advanced payload
```

## Environment Variables

Required:
- `GOOGLE_API_KEY`: Gemini API key for LLM operations

Metasploit Configuration (Optional):
- `MSF_PASSWORD`: Password for Metasploit RPC authentication
- `MSF_SERVER`: Metasploit RPC server address (default: 127.0.0.1)
- `MSF_PORT`: Metasploit RPC port (default: 55553)
- `MSF_SSL`: Use SSL for RPC connection (default: true)

## Security Considerations

⚠️ **CRITICAL WARNING**: This system executes REAL commands and has REAL EXPLOITATION CAPABILITIES.

- **Network Scanning**: Can discover and probe systems on your network
- **Vulnerability Scanning**: Identifies real security issues in web applications
- **Exploitation**: Metasploit agent can compromise vulnerable systems
- **Post-Exploitation**: Can escalate privileges and harvest credentials

**Safety Guidelines**:
- Only use against systems you own or have explicit permission to test
- Run in isolated environments or containers when testing
- The system will attempt sudo elevation when needed for privileged operations
- Metasploit operations are particularly dangerous - use with extreme caution
- Consider using a dedicated penetration testing lab or virtual environment
- Always follow responsible disclosure practices for any vulnerabilities found