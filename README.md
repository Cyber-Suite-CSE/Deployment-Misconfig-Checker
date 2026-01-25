# Multi-Agent Cybersecurity System

A hierarchical multi-agent system for cybersecurity and penetration testing tasks using LangChain and Google Gemini.

## Architecture

```
User Request → OrchestratorAgent → Tool-Specific Agent (NMAP/WPScan) → Tool Execution → Response
```

- **Orchestrator Agent**: Analyzes user requests and routes to appropriate tool agents
- **NMAP Agent**: Specialized agent for network scanning and reconnaissance
- **NMAP Tool**: Executes actual nmap commands safely
- **WPScan Agent**: Specialized agent for WordPress security scanning
- **WPScan Tool**: Executes actual wpscan commands safely

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install NMAP

- **Ubuntu/Debian**: `sudo apt-get install nmap`
- **MacOS**: `brew install nmap`
- **Windows**: Download from [nmap.org](https://nmap.org/download.html)

### 3. Install WPScan

- **Ubuntu/Debian**: `sudo apt-get install wpscan`
- **MacOS**: `brew install wpscan`
- **Ruby Gem**: `gem install wpscan`
- **Docker**: `docker pull wpscanteam/wpscan`

### 4. Configure API Key

1. Get a Google Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a `.env` file:

```bash
cp .env.example .env
```

3. Edit `.env` and add your API key:

```
GOOGLE_API_KEY=your_actual_api_key_here
```

## Usage

Run the system:

```bash
msfrpcd -P yourpassword -p 55553
python main.py
```

### Example Commands

- **Basic port scan**: "Scan localhost for open ports"
- **Network discovery**: "Find all devices on 192.168.1.0/24"
- **Service detection**: "What services are running on 192.168.1.1?"
- **Stealth scan**: "Perform a stealth scan on example.com"
- **OS detection**: "Detect the operating system of 10.0.0.1"
- **Help with nmap**: "Show me how to use nmap for vulnerability scanning"
- **WordPress scan**: "Scan https://example.com for WordPress vulnerabilities"
- **Plugin enumeration**: "Find WordPress plugins on https://example.com"
- **User enumeration**: "Enumerate users on WordPress site https://example.com"
- **Theme detection**: "Check WordPress themes on https://example.com"

### Available Commands

- Type natural language requests for scanning tasks
- `help` or `?` - Show help message
- `capabilities` - Show available agent capabilities
- `clear` - Clear the screen
- `exit` or `quit` - Exit the program

## Project Structure

```
cyber_agent_system/
├── agents/
│   ├── orchestrator_agent.py   # Main orchestrator
│   ├── nmap_agent.py           # NMAP specialist
│   └── wpscan_agent.py         # WPScan specialist
├── tools/
│   ├── nmap_tool.py            # NMAP execution tool
│   └── wpscan_tool.py          # WPScan execution tool
├── main.py                     # Entry point
├── requirements.txt            # Dependencies
├── .env.example               # Environment template
└── README.md                  # This file
```

## Extending the System

To add new tools:

1. Create a new tool in `tools/` directory
2. Create a specialized agent in `agents/` directory
3. Register the agent in `orchestrator_agent.py`
4. Update the orchestrator's routing logic

## Security Notes

- The system includes safety checks to prevent dangerous commands
- Always use responsibly and only on networks you own or have permission to test
- Be aware of local laws and regulations regarding network scanning

## Future Enhancements

- [ ] Add Metasploit agent
- [ ] Add Nikto agent for web vulnerability scanning
- [ ] Add SQLMap agent for SQL injection testing
- [x] Add WPScan agent for WordPress security scanning
- [ ] Implement agent memory for context retention
- [ ] Add result parsing and structured output
- [ ] Create web UI interface
