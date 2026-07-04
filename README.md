# Multi-Agent Cybersecurity System

A multi-agent system that executes real cybersecurity commands using LangChain and LangGraph. An orchestrator routes natural-language requests to specialized tool agents.

## Architecture

```
User Request → Orchestrator → [Nmap | Masscan | WPScan | Nikto | Metasploit] → Command Execution → Results
```

## Setup

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Security Tools

```bash
sudo apt-get install nmap masscan nikto        # Ubuntu/Debian
brew install nmap masscan nikto                 # macOS
gem install wpscan                              # WPScan (Ruby gem)
```

Start the Metasploit RPC service:

```bash
msfrpcd -P your_password -p 55553
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:

```
LLM_PROVIDER=google_genai          # or "openai"
GOOGLE_API_KEY=your_key_here       # if using Google Gemini
OPENAI_API_KEY=your_key_here       # if using OpenAI
MSF_PASSWORD=your_msfrpc_password
```

## Usage

```bash
python main.py          # CLI mode
python main.py --tui    # TUI mode
```

### Example Commands

| Request | Tool |
|---|---|
| "Scan localhost" | Nmap |
| "Find web servers on 192.168.1.0/24" | Nmap |
| "Stealth scan example.com" | Nmap |
| "Sweep 10.0.0.0/8 fast" | Masscan |
| "Scan WordPress site https://example.com" | WPScan |
| "Enumerate WordPress users" | WPScan |
| "Scan web server example.com" | Nikto |
| "Check SSL configuration on https://site" | Nikto |
| "Exploit EternalBlue on 192.168.1.100" | Metasploit |
| "Generate Windows reverse shell" | Metasploit |
| "List active sessions" | Metasploit |

### CLI Commands

- `help` / `?` — Show help
- `capabilities` — Show agent capabilities
- `/clear` — Start a new session
- `/resume [id]` — List or resume previous sessions
- `exit` / `quit` — Exit

## Project Structure

```
agents/          # Orchestrator + tool-specific agents (Nmap, Masscan, WPScan, Nikto, Metasploit)
tools/           # Subprocess/RPC execution for each security tool
models/          # Pydantic models for structured results
prompts/         # Agent prompt templates
tui/             # Textual-based terminal UI
backend/         # FastAPI backend
eval/            # Evaluation scripts
main.py          # Entry point
llm_factory.py   # LLM provider initialization (Gemini / OpenAI)
```

## Security Warning

This system executes **real commands** with real capabilities including exploitation. Only use against systems you own or have explicit permission to test.
