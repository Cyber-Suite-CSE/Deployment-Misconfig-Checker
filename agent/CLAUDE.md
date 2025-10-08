# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Multi-agent cybersecurity system using LangChain and Google Gemini for executing real network security commands. The system uses a hierarchical architecture where an orchestrator agent routes requests to specialized tool agents (currently NMAP).

## Architecture

```
User Request → OrchestratorAgent → NmapAgent → execute_nmap tool → Real Command Execution
```

**Key Components:**
- `main.py`: CLI interface with colorized output and interactive loop
- `agents/orchestrator_agent.py`: Routes requests to appropriate tool agents based on capability analysis
- `agents/nmap_agent.py`: Specialized agent with intelligent scan splitting, timeout recovery, and result aggregation
- `tools/nmap_tool.py`: Direct subprocess execution of nmap commands with safety checks

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
# Edit .env and add GOOGLE_API_KEY from https://makersuite.google.com/app/apikey
```

### Check Dependencies
```bash
# Verify nmap installation
nmap --version

# Install nmap if missing
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

## Key Implementation Details

### Agent Communication Flow
1. **OrchestratorAgent** analyzes user request using Gemini LLM
2. Creates specific task descriptions for tool agents
3. **NmapAgent** receives task and uses LangGraph ReAct agent
4. Agent invokes `execute_nmap` tool with actual commands
5. Tool executes via subprocess with 120-second timeout
6. Results aggregated and formatted for user

### Smart Scan Optimization (in NmapAgent)
- **Complexity Analysis**: Evaluates scan complexity based on ports, targets, options
- **Automatic Splitting**: Complex scans split into manageable chunks
- **Progressive Retry**: Failed scans retried with increasingly smaller scope (up to 3 attempts)
- **Result Aggregation**: Multiple scan results combined into comprehensive reports

### Safety Features
- File output flags (`-oX`, `-oN`, etc.) automatically removed
- Command injection patterns blocked
- Automatic sudo elevation for privileged operations
- 120-second timeout per command execution

## Adding New Tools/Agents

To extend with new security tools:

1. **Create Tool** in `tools/` directory:
   - Use `@tool` decorator from langchain_core
   - Implement safety checks and actual command execution
   - Return real execution output

2. **Create Agent** in `agents/` directory:
   - Initialize with LLM (Gemini)
   - Use LangGraph's `create_langgraph_agent`
   - Implement `process_request()` method
   - Add complexity analysis if needed for optimization

3. **Register in Orchestrator**:
   - Add to `self.tool_agents` dict in `OrchestratorAgent.__init__()`
   - Add capabilities to `self.tool_capabilities`
   - Update routing logic in `_route_to_agent()`

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

## Environment Variables

Required:
- `GOOGLE_API_KEY`: Gemini API key for LLM operations

## Security Considerations

This system executes REAL commands. It includes safety checks but should be run in isolated environments or containers when testing against production networks. The system will attempt sudo elevation when needed for privileged operations.