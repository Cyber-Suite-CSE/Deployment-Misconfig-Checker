#!/usr/bin/env python3
"""
Multi-Agent Cybersecurity System - EXECUTION FOCUSED
A hierarchical agent system that EXECUTES REAL cybersecurity commands
"""

import os
import sys
from typing import Any, Dict
from dotenv import load_dotenv
from colorama import init, Fore, Style, Back
from agents.orchestrator_agent import OrchestratorAgent
from v2.orchestrator import V2DeepOrchestrator
from tools.nmap_tool import validate_nmap_installed
from tools.wpscan_tool import validate_wpscan_installed
from tools.nikto_tool import validate_nikto_installed
from v2.tools.masscan_tool import validate_masscan_installed
# from tools.metasploit_tool import validate_metasploit_connection # Disabled
from llm_factory import get_current_provider

init(autoreset=True)


def print_banner():
    """Print welcome banner with execution emphasis and LLM provider"""
    provider = get_current_provider()
    provider_display = "Google Gemini" if provider == "google_genai" else "OpenAI"
    orchestrator_mode = get_orchestrator_mode().upper()
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
 ║  {Fore.YELLOW}Multi-Agent Cybersecurity {Fore.RED}EXECUTION{Fore.YELLOW} System{Fore.CYAN}                 ║
 ║  {Fore.GREEN}Powered by LangChain & {provider_display}{Fore.CYAN}                              ║
 ║  {Fore.BLUE}Orchestrator Mode: {orchestrator_mode:<40}{Fore.CYAN}║
 ║  {Fore.MAGENTA}⚡ EXECUTES REAL COMMANDS - USE IN CONTAINER ⚡{Fore.CYAN}            ║
 ╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def print_help():
    """Print help with execution examples"""
    help_text = f"""
{Fore.YELLOW}═══ AVAILABLE COMMANDS ═══{Style.RESET_ALL}
{Fore.GREEN}▸{Style.RESET_ALL} Type cybersecurity requests - {Fore.RED}COMMANDS WILL BE EXECUTED{Style.RESET_ALL}
{Fore.GREEN}▸{Style.RESET_ALL} 'help' or '?' - Show this help
{Fore.GREEN}▸{Style.RESET_ALL} 'capabilities' - Show execution capabilities
{Fore.GREEN}▸{Style.RESET_ALL} 'clear' - Clear screen
{Fore.GREEN}▸{Style.RESET_ALL} 'exit' or 'quit' - Exit program

{Fore.YELLOW}═══ EXAMPLE EXECUTION REQUESTS ═══{Style.RESET_ALL}
{Fore.CYAN}▸{Style.RESET_ALL} "Scan localhost" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap localhost
{Fore.CYAN}▸{Style.RESET_ALL} "Find web servers on 192.168.1.0/24" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap -p 80,443 192.168.1.0/24
{Fore.CYAN}▸{Style.RESET_ALL} "Check services on 192.168.1.1" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap -sV 192.168.1.1
{Fore.CYAN}▸{Style.RESET_ALL} "Stealth scan example.com" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap -sS example.com
{Fore.CYAN}▸{Style.RESET_ALL} "Show nmap help" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap --help
{Fore.CYAN}▸{Style.RESET_ALL} "Scan WordPress site https://example.com" → {Fore.RED}EXECUTES:{Style.RESET_ALL} wpscan --url https://example.com
{Fore.CYAN}▸{Style.RESET_ALL} "Enumerate WordPress users" → {Fore.RED}EXECUTES:{Style.RESET_ALL} wpscan --url <url> --enumerate u
{Fore.CYAN}▸{Style.RESET_ALL} "Find WordPress plugins" → {Fore.RED}EXECUTES:{Style.RESET_ALL} wpscan --url <url> --enumerate p
{Fore.CYAN}▸{Style.RESET_ALL} "Scan web server example.com" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nikto -h example.com
{Fore.CYAN}▸{Style.RESET_ALL} "Exploit EternalBlue on 192.168.1.100" → {Fore.RED}EXECUTES:{Style.RESET_ALL} Metasploit ms17_010_eternalblue
{Fore.CYAN}▸{Style.RESET_ALL} "Generate Windows payload" → {Fore.RED}EXECUTES:{Style.RESET_ALL} msfvenom payload generation
{Fore.CYAN}▸{Style.RESET_ALL} "List Metasploit sessions" → {Fore.RED}EXECUTES:{Style.RESET_ALL} sessions -l

{Fore.MAGENTA}⚠️  ALL COMMANDS RUN FOR REAL - DEBUG OUTPUT WILL SHOW ⚠️{Style.RESET_ALL}
    """
    print(help_text)


def verify_execution_in_response(response: str) -> bool:
    """
    Verify that a command was actually executed

    Args:
        response: Response text to check

    Returns:
        True if execution was detected
    """
    execution_indicators = [
        "[DEBUG]",
        "Executing command:",
        "RAW STDOUT",
        "RAW STDERR",
        "Return code:",
        "Direct execution result:"
    ]

    for indicator in execution_indicators:
        if indicator in response:
            return True
    return False


def get_orchestrator_mode() -> str:
    """Get the configured orchestrator mode."""
    return os.getenv("ORCHESTRATOR_VERSION", "v2").lower()


def create_orchestrator():
    """Create the configured orchestrator implementation."""
    mode = get_orchestrator_mode()

    if mode == "v1":
        print(f"{Fore.CYAN}Using classic orchestrator (v1){Style.RESET_ALL}")
        return OrchestratorAgent()

    if mode == "v2":
        print(f"{Fore.CYAN}Using Deep Agents orchestrator (v2){Style.RESET_ALL}")
        return V2DeepOrchestrator()

    raise ValueError(
        f"Invalid ORCHESTRATOR_VERSION: {mode}. Supported values: 'v1', 'v2'."
    )


def print_progress_step(step_data: Dict[str, Any]):
    """Render real-time workflow progress from orchestrator callbacks."""
    agent = step_data.get("agent", "unknown")
    step = step_data.get("step", "?")
    target = step_data.get("target", "unknown")
    structured = step_data.get("structured_data", {}) or {}
    summary = structured.get("scan_summary", "Step completed")

    print(
        f"{Fore.BLUE}[Progress] Step {step}: {agent} completed for {target}{Style.RESET_ALL}"
    )
    print(f"{Fore.WHITE}Summary: {summary}{Style.RESET_ALL}")


def main():
    """Main application with execution verification"""
    # Load environment variables
    load_dotenv()

    # Check for appropriate API key based on provider
    provider = os.getenv("LLM_PROVIDER", "google_genai").lower()
    
    if provider == "openai":
        if not os.getenv("OPENAI_API_KEY"):
            print(f"{Fore.RED}Error: OPENAI_API_KEY not found{Style.RESET_ALL}")
            print("Please create a .env file with:")
            print(f"{Fore.YELLOW}LLM_PROVIDER=openai{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}OPENAI_API_KEY=your_openai_api_key_here{Style.RESET_ALL}")
            sys.exit(1)
    elif provider == "google_genai":
        if not os.getenv("GOOGLE_API_KEY"):
            print(f"{Fore.RED}Error: GOOGLE_API_KEY not found{Style.RESET_ALL}")
            print("Please create a .env file with:")
            print(f"{Fore.YELLOW}LLM_PROVIDER=google_genai{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}GOOGLE_API_KEY=your_gemini_api_key_here{Style.RESET_ALL}")
            sys.exit(1)
    else:
        print(f"{Fore.RED}Error: Invalid LLM_PROVIDER: {provider}{Style.RESET_ALL}")
        print("Supported providers: 'google_genai', 'openai'")
        sys.exit(1)

    print(f"{Fore.CYAN}Checking system requirements...{Style.RESET_ALL}")
    
    nmap_installed = validate_nmap_installed()
    wpscan_installed = validate_wpscan_installed()
    nikto_installed = validate_nikto_installed()
    masscan_installed = validate_masscan_installed()
    metasploit_connected = False # validate_metasploit_connection()

    if not nmap_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: nmap not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall nmap:")
        print(f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install nmap")
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install nmap")
        print(f"  {Fore.GREEN}Windows:{Style.RESET_ALL} https://nmap.org/download.html")

    if not wpscan_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: wpscan not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall wpscan:")
        print(f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install wpscan")
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install wpscan")
        print(f"  {Fore.GREEN}Ruby Gem:{Style.RESET_ALL} gem install wpscan")
        print(f"  {Fore.GREEN}Docker:{Style.RESET_ALL} docker pull wpscanteam/wpscan")

    if not nikto_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: nikto not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall nikto:")
        print(f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install nikto")
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install nikto")
        print(f"  {Fore.GREEN}CPAN:{Style.RESET_ALL} cpan install NIKTO")

    if not masscan_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: masscan not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}Deep service discovery will fall back to nmap only{Style.RESET_ALL}")
        print("\nInstall masscan:")
        print(f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install masscan")
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install masscan")



    if not nmap_installed or not wpscan_installed or not nikto_installed:
        print(f"\n{Fore.YELLOW}Or run in a container with tools pre-installed{Style.RESET_ALL}")

        response = input(f"\n{Fore.CYAN}Continue anyway? (y/n): {Style.RESET_ALL}")
        if response.lower() != 'y':
            sys.exit(0)

    # Print banner
    print_banner()
    print(f"{Fore.GREEN}Type 'help' for commands or 'exit' to quit{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}System will EXECUTE REAL COMMANDS - Use responsibly!{Style.RESET_ALL}\n")

    # Initialize orchestrator
    try:
        print(f"{Fore.CYAN}Initializing execution system...{Style.RESET_ALL}")
        orchestrator = create_orchestrator()
        print(f"{Fore.GREEN}✓ Execution system ready!{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.RED}Failed to initialize: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # Main loop
    while True:
        try:
            # Get user input
            user_input = input(f"\n{Fore.CYAN}╭─[{Fore.YELLOW}CyberExec{Fore.CYAN}]─[{Fore.GREEN}~{Fore.CYAN}]\n╰─{Fore.RED}#{Style.RESET_ALL} ").strip()

            # Handle commands
            if not user_input:
                continue

            if user_input.lower() in ['exit', 'quit']:
                print(f"{Fore.YELLOW}Shutting down execution system...{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                break

            if user_input.lower() in ['help', '?']:
                print_help()
                continue

            if user_input.lower() == 'capabilities':
                print("\n" + orchestrator.get_available_capabilities())
                continue

            if user_input.lower() == 'clear':
                os.system('clear' if os.name != 'nt' else 'cls')
                print_banner()
                continue

            # Process execution request
            print(f"\n{Fore.YELLOW}[System] Processing execution request...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")

            # Execute through orchestrator
            workflow_result = orchestrator.run_workflow(
                user_input,
                progress_callback=print_progress_step,
            )
            response = workflow_result.get("response", "")

            # Verify execution
            if workflow_result.get("type") == "information":
                print(f"\n{Fore.GREEN}✓ INFORMATION REQUEST ANSWERED{Style.RESET_ALL}")
            elif workflow_result.get("execution_history"):
                print(f"\n{Fore.GREEN}✓ COMMAND EXECUTED SUCCESSFULLY{Style.RESET_ALL}")
            elif verify_execution_in_response(response):
                print(f"\n{Fore.GREEN}✓ COMMAND EXECUTED SUCCESSFULLY{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}⚠️  No execution detected in response{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}The agent may have only provided information{Style.RESET_ALL}")

            print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}[Response]{Style.RESET_ALL}")
            print(response)

        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}Interrupted. Type 'exit' to quit.{Style.RESET_ALL}")
            continue
        except Exception as e:
            print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
            print("Try again or type 'help' for assistance.")


if __name__ == "__main__":
    main()
