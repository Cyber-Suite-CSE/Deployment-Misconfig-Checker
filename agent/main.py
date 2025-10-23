#!/usr/bin/env python3
"""
Multi-Agent Cybersecurity System - EXECUTION FOCUSED
A hierarchical agent system that EXECUTES REAL cybersecurity commands
"""

import os
import sys
from dotenv import load_dotenv
from colorama import init, Fore, Style, Back
from agents.orchestrator_agent import OrchestratorAgent
from tools.nmap_tool import validate_nmap_installed
from tools.wpscan_tool import validate_wpscan_installed
from tools.nikto_tool import validate_nikto_installed
from tools.metasploit_tool import validate_metasploit_connection

init(autoreset=True)


def print_banner():
    """Print welcome banner with execution emphasis"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}Multi-Agent Cybersecurity {Fore.RED}EXECUTION{Fore.YELLOW} System{Fore.CYAN}                 ║
║  {Fore.GREEN}Powered by LangChain & Gemini{Fore.CYAN}                              ║
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


def main():
    """Main application with execution verification"""
    # Load environment variables
    load_dotenv()

    llm_provider = os.getenv("LLM_PROVIDER", "openai")
    
    if llm_provider == "openai":
        if not os.getenv("OPENAI_API_KEY"):
            print(f"{Fore.RED}Error: OPENAI_API_KEY not found{Style.RESET_ALL}")
            print("Please create a .env file with:")
            print(f"{Fore.YELLOW}OPENAI_API_KEY=your_api_key_here{Style.RESET_ALL}")
            sys.exit(1)
    elif llm_provider == "google_genai":
        if not os.getenv("GOOGLE_API_KEY"):
            print(f"{Fore.RED}Error: GOOGLE_API_KEY not found{Style.RESET_ALL}")
            print("Please create a .env file with:")
            print(f"{Fore.YELLOW}GOOGLE_API_KEY=your_api_key_here{Style.RESET_ALL}")
            sys.exit(1)
    else:
        print(f"{Fore.RED}Error: Invalid LLM_PROVIDER={llm_provider}{Style.RESET_ALL}")
        print(f"Valid options: 'openai' or 'google_genai'")
        sys.exit(1)

    print(f"{Fore.CYAN}Checking system requirements...{Style.RESET_ALL}")
    
    nmap_installed = validate_nmap_installed()
    wpscan_installed = validate_wpscan_installed()
    nikto_installed = validate_nikto_installed()
    metasploit_connected = validate_metasploit_connection()

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

    if not metasploit_connected:
        print(f"\n{Fore.YELLOW}⚠️  Warning: Metasploit RPC not connected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system has REAL EXPLOITATION CAPABILITIES!{Style.RESET_ALL}")
        print("\nStart Metasploit RPC:")
        print(f"  {Fore.GREEN}Start RPC:{Style.RESET_ALL} msfrpcd -P <password> -p 55553")
        print(f"  {Fore.GREEN}Set .env:{Style.RESET_ALL} MSF_PASSWORD=<password>")
        print(f"  {Fore.GREEN}Docker:{Style.RESET_ALL} docker run -p 55553:55553 metasploit/metasploit-framework")

    if not nmap_installed or not wpscan_installed or not nikto_installed or not metasploit_connected:
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
        orchestrator = OrchestratorAgent()
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
            response = orchestrator.process_user_request(user_input)

            # Verify execution
            if verify_execution_in_response(response):
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