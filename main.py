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
from agents.hitl_helpers import AUDIT_LOG_PATH, CHECKPOINT_DB_PATH
from tools.nmap_tool import validate_nmap_installed
from tools.masscan_tool import validate_masscan_installed
from tools.wpscan_tool import validate_wpscan_installed
from tools.nikto_tool import validate_nikto_installed
from tools.metasploit_passive_tool import validate_metasploit_connection
from llm_factory import get_current_provider

init(autoreset=True)


def _bootstrap_hitl_paths() -> None:
    """Make sure ./logs/ and the checkpointer DB directory are writable.

    Failure here is non-fatal — we warn and let the user decide whether to continue.
    """
    for label, path in (
        ("audit log", AUDIT_LOG_PATH),
        ("checkpointer db", CHECKPOINT_DB_PATH),
    ):
        directory = os.path.dirname(path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
            probe = os.path.join(directory, ".write_probe")
            with open(probe, "w") as fh:
                fh.write("")
            os.remove(probe)
        except OSError as exc:
            print(
                f"{Fore.YELLOW}[System] Warning: cannot write {label} at {path} ({exc}){Style.RESET_ALL}"
            )


def _audit_count_for_session(start_size: int) -> int:
    """Lines added to the audit log since ``start_size`` bytes."""
    try:
        with open(AUDIT_LOG_PATH, "rb") as fh:
            fh.seek(start_size)
            return sum(1 for _ in fh)
    except FileNotFoundError:
        return 0


def print_banner():
    """Print welcome banner with execution emphasis and LLM provider"""
    provider = get_current_provider()
    provider_display = "Google Gemini" if provider == "google_genai" else "OpenAI"
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
 ║  {Fore.YELLOW}Multi-Agent Cybersecurity {Fore.RED}EXECUTION{Fore.YELLOW} System{Fore.CYAN}                 ║
 ║  {Fore.GREEN}Powered by LangChain & {provider_display}{Fore.CYAN}                              ║
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
{Fore.GREEN}▸{Style.RESET_ALL} '/clear' - Start a new session (fresh thread, clears screen)
{Fore.GREEN}▸{Style.RESET_ALL} '/resume [id]' - List previous sessions or resume one by id/prefix
{Fore.GREEN}▸{Style.RESET_ALL} 'exit' or 'quit' - Exit program

{Fore.YELLOW}═══ EXAMPLE EXECUTION REQUESTS ═══{Style.RESET_ALL}
{Fore.CYAN}▸{Style.RESET_ALL} "Scan localhost" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap localhost
{Fore.CYAN}▸{Style.RESET_ALL} "Find web servers on 192.168.1.0/24" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap -p 80,443 192.168.1.0/24
{Fore.CYAN}▸{Style.RESET_ALL} "Check services on 192.168.1.1" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap -sV 192.168.1.1
{Fore.CYAN}▸{Style.RESET_ALL} "Stealth scan example.com" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap -sS example.com
{Fore.CYAN}▸{Style.RESET_ALL} "Show nmap help" → {Fore.RED}EXECUTES:{Style.RESET_ALL} nmap --help
{Fore.CYAN}▸{Style.RESET_ALL} "Sweep 10.0.0.0/8 fast" → {Fore.RED}EXECUTES:{Style.RESET_ALL} masscan -p80,443 10.0.0.0/8 --rate=1000
{Fore.CYAN}▸{Style.RESET_ALL} "Find open ports across 192.168.0.0/16" → {Fore.RED}EXECUTES:{Style.RESET_ALL} masscan -p1-65535 192.168.0.0/16 --rate=10000
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


def _render_session_list(sessions) -> None:
    """Print a numbered table of recent sessions to stdout."""
    if not sessions:
        print(f"{Fore.YELLOW}No previous sessions found.{Style.RESET_ALL}")
        return
    print(
        f"\n{Fore.CYAN}{'#':>3}  {'id':<10} {'updated':<22} {'turns':>5}  first message{Style.RESET_ALL}"
    )
    for idx, entry in enumerate(sessions, start=1):
        tid = entry.get("thread_id", "")[:8]
        updated = entry.get("updated_at", "")[:19].replace("T", " ")
        turns = entry.get("turn_count", 0)
        first = (entry.get("first_message") or "").replace("\n", " ")
        if len(first) > 60:
            first = first[:57] + "..."
        print(f"{idx:>3}  {tid:<10} {updated:<22} {turns:>5}  {first}")


def _resume_by_input(orchestrator, raw: str, sessions) -> None:
    """Resolve user input (number, id, or prefix) and resume the session."""
    raw = raw.strip()
    if not raw:
        print(f"{Fore.YELLOW}Cancelled.{Style.RESET_ALL}")
        return
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(sessions):
            target = sessions[idx - 1]["thread_id"]
            resolved = orchestrator.resume_session(target)
        else:
            resolved = None
    else:
        resolved = orchestrator.resume_session(raw)
    if resolved:
        print(
            f"{Fore.GREEN}[Session] Resumed {resolved[:8]}{Style.RESET_ALL}"
        )
    else:
        print(f"{Fore.RED}No session found matching {raw!r}{Style.RESET_ALL}")


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
        "Direct execution result:",
    ]

    for indicator in execution_indicators:
        if indicator in response:
            return True
    return False


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
            print(
                f"{Fore.YELLOW}OPENAI_API_KEY=your_openai_api_key_here{Style.RESET_ALL}"
            )
            sys.exit(1)
    elif provider == "google_genai":
        if not os.getenv("GOOGLE_API_KEY"):
            print(f"{Fore.RED}Error: GOOGLE_API_KEY not found{Style.RESET_ALL}")
            print("Please create a .env file with:")
            print(f"{Fore.YELLOW}LLM_PROVIDER=google_genai{Style.RESET_ALL}")
            print(
                f"{Fore.YELLOW}GOOGLE_API_KEY=your_gemini_api_key_here{Style.RESET_ALL}"
            )
            sys.exit(1)
    else:
        print(f"{Fore.RED}Error: Invalid LLM_PROVIDER: {provider}{Style.RESET_ALL}")
        print("Supported providers: 'google_genai', 'openai'")
        sys.exit(1)

    print(f"{Fore.CYAN}Checking system requirements...{Style.RESET_ALL}")

    nmap_installed = validate_nmap_installed()
    masscan_installed = validate_masscan_installed()
    wpscan_installed = validate_wpscan_installed()
    nikto_installed = validate_nikto_installed()
    metasploit_connected = validate_metasploit_connection()

    if not nmap_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: nmap not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall nmap:")
        print(
            f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install nmap"
        )
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install nmap")
        print(f"  {Fore.GREEN}Windows:{Style.RESET_ALL} https://nmap.org/download.html")

    if not masscan_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: masscan not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall masscan:")
        print(
            f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install masscan"
        )
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install masscan")
        print(f"  {Fore.GREEN}Alpine:{Style.RESET_ALL} apk add masscan")

    if not wpscan_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: wpscan not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall wpscan:")
        print(
            f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install wpscan"
        )
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install wpscan")
        print(f"  {Fore.GREEN}Ruby Gem:{Style.RESET_ALL} gem install wpscan")
        print(f"  {Fore.GREEN}Docker:{Style.RESET_ALL} docker pull wpscanteam/wpscan")

    if not nikto_installed:
        print(f"\n{Fore.YELLOW}⚠️  Warning: nikto not detected{Style.RESET_ALL}")
        print(f"{Fore.RED}This system EXECUTES REAL COMMANDS!{Style.RESET_ALL}")
        print("\nInstall nikto:")
        print(
            f"  {Fore.GREEN}Ubuntu/Debian:{Style.RESET_ALL} sudo apt-get install nikto"
        )
        print(f"  {Fore.GREEN}MacOS:{Style.RESET_ALL} brew install nikto")
        print(f"  {Fore.GREEN}CPAN:{Style.RESET_ALL} cpan install NIKTO")

    if not metasploit_connected:
        print(
            f"\n{Fore.YELLOW}⚠️  Warning: Metasploit RPC not connected{Style.RESET_ALL}"
        )
        print(f"{Fore.RED}Exploit reconnaissance will be unavailable!{Style.RESET_ALL}")
        print("\nStart Metasploit RPC service:")
        print(f"  {Fore.GREEN}msfrpcd -P your_password -p 55553{Style.RESET_ALL}")
        print(
            f"  {Fore.GREEN}Docker:{Style.RESET_ALL} docker run -it -p 55553:55553 metasploitframework/metasploit-framework"
        )

    if not nmap_installed or not masscan_installed or not wpscan_installed or not nikto_installed:
        print(
            f"\n{Fore.YELLOW}Or run in a container with tools pre-installed{Style.RESET_ALL}"
        )

        response = input(f"\n{Fore.CYAN}Continue anyway? (y/n): {Style.RESET_ALL}")
        if response.lower() != "y":
            sys.exit(0)

    # Print banner
    print_banner()
    print(f"{Fore.GREEN}Type 'help' for commands or 'exit' to quit{Style.RESET_ALL}")
    print(
        f"{Fore.MAGENTA}System will EXECUTE REAL COMMANDS - Use responsibly!{Style.RESET_ALL}\n"
    )

    # Bootstrap HITL paths (audit log + checkpointer DB)
    _bootstrap_hitl_paths()

    # Initialize orchestrator
    try:
        print(f"{Fore.CYAN}Initializing execution system...{Style.RESET_ALL}")
        orchestrator = OrchestratorAgent()
        print(f"{Fore.GREEN}✓ Execution system ready!{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN}[Session] {orchestrator.current_session_id()[:8]} "
            f"(use /resume to continue an older one){Style.RESET_ALL}\n"
        )
    except Exception as e:
        print(f"{Fore.RED}Failed to initialize: {e}{Style.RESET_ALL}")
        sys.exit(1)

    # If --tui was passed, hand off to the Textual front-end and skip the REPL.
    if "--tui" in sys.argv:
        try:
            from tui import run_tui
        except ImportError as e:
            print(
                f"{Fore.RED}Failed to import TUI: {e}{Style.RESET_ALL}\n"
                f"Install dependencies: {Fore.GREEN}pip install -r requirements.txt{Style.RESET_ALL}"
            )
            sys.exit(1)
        run_tui(orchestrator)
        return

    # Main loop
    while True:
        try:
            # Get user input
            user_input = input(
                f"\n{Fore.CYAN}╭─[{Fore.YELLOW}CyberExec{Fore.CYAN}]─[{Fore.GREEN}~{Fore.CYAN}]\n╰─{Fore.RED}#{Style.RESET_ALL} "
            ).strip()

            # Handle commands
            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit"]:
                print(
                    f"{Fore.YELLOW}Shutting down execution system...{Style.RESET_ALL}"
                )
                print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                break

            if user_input.lower() in ["help", "?"]:
                print_help()
                continue

            if user_input.lower() == "capabilities":
                print("\n" + orchestrator.get_available_capabilities())
                continue

            lowered = user_input.lower().strip()
            if lowered == "/clear":
                new_id = orchestrator.new_session()
                os.system("clear" if os.name != "nt" else "cls")
                print_banner()
                print(
                    f"{Fore.GREEN}[Session] New session started: {new_id[:8]}{Style.RESET_ALL}"
                )
                continue

            if lowered == "/resume" or lowered.startswith("/resume "):
                arg = user_input.strip()[len("/resume"):].strip()
                current = orchestrator.current_session_id()
                sessions = [
                    s for s in orchestrator.list_sessions()
                    if s.get("thread_id") != current
                ]
                if arg:
                    _resume_by_input(orchestrator, arg, sessions)
                    continue
                _render_session_list(sessions)
                if not sessions:
                    continue
                pick = input(
                    f"\n{Fore.CYAN}Resume which? "
                    f"(number, full id, or prefix; blank to cancel) > {Style.RESET_ALL}"
                )
                _resume_by_input(orchestrator, pick, sessions)
                continue

            # Process execution request
            print(
                f"\n{Fore.YELLOW}[System] Processing execution request...{Style.RESET_ALL}"
            )
            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")

            # Snapshot audit log size so we can report decisions added during this request
            try:
                audit_start_size = os.path.getsize(AUDIT_LOG_PATH)
            except OSError:
                audit_start_size = 0

            # Execute through orchestrator
            response = orchestrator.process_user_request(user_input)

            # Verify execution — supervisor's final synthesis is clean text without [DEBUG]
            # markers, so authoritative source is the orchestrator's execution history.
            executed_steps = len(orchestrator._execution_history)
            if executed_steps > 0 or verify_execution_in_response(response):
                if executed_steps:
                    print(
                        f"\n{Fore.GREEN}✓ {executed_steps} agent step(s) EXECUTED SUCCESSFULLY{Style.RESET_ALL}"
                    )
                else:
                    print(f"\n{Fore.GREEN}✓ COMMAND EXECUTED SUCCESSFULLY{Style.RESET_ALL}")
            else:
                print(
                    f"\n{Fore.YELLOW}⚠️  No execution detected{Style.RESET_ALL}"
                )
                print(
                    f"{Fore.YELLOW}The agent may have only provided information{Style.RESET_ALL}"
                )

            new_decisions = _audit_count_for_session(audit_start_size)
            if new_decisions:
                print(
                    f"{Fore.BLUE}[Audit] {new_decisions} HITL decision(s) recorded → {AUDIT_LOG_PATH}{Style.RESET_ALL}"
                )

            print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}[Response]{Style.RESET_ALL}")
            print(response)

        except KeyboardInterrupt:
            print(
                f"\n\n{Fore.YELLOW}Interrupted. Type 'exit' to quit.{Style.RESET_ALL}"
            )
            continue
        except Exception as e:
            print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
            print("Try again or type 'help' for assistance.")


if __name__ == "__main__":
    main()
