"""Interactive CLI for V1 ad-hoc runs. Usage: python -m v1.main"""

from __future__ import annotations

import os
import sys

from colorama import Fore, Style, init
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from v1.single_agent import SingleSecurityAgent

init(autoreset=True)


def banner() -> None:
    print(
        f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
 ║  {Fore.YELLOW}V1 Single-Agent Cybersecurity Baseline{Fore.CYAN}                     ║
 ║  {Fore.GREEN}One ReAct agent + all tools (nmap/nikto/wpscan/msf-passive){Fore.CYAN}║
 ║  {Fore.MAGENTA}⚡ EXECUTES REAL COMMANDS - USE IN A LAB ⚡{Fore.CYAN}                ║
 ╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    )


def main() -> None:
    load_dotenv()
    if not os.getenv("OPENAI_API_KEY"):
        print(f"{Fore.RED}Error: OPENAI_API_KEY not set in .env{Style.RESET_ALL}")
        sys.exit(1)

    banner()
    print(f"{Fore.CYAN}Initializing V1 agent…{Style.RESET_ALL}")
    agent = SingleSecurityAgent()
    print(
        f"{Fore.GREEN}✓ Ready. Model={agent.model} temp={agent.temperature} "
        f"recursion_limit={agent.recursion_limit}{Style.RESET_ALL}"
    )
    print(f"{Fore.YELLOW}Type 'exit' or 'quit' to leave.{Style.RESET_ALL}")

    while True:
        try:
            prompt = input(
                f"\n{Fore.CYAN}╭─[{Fore.YELLOW}V1{Fore.CYAN}]\n╰─{Fore.RED}#{Style.RESET_ALL} "
            ).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not prompt:
            continue
        if prompt.lower() in {"exit", "quit"}:
            break

        print(f"\n{Fore.YELLOW}[V1] Running…{Style.RESET_ALL}")
        try:
            out = agent.process_request(prompt)
        except Exception as exc:  # noqa: BLE001 — top-level user loop
            print(f"{Fore.RED}Error: {exc}{Style.RESET_ALL}")
            continue

        print(
            f"\n{Fore.GREEN}[V1] Wall clock: {out['wall_clock_seconds']:.1f}s "
            f"| messages: {len(out['all_messages'])}{Style.RESET_ALL}"
        )
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        print(out["final_message"])
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
