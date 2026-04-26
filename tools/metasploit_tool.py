import os
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from colorama import Fore, Style


def get_msf_client():
    """Stubbed client - Metasploit is disabled"""
    raise ConnectionError(
        "Metasploit integration has been removed for lightweight deployment."
    )


def validate_metasploit_connection() -> bool:
    """Check if Metasploit RPC service is reachable"""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient

        password = os.getenv("MSF_PASSWORD", "msf")
        server = os.getenv("MSF_SERVER", "127.0.0.1")
        port = int(os.getenv("MSF_PORT", "55553"))
        ssl = os.getenv("MSF_SSL", "true").lower() == "true"
        client = MsfRpcClient(password, server=server, port=port, ssl=ssl)
        print(f"{Fore.GREEN}✓ Metasploit RPC connection established{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(
            f"{Fore.YELLOW}ℹ️  Metasploit RPC not available: {str(e)}{Style.RESET_ALL}"
        )
        return False


@tool
def search_and_select_exploit(vulnerability_info: str) -> str:
    """
    Search for exploits (Disabled)
    """
    return "Exploitation capabilities are disabled in this lightweight version."


@tool
def execute_exploit(
    exploit_module: str, rhosts: str, lhost: str = "127.0.0.1", lport: str = "4444"
) -> str:
    """
    Execute exploit (Disabled)
    """
    return "Exploitation capabilities are disabled in this lightweight version."


@tool
def check_sessions() -> str:
    """
    Check sessions (Disabled)
    """
    return "Exploitation capabilities are disabled in this lightweight version."
