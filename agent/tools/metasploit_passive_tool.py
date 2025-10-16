import os
import sys
import json
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from pymetasploit3.msfrpc import MsfRpcClient
from colorama import Fore, Style

_msf_client = None


def get_msf_client() -> MsfRpcClient:
    """Get or create Metasploit RPC client with lazy initialization"""
    global _msf_client

    if _msf_client is None:
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


@tool
def list_available_exploits(vulnerability_keywords: str, max_results: int = 10) -> str:
    """
    List available Metasploit exploits based on vulnerability keywords (PASSIVE - no execution)
    
    Args:
        vulnerability_keywords: Keywords related to vulnerabilities (e.g., "wordpress social warfare", "ms17-010", "apache struts")
        max_results: Maximum number of exploits to return (default: 10)
    
    Returns:
        Formatted list of available exploits with descriptions and required options
    """
    try:
        client = get_msf_client()
        
        print(f"{Fore.CYAN}[DEBUG] Searching for exploits matching: {vulnerability_keywords}{Style.RESET_ALL}")
        print(f"KEYWORD LIST: {vulnerability_keywords}\n")
        search_results = client.modules.search(vulnerability_keywords) or []

        print(f"{Fore.MAGENTA}[DEBUG] Raw modules.search() output:{Style.RESET_ALL}")
        print(json.dumps(search_results[:3], indent=2, default=str))
        print(f"{Fore.MAGENTA}[DEBUG] Total results: {len(search_results)}{Style.RESET_ALL}\n")

        exploit_results = [
            module for module in search_results
            if module.get("type", "").lower() == "exploit" and module.get("fullname")
        ][:max_results]

        if not exploit_results:
            return (
                f"No exploits found for: {vulnerability_keywords}\n\n"
                "Try refining the keywords (include product names, versions, or CVE IDs) "
                "or verify the module exists in the Metasploit database."
            )

        result_lines = [
            f"Found {len(exploit_results)} potential exploit(s) for: {vulnerability_keywords}\n"
        ]

        for idx, module in enumerate(exploit_results, 1):
            exploit_path = module["fullname"]
            result_lines.append(f"{idx}. {exploit_path}")

            try:
                module_info = client.modules.use(module.get("type", "exploit"), exploit_path)

                description = module_info.get('description', 'No description available')
                if len(description) > 200:
                    description = description[:200] + "..."
                result_lines.append(f"   Description: {description}")

                rank = module_info.get('rank', 'normal')
                result_lines.append(f"   Rank: {rank}")

                options = module_info.get('options', {})
                required_opts = [opt for opt, details in options.items() if details.get('required') and details.get('default') is None]

                if required_opts:
                    result_lines.append(f"   Required Options: {', '.join(required_opts)}")

                targets = module_info.get('targets', [])
                if targets and len(targets) > 0:
                    result_lines.append(f"   Available Targets: {len(targets)}")

            except Exception as e:
                result_lines.append(f"   (Unable to fetch details: {str(e)})")

            result_lines.append("")

        result_lines.append(
            f"{Fore.YELLOW}NOTE: These are reconnaissance results only. No exploits have been executed.{Style.RESET_ALL}"
        )

        return "\n".join(result_lines)
        
    except Exception as e:
        return f"Error searching exploits: {str(e)}"


@tool
def get_exploit_details(exploit_path: str) -> str:
    """
    Get detailed information about a specific Metasploit exploit (PASSIVE)
    
    Args:
        exploit_path: Full path to the exploit module (e.g., "exploit/windows/smb/ms17_010_eternalblue")
    
    Returns:
        Detailed information about the exploit including options, targets, and usage
    """
    try:
        client = get_msf_client()
        
        print(f"{Fore.CYAN}[DEBUG] Getting details for: {exploit_path}{Style.RESET_ALL}")
        
        module_info = client.modules.use('exploit', exploit_path)
        
        result = f"=== EXPLOIT DETAILS ===\n\n"
        result += f"Module: {exploit_path}\n\n"
        
        description = module_info.get('description', 'No description available')
        result += f"Description:\n{description}\n\n"
        
        authors = module_info.get('author', [])
        if authors:
            result += f"Author(s): {', '.join(authors)}\n\n"
        
        rank = module_info.get('rank', 'normal')
        result += f"Reliability Rank: {rank}\n\n"
        
        references = module_info.get('references', [])
        if references:
            result += f"References:\n"
            for ref in references[:5]:
                result += f"  - {ref}\n"
            result += "\n"
        
        options = module_info.get('options', {})
        if options:
            result += "Options:\n"
            for opt_name, opt_details in options.items():
                required = "Required" if opt_details.get('required') else "Optional"
                default = opt_details.get('default', 'None')
                desc = opt_details.get('desc', 'No description')
                result += f"  {opt_name} ({required}): {desc}\n"
                result += f"    Default: {default}\n"
            result += "\n"
        
        targets = module_info.get('targets', [])
        if targets:
            result += f"Available Targets ({len(targets)}):\n"
            for idx, target in enumerate(targets[:10]):
                result += f"  {idx}: {target}\n"
            result += "\n"
        
        payloads = module_info.get('payloads', [])
        if payloads:
            result += f"Compatible Payloads: {len(payloads)} available\n"
            for payload in payloads[:5]:
                result += f"  - {payload}\n"
            result += "\n"
        
        result += f"\n{Fore.YELLOW}This is informational only - no exploit has been executed.{Style.RESET_ALL}"
        
        return result
        
    except Exception as e:
        return f"Error getting exploit details: {str(e)}"


@tool  
def search_exploits_by_cve(cve_id: str) -> str:
    """
    Search for Metasploit exploits by CVE identifier (PASSIVE)
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2017-0144", "2017-0144")
    
    Returns:
        List of exploits that target the specified CVE
    """
    try:
        client = get_msf_client()
        
        if not cve_id.upper().startswith('CVE-'):
            cve_id = f"CVE-{cve_id}"
        
        print(f"{Fore.CYAN}[DEBUG] Searching for exploits targeting: {cve_id}{Style.RESET_ALL}\n")
        
        all_exploits = client.modules.exploits
        matched_exploits = []
        
        cve_normalized = cve_id.replace('-', '_').lower()
        cve_year = cve_id.split('-')[1] if '-' in cve_id else ""
        
        for exploit in all_exploits:
            exploit_lower = exploit.lower()
            if (cve_normalized in exploit_lower or 
                cve_id.lower() in exploit_lower or
                cve_year in exploit_lower):
                matched_exploits.append(exploit)
        
        if not matched_exploits:
            return f"No exploits found for {cve_id}\n\nThe CVE may not have a Metasploit module, or try searching by vulnerability name instead."
        
        result = f"Found {len(matched_exploits)} exploit(s) for {cve_id}:\n\n"
        
        for idx, exploit_path in enumerate(matched_exploits, 1):
            result += f"{idx}. {exploit_path}\n"
            
            try:
                module_info = client.modules.use('exploit', exploit_path)
                description = module_info.get('description', 'No description')[:150]
                rank = module_info.get('rank', 'normal')
                result += f"   {description}...\n"
                result += f"   Rank: {rank}\n"
            except:
                pass
            
            result += "\n"
        
        result += f"\n{Fore.YELLOW}Use get_exploit_details to learn more about a specific exploit.{Style.RESET_ALL}"
        
        return result
        
    except Exception as e:
        return f"Error searching by CVE: {str(e)}"
