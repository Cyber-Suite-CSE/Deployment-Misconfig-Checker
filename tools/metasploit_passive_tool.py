import os
import re
import sys
import json
from typing import Dict, Any, List, Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator
from pymetasploit3.msfrpc import MsfRpcClient
from colorama import Fore, Style

_msf_client = None


_KEYWORDS_RE = re.compile(r"^[\w \-.]{1,200}$")
_MODULE_PATH_RE = re.compile(r"^(exploit|auxiliary|post|payload|encoder|nop)/[a-z0-9_/]{1,200}$")
_CVE_RE = re.compile(r"^(CVE-)?\d{4}-\d{4,7}$", re.IGNORECASE)


class ListExploitsInput(BaseModel):
    vulnerability_keywords: str = Field(
        description=(
            "Keywords to search the Metasploit module index. "
            "Allowed chars: alphanumerics, spaces, '-' and '.'. "
            "Examples: 'wordpress social warfare', 'ms17-010', 'apache struts'."
        ),
    )
    max_results: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum exploits to return (clamped to 1-50).",
    )

    @field_validator("vulnerability_keywords")
    @classmethod
    def _validate_keywords(cls, v: str) -> str:
        v = v.strip()
        if not _KEYWORDS_RE.match(v):
            raise ValueError(
                "vulnerability_keywords contains disallowed characters; "
                "allowed set: alphanumerics, spaces, '-', '.'"
            )
        return v


class ExploitDetailsInput(BaseModel):
    exploit_path: str = Field(
        description=(
            "Full module path. Must match "
            "'(exploit|auxiliary|post|payload|encoder|nop)/<lowercase/path>'. "
            "Example: 'exploit/windows/smb/ms17_010_eternalblue'."
        ),
    )

    @field_validator("exploit_path")
    @classmethod
    def _validate_path(cls, v: str) -> str:
        v = v.strip()
        if not _MODULE_PATH_RE.match(v):
            raise ValueError(
                "exploit_path must match "
                "'(exploit|auxiliary|post|payload|encoder|nop)/<a-z0-9_/>'"
            )
        return v


class CveSearchInput(BaseModel):
    cve_id: str = Field(
        description=(
            "CVE identifier. Accepts 'CVE-YYYY-NNNN' or 'YYYY-NNNN' "
            "(case-insensitive). Normalised to 'CVE-YYYY-NNNN'."
        ),
    )

    @field_validator("cve_id")
    @classmethod
    def _validate_cve(cls, v: str) -> str:
        v = v.strip()
        if not _CVE_RE.match(v):
            raise ValueError("cve_id must match 'CVE-YYYY-NNNN' or 'YYYY-NNNN'")
        if not v.upper().startswith("CVE-"):
            v = f"CVE-{v}"
        return v.upper()


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


def validate_metasploit_connection() -> bool:
    """Check if Metasploit RPC service is reachable."""
    try:
        get_msf_client()
        print(f"{Fore.GREEN}✓ Metasploit RPC connection established{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.YELLOW}ℹ️  Metasploit RPC not available: {str(e)}{Style.RESET_ALL}")
        return False


@tool("list_available_exploits", args_schema=ListExploitsInput, return_direct=False)
def list_available_exploits(vulnerability_keywords: str, max_results: int = 10) -> str:
    """List available Metasploit exploits matching vulnerability keywords (PASSIVE — no execution).

    Inputs are validated by the schema: keywords match `^[\\w \\-.]{1,200}$` and
    max_results is clamped to 1-50. Returns formatted module info; never runs them.
    """
    # Re-validate so errors are caught when the tool is called programmatically.
    params = ListExploitsInput(
        vulnerability_keywords=vulnerability_keywords,
        max_results=max_results,
    )
    vulnerability_keywords = params.vulnerability_keywords
    max_results = params.max_results
    try:
        client = get_msf_client()
        
        print(f"{Fore.CYAN}[DEBUG] Searching for exploits matching: {vulnerability_keywords}{Style.RESET_ALL}")
        print(f"KEYWORD LIST: {vulnerability_keywords}\n")
        # Use the raw RPC call so this works on pymetasploit3 1.0.3 (which lacks
        # ModuleManager.search) as well as 1.0.6+. The underlying module.search
        # endpoint has been stable in MSF for years.
        search_results = client.call('module.search', [vulnerability_keywords]) or []

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


@tool("get_exploit_details", args_schema=ExploitDetailsInput, return_direct=False)
def get_exploit_details(exploit_path: str) -> str:
    """Get detailed information about a Metasploit module path (PASSIVE).

    Path is validated by the schema. Returns description, rank, options,
    targets, and compatible payloads. Does not run the module.
    """
    params = ExploitDetailsInput(exploit_path=exploit_path)
    exploit_path = params.exploit_path
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


@tool("search_exploits_by_cve", args_schema=CveSearchInput, return_direct=False)
def search_exploits_by_cve(cve_id: str) -> str:
    """Search for Metasploit modules tagged with a CVE identifier (PASSIVE).

    The schema accepts 'CVE-YYYY-NNNN' or bare 'YYYY-NNNN' and normalises
    to the canonical 'CVE-YYYY-NNNN' form before searching.
    """
    params = CveSearchInput(cve_id=cve_id)
    cve_id = params.cve_id
    try:
        client = get_msf_client()

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
