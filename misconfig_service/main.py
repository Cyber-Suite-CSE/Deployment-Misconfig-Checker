import json
import os
from datetime import datetime
from dotenv import load_dotenv

from config import SERVICES_DIR
from core.data_loader import DataLoader
from core.scanner import MisconfigScanner
from cli.commands import get_target_file, ask_run_exploits, ask_severity_level
from cli.output import display_fingerprint_results, display_exploit_results

load_dotenv()


def run_exploit_framework(matches):
    try:
        from exploits import ExploitManager, ExploitSeverity
        
        exploit_manager = ExploitManager()
        
        severity_choice = ask_severity_level()
        severity_map = {
            '1': ExploitSeverity.INFO,
            '2': ExploitSeverity.LOW,
            '3': ExploitSeverity.MEDIUM,
            '4': ExploitSeverity.HIGH,
            '5': ExploitSeverity.CRITICAL
        }
        
        max_severity = severity_map.get(severity_choice, ExploitSeverity.MEDIUM)
        print(f"Selected maximum severity: {max_severity.value.upper()}")
        
        exploit_results = exploit_manager.execute_exploits(matches, max_severity)
        
        display_exploit_results(exploit_results)
        
        if exploit_results:
            report_dir = "reports"
            os.makedirs(report_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(report_dir, f"exploit_report_{timestamp}.json")
            
            report = exploit_manager.generate_report(report_file)
            print(f"\nDEBUG: Exploit report generated: {report_file}")
            print(f"DEBUG: Total exploits executed: {report['total_exploits_executed']}")
            print(f"DEBUG: Successful exploits: {report['successful_exploits']}")
            
    except ImportError as e:
        print(f"DEBUG: Exploit framework not available: {e}")
    except Exception as e:
        print(f"DEBUG: Error running exploits: {e}")


def main():
    print("DEBUG: Starting fingerprint scanner...")
    try:
        print("DEBUG: Step 1 - Loading services configuration...")
        data_loader = DataLoader(SERVICES_DIR)
        services = data_loader.load_services()
        print(f"DEBUG: Loaded {len(services)} service fingerprints")
        
        print("DEBUG: Step 2 - Getting target data file...")
        target_file = get_target_file()
        if not target_file:
            return
        
        print("DEBUG: Step 3 - Loading target data...")
        target_data = data_loader.load_target_data(target_file)
        
        print("DEBUG: Step 4 - Starting target scan...")
        scanner = MisconfigScanner()
        matches = scanner.scan_target(services, target_data)
        
        print("DEBUG: Step 5 - Displaying results...")
        display_fingerprint_results(matches)
        
        if matches and ask_run_exploits():
            print("DEBUG: Step 6 - Running exploit framework...")
            run_exploit_framework(matches)
        else:
            print("DEBUG: Skipping exploit framework.")
            
    except FileNotFoundError as e:
        print(f"DEBUG: Error - File not found: {e}")
    except json.JSONDecodeError as e:
        print(f"DEBUG: Error - Invalid JSON format: {e}")
    except Exception as e:
        print(f"DEBUG: Unexpected error: {e}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    main()
