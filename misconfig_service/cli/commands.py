from typing import Optional


def get_target_file() -> Optional[str]:
    target_file = input("Enter path to target data JSON file: ").strip()
    if not target_file:
        print("DEBUG: No file provided. Exiting.")
        return None
    return target_file


def ask_run_exploits() -> bool:
    print(f"\nDEBUG: === EXPLOIT FRAMEWORK ===")
    run_exploits = input("Do you want to run exploit tests on detected vulnerabilities? (y/N): ").strip().lower()
    return run_exploits in ['y', 'yes']


def ask_severity_level():
    print("\nAvailable severity levels:")
    print("1. INFO - Information gathering only")
    print("2. LOW - Safe reconnaissance") 
    print("3. MEDIUM - Limited security testing")
    print("4. HIGH - Comprehensive security testing")
    print("5. CRITICAL - Advanced penetration testing")
    
    severity_choice = input("Choose maximum severity level (1-3 recommended): ").strip()
    return severity_choice
