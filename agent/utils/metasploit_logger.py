"""
Enhanced logging wrapper for Metasploit tools
Use this to verify that Metasploit is actually being used
"""

import os
import sys
from datetime import datetime
from pathlib import Path

# Create logs directory
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / f"metasploit_activity_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


class MetasploitLogger:
    """Logger to track all Metasploit activity"""
    
    def __init__(self):
        self.log_file = open(LOG_FILE, "w")
        self.log(f"=== Metasploit Activity Log Started at {datetime.now()} ===\n")
    
    def log(self, message: str):
        """Write to both console and file"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {message}\n"
        print(log_entry, end="")
        self.log_file.write(log_entry)
        self.log_file.flush()
    
    def log_rpc_call(self, method: str, params: dict = None):
        """Log RPC method call"""
        self.log(f"🔌 RPC CALL: {method}")
        if params:
            self.log(f"   Parameters: {params}")
    
    def log_tool_call(self, tool_name: str, args: dict):
        """Log tool invocation"""
        self.log(f"🔧 TOOL CALLED: {tool_name}")
        self.log(f"   Arguments: {args}")
    
    def log_exploit_search(self, query: str, results_count: int):
        """Log exploit search"""
        self.log(f"🔍 SEARCH: {query}")
        self.log(f"   Results: {results_count} exploits found")
    
    def log_exploit_execution(self, module: str, target: str):
        """Log exploit execution"""
        self.log(f"💥 EXECUTING: {module}")
        self.log(f"   Target: {target}")
    
    def log_session_check(self, session_count: int):
        """Log session check"""
        self.log(f"🎯 SESSION CHECK: {session_count} active sessions")
    
    def log_error(self, error: str):
        """Log error"""
        self.log(f"❌ ERROR: {error}")
    
    def close(self):
        """Close log file"""
        self.log(f"\n=== Log Ended at {datetime.now()} ===")
        self.log_file.close()


# Global logger instance
_logger = None


def get_logger():
    """Get or create logger instance"""
    global _logger
    if _logger is None:
        _logger = MetasploitLogger()
    return _logger


def log_activity(activity_type: str, details: dict):
    """
    Log Metasploit activity
    
    Args:
        activity_type: Type of activity (search, execute, check_sessions, etc.)
        details: Dictionary with activity details
    """
    logger = get_logger()
    
    if activity_type == "search":
        logger.log_exploit_search(
            details.get("query", "unknown"),
            details.get("results_count", 0)
        )
    elif activity_type == "execute":
        logger.log_exploit_execution(
            details.get("module", "unknown"),
            details.get("target", "unknown")
        )
    elif activity_type == "check_sessions":
        logger.log_session_check(details.get("session_count", 0))
    elif activity_type == "tool_call":
        logger.log_tool_call(
            details.get("tool_name", "unknown"),
            details.get("args", {})
        )
    elif activity_type == "rpc_call":
        logger.log_rpc_call(
            details.get("method", "unknown"),
            details.get("params", {})
        )
    elif activity_type == "error":
        logger.log_error(details.get("message", "unknown error"))
    else:
        logger.log(f"ACTIVITY: {activity_type} - {details}")


# Example usage in tools
if __name__ == "__main__":
    # Test the logger
    logger = get_logger()
    
    logger.log_rpc_call("modules.exploits", {"search": "wordpress"})
    logger.log_exploit_search("WordPress 5.3", 15)
    logger.log_exploit_execution("exploit/unix/webapp/wp_admin_shell_upload", "localhost:8080")
    logger.log_session_check(0)
    logger.log_error("Connection refused")
    
    logger.close()
    
    print(f"\n✓ Log file created: {LOG_FILE}")
