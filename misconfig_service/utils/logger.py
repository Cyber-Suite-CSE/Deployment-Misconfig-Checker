from enum import Enum

class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

class Logger:
    def __init__(self, level: LogLevel = LogLevel.DEBUG):
        self.level = level
        self._level_order = {
            LogLevel.DEBUG: 0,
            LogLevel.INFO: 1,
            LogLevel.WARNING: 2,
            LogLevel.ERROR: 3
        }
    
    def set_level(self, level: LogLevel):
        self.level = level
    
    def _should_log(self, level: LogLevel) -> bool:
        return self._level_order[level] >= self._level_order[self.level]
    
    def debug(self, message: str):
        if self._should_log(LogLevel.DEBUG):
            print(f"DEBUG: {message}")
    
    def info(self, message: str):
        if self._should_log(LogLevel.INFO):
            print(f"INFO: {message}")
    
    def warning(self, message: str):
        if self._should_log(LogLevel.WARNING):
            print(f"WARNING: {message}")
    
    def error(self, message: str):
        if self._should_log(LogLevel.ERROR):
            print(f"ERROR: {message}")
