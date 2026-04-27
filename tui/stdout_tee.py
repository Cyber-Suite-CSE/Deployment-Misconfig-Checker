"""Line-buffered ``sys.stdout`` tee.

Wrapping ``sys.stdout`` for the duration of an orchestrator request lets us
observe every ``print()`` issued by tools/agents without changing their code.
Each completed line is forwarded to ``on_line`` and also written through to the
original stream so the underlying terminal still sees output (useful when
debugging the TUI itself with ``textual run --dev``).
"""

from __future__ import annotations

import threading
from typing import Callable, TextIO


class TeeStdout:
    def __init__(self, original: TextIO, on_line: Callable[[str], None]) -> None:
        self._original = original
        self._on_line = on_line
        self._buf = ""
        self._lock = threading.Lock()

    def write(self, s: str) -> int:
        if not s:
            return 0
        with self._lock:
            self._buf += s
            lines = self._buf.split("\n")
            self._buf = lines.pop()  # last chunk has no trailing newline yet
            for line in lines:
                try:
                    self._on_line(line)
                except Exception:
                    pass
        try:
            return self._original.write(s)
        except Exception:
            return len(s)

    def flush(self) -> None:
        try:
            self._original.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        return self._original.fileno()
