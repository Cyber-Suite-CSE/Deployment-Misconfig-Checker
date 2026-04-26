"""Subprocess helper with process-group cleanup, live streaming, and a registry for SIGINT.

Each tool runs its scanner via `run_with_timeout`, which:
- Puts the child in its own process group (POSIX `start_new_session=True`,
  Windows `CREATE_NEW_PROCESS_GROUP`) so we can kill the *whole* tree on
  timeout — not just the shell.
- Tees stdout/stderr to the terminal in real time via reader threads, so
  long-running scans don't look hung. Output is also captured for the LLM.
- Uses `proc.wait(timeout=N)` to enforce a hard deadline. Reader threads
  drain pipes continuously so the child never blocks on a full buffer.
- Tracks the live `Popen` in a thread-safe registry so a SIGINT handler can
  sweep all active processes (see `terminate_all`).
- On timeout sends SIGTERM, gives the group 5 s to drain, then SIGKILL.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from typing import IO, List, Tuple

_IS_WIN = sys.platform == "win32"

_LOCK = threading.Lock()
_ACTIVE: "set[subprocess.Popen]" = set()


def _register(proc: subprocess.Popen) -> None:
    with _LOCK:
        _ACTIVE.add(proc)


def _unregister(proc: subprocess.Popen) -> None:
    with _LOCK:
        _ACTIVE.discard(proc)


def _kill_group(proc: subprocess.Popen, sig: int) -> None:
    if proc.poll() is not None:
        return
    if _IS_WIN:
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError):
        pass


def terminate_all(grace: float = 3.0) -> None:
    """SIGTERM every active subprocess, then SIGKILL stragglers after `grace` seconds."""
    with _LOCK:
        procs = list(_ACTIVE)
    for proc in procs:
        _kill_group(proc, signal.SIGTERM)
    deadline = time.monotonic() + grace
    for proc in procs:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _kill_group(proc, signal.SIGKILL if not _IS_WIN else signal.SIGTERM)


def active_count() -> int:
    with _LOCK:
        return len(_ACTIVE)


def _drain(pipe: "IO[str]", buf: List[str], tee_to: "IO[str] | None") -> None:
    """Continuously read `pipe` line-by-line into `buf`; if `tee_to`, also write there.

    Runs as a daemon thread so the child never blocks on a full pipe buffer
    even when output is huge or terminal I/O is slow.
    """
    try:
        for line in iter(pipe.readline, ""):
            if not line:
                break
            buf.append(line)
            if tee_to is not None:
                try:
                    tee_to.write(line)
                    tee_to.flush()
                except Exception:
                    # Don't let a broken stdout kill the reader; we still need to drain.
                    pass
    except Exception:
        pass
    finally:
        try:
            pipe.close()
        except Exception:
            pass


def run_with_timeout(
    command: str,
    timeout: float,
    *,
    shell: bool = True,
    text: bool = True,
    stream: bool = True,
) -> Tuple[str, str, int, bool]:
    """Run `command` with a hard wall-clock timeout, killing the whole process group on expiry.

    When `stream=True` (the default), stdout/stderr are teed to the terminal
    in real time so long-running scans show progress. Captured output is
    returned regardless.

    Returns:
        (stdout, stderr, returncode, timed_out)
    """
    popen_kwargs = {
        "shell": shell,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": text,
        "bufsize": 1,  # line-buffered so streaming feels live
    }
    if _IS_WIN:
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(command, **popen_kwargs)
    _register(proc)

    stdout_buf: List[str] = []
    stderr_buf: List[str] = []
    out_sink = sys.stdout if stream else None
    err_sink = sys.stderr if stream else None

    t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_buf, out_sink), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_buf, err_sink), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _kill_group(proc, signal.SIGKILL if not _IS_WIN else signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        # Reader threads should reach EOF naturally once the process exits.
        t_out.join(timeout=3)
        t_err.join(timeout=3)
        rc = proc.returncode if proc.returncode is not None else -1
        return "".join(stdout_buf), "".join(stderr_buf), rc, timed_out
    finally:
        _unregister(proc)
