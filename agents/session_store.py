"""Sidecar metadata for supervisor sessions.

The LangGraph SqliteSaver checkpointer stores graph state keyed by ``thread_id``,
but it has no notion of "first user message" or "last used at". To power
``/resume`` we maintain a small JSON file alongside the checkpoint DB that
remembers, per thread, when it was created, when it was last touched, the
opening user message, and the turn count.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from typing import Dict, List, Optional

from agents.hitl_helpers import SESSION_STORE_PATH


_FIRST_MESSAGE_LIMIT = 200


class SessionStore:
    """JSON-backed metadata index of supervisor session threads."""

    def __init__(self, path: str = SESSION_STORE_PATH):
        self._path = path

    # ------------------------------------------------------------------
    # Read/write
    # ------------------------------------------------------------------
    def _load(self) -> Dict[str, Dict]:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        sessions = data.get("sessions") if isinstance(data, dict) else None
        if not isinstance(sessions, list):
            return {}
        return {
            entry["thread_id"]: entry
            for entry in sessions
            if isinstance(entry, dict) and isinstance(entry.get("thread_id"), str)
        }

    def _save(self, by_id: Dict[str, Dict]) -> None:
        directory = os.path.dirname(self._path) or "."
        os.makedirs(directory, exist_ok=True)
        payload = {"sessions": list(by_id.values())}
        fd, tmp_path = tempfile.mkstemp(prefix=".sessions-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self._path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    def record_turn(self, thread_id: str, user_message: str) -> None:
        """Upsert a session entry. Failures are swallowed — never break the REPL."""
        try:
            by_id = self._load()
            now = datetime.utcnow().isoformat() + "Z"
            entry = by_id.get(thread_id)
            if entry is None:
                entry = {
                    "thread_id": thread_id,
                    "created_at": now,
                    "updated_at": now,
                    "first_message": (user_message or "").strip()[:_FIRST_MESSAGE_LIMIT],
                    "turn_count": 1,
                }
                by_id[thread_id] = entry
            else:
                entry["updated_at"] = now
                entry["turn_count"] = int(entry.get("turn_count", 0)) + 1
                if not entry.get("first_message"):
                    entry["first_message"] = (user_message or "").strip()[:_FIRST_MESSAGE_LIMIT]
            self._save(by_id)
        except OSError:
            return

    def list_recent(self, limit: int = 20) -> List[Dict]:
        by_id = self._load()
        items = list(by_id.values())
        items.sort(key=lambda e: e.get("updated_at", ""), reverse=True)
        return items[: max(0, limit)]

    def exists(self, thread_id: str) -> bool:
        return thread_id in self._load()

    def find_by_prefix(self, prefix: str) -> Optional[str]:
        if not prefix:
            return None
        matches = [tid for tid in self._load() if tid.startswith(prefix)]
        if len(matches) == 1:
            return matches[0]
        return None
