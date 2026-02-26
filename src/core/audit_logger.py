from __future__ import annotations

from datetime import datetime, timezone

from src.core.events import (
    EntryAdded, EntryUpdated, EntryDeleted,
    UserLoggedIn, UserLoggedOut,
    ClipboardCopied, ClipboardCleared
)
from src.database.db import Database


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    def __init__(self, db: Database) -> None:
        self.db = db

    def on_entry_added(self, e: EntryAdded) -> None:
        self._write("EntryAdded", e.entry_id, f"title={e.title}")

    def on_entry_updated(self, e: EntryUpdated) -> None:
        self._write("EntryUpdated", e.entry_id, "")

    def on_entry_deleted(self, e: EntryDeleted) -> None:
        self._write("EntryDeleted", e.entry_id, "")

    def on_login(self, e: UserLoggedIn) -> None:
        self._write("UserLoggedIn", None, f"user={e.user}")

    def on_logout(self, e: UserLoggedOut) -> None:
        self._write("UserLoggedOut", None, f"user={e.user}")

    def on_clipboard_copied(self, e: ClipboardCopied) -> None:
        self._write("ClipboardCopied", e.entry_id, "")

    def on_clipboard_cleared(self, e: ClipboardCleared) -> None:
        self._write("ClipboardCleared", None, "")

    def _write(self, action: str, entry_id: int | None, details: str) -> None:
        conn = self.db.connect()
        conn.execute(
            "INSERT INTO audit_log(action, timestamp, entry_id, details, signature) VALUES(?, ?, ?, ?, ?)",
            (action, utc_now_iso(), entry_id, details, None),
        )
        conn.commit()