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
        self._write("Добавление записи", e.entry_id, f"заголовок={e.title}")

    def on_entry_updated(self, e: EntryUpdated) -> None:
        self._write("Изменение записи", e.entry_id, "")

    def on_entry_deleted(self, e: EntryDeleted) -> None:
        self._write("Удаление записи", e.entry_id, "")

    def on_login(self, e: UserLoggedIn) -> None:
        self._write("Вход пользователя", None, f"пользователь={e.user}")

    def on_logout(self, e: UserLoggedOut) -> None:
        self._write("Выход пользователя", None, f"пользователь={e.user}")

    def on_clipboard_copied(self, e: ClipboardCopied) -> None:
        self._write("Копирование в буфер обмена", e.entry_id, "")

    def on_clipboard_cleared(self, e: ClipboardCleared) -> None:
        self._write("Очистка буфера обмена", None, "")

    def _write(self, action: str, entry_id: int | None, details: str) -> None:
        conn = self.db.connect()
        conn.execute(
            "INSERT INTO audit_log(action, timestamp, entry_id, details, signature) VALUES(?, ?, ?, ?, ?)",
            (action, utc_now_iso(), entry_id, details, None),
        )
        conn.commit()