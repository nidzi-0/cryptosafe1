from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from src.core.crypto.abstract import EncryptionService
from .db import Database


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class VaultEntryInput:
    title: str
    username: str | None
    password: str
    url: str | None
    notes: str | None
    tags: str | None


class VaultRepository:
    def __init__(self, db: Database, crypto: EncryptionService) -> None:
        self.db = db
        self.crypto = crypto

    @staticmethod
    def _validate(data: VaultEntryInput) -> None:
        if not isinstance(data.title, str) or not data.title.strip():
            raise ValueError("Требуется заголовок")
        if len(data.title) > 200:
            raise ValueError("Слишком длинный заголовок")
        if not isinstance(data.password, str) or len(data.password) < 1:
            raise ValueError("Требуется пароль")
        if data.url is not None and len(data.url) > 500:
            raise ValueError("Слишком длинный URL")

    def add_entry(self, data: VaultEntryInput) -> int:
        self._validate(data)

        conn = self.db.connect()
        now = utc_now_iso()

        username_enc = None
        if data.username:
            username_enc = self.crypto.encrypt(data.username.encode("utf-8"))

        password_enc = self.crypto.encrypt(data.password.encode("utf-8"))

        notes_enc = None
        if data.notes:
            notes_enc = self.crypto.encrypt(data.notes.encode("utf-8"))

        cur = conn.execute(
            """
            INSERT INTO vault_entries(title, username, encrypted_password, url, notes, created_at, updated_at, tags)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (data.title.strip(), username_enc, password_enc, data.url, notes_enc, now, now, data.tags),
        )
        conn.commit()
        return int(cur.lastrowid)

    def reencrypt_all_entries(self, old_crypto: EncryptionService, new_crypto: EncryptionService) -> int:
        conn = self.db.connect()
        rows = conn.execute(
            """
            SELECT id, username, encrypted_password, notes
            FROM vault_entries
            """
        ).fetchall()

        updated_count = 0
        now = utc_now_iso()

        for row in rows:
            username_plain = None
            if row["username"] is not None:
                username_plain = old_crypto.decrypt(row["username"])

            password_plain = old_crypto.decrypt(row["encrypted_password"])

            notes_plain = None
            if row["notes"] is not None:
                notes_plain = old_crypto.decrypt(row["notes"])

            username_new = None
            if username_plain is not None:
                username_new = new_crypto.encrypt(username_plain)

            password_new = new_crypto.encrypt(password_plain)

            notes_new = None
            if notes_plain is not None:
                notes_new = new_crypto.encrypt(notes_plain)

            conn.execute(
                """
                UPDATE vault_entries
                SET username = ?, encrypted_password = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (username_new, password_new, notes_new, now, row["id"]),
            )

            updated_count += 1

        return updated_count