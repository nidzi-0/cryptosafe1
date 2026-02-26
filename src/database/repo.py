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
    def __init__(self, db: Database, crypto: EncryptionService, key: bytes) -> None:
        self.db = db
        self.crypto = crypto
        self.key = key

    @staticmethod
    def _validate(data: VaultEntryInput) -> None:
        if not isinstance(data.title, str) or not data.title.strip():
            raise ValueError("Title is required")
        if len(data.title) > 200:
            raise ValueError("Title too long")
        if not isinstance(data.password, str) or len(data.password) < 1:
            raise ValueError("Password is required")
        if data.url is not None and len(data.url) > 500:
            raise ValueError("URL too long")

    def add_entry(self, data: VaultEntryInput) -> int:
        self._validate(data)

        conn = self.db.connect()
        now = utc_now_iso()

        username_enc = None
        if data.username:
            username_enc = self.crypto.encrypt(data.username.encode("utf-8"), self.key)

        password_enc = self.crypto.encrypt(data.password.encode("utf-8"), self.key)

        notes_enc = None
        if data.notes:
            notes_enc = self.crypto.encrypt(data.notes.encode("utf-8"), self.key)

        cur = conn.execute(
            """
            INSERT INTO vault_entries(title, username, encrypted_password, url, notes, created_at, updated_at, tags)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (data.title.strip(), username_enc, password_enc, data.url, notes_enc, now, now, data.tags),
        )
        conn.commit()
        return int(cur.lastrowid)