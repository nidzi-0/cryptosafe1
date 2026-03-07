from __future__ import annotations

from src.core.crypto.abstract import EncryptionService
from .db import Database


class SettingsRepository:
    def __init__(self, db: Database, crypto: EncryptionService, key: bytes) -> None:
        self.db = db
        self.crypto = crypto
        self.key = key

    def set_setting(self, setting_key: str, setting_value: str, encrypted: bool = False) -> None:
        conn = self.db.connect()

        value_to_store: bytes
        if encrypted:
            value_to_store = self.crypto.encrypt(setting_value.encode("utf-8"), self.key)
        else:
            value_to_store = setting_value.encode("utf-8")

        conn.execute(
            """
            INSERT INTO settings(setting_key, setting_value, encrypted)
            VALUES(?, ?, ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value=excluded.setting_value,
                encrypted=excluded.encrypted
            """,
            (setting_key, value_to_store, int(encrypted)),
        )
        conn.commit()

    def get_setting(self, setting_key: str) -> str | None:
        conn = self.db.connect()
        row = conn.execute(
            "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?",
            (setting_key,),
        ).fetchone()

        if row is None:
            return None

        raw_value = row["setting_value"]
        encrypted = bool(row["encrypted"])

        if raw_value is None:
            return None

        if encrypted:
            return self.crypto.decrypt(raw_value, self.key).decode("utf-8")

        return raw_value.decode("utf-8")