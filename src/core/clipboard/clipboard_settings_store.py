from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.core.clipboard.clipboard_service import (
    ClipboardSecurityLevel,
    ClipboardSettings,
)


class ClipboardSettingsStoreError(Exception):
    """Ошибка хранилища clipboard-настроек."""


class ClipboardSettingsStore:
    SETTINGS_KEY = "clipboard_settings"

    PRESETS = {
        "standard": {
            "auto_clear_seconds": 30,
            "notifications_enabled": True,
            "warning_before_clear_seconds": 5,
            "security_level": ClipboardSecurityLevel.BASIC.value,
            "block_on_suspicious_activity": False,
            "allowed_applications": [],
        },
        "secure": {
            "auto_clear_seconds": 15,
            "notifications_enabled": True,
            "warning_before_clear_seconds": 5,
            "security_level": ClipboardSecurityLevel.ADVANCED.value,
            "block_on_suspicious_activity": False,
            "allowed_applications": [],
        },
        "public_computer": {
            "auto_clear_seconds": 5,
            "notifications_enabled": True,
            "warning_before_clear_seconds": 5,
            "security_level": ClipboardSecurityLevel.PARANOID.value,
            "block_on_suspicious_activity": True,
            "allowed_applications": [],
        },
    }

    def __init__(
        self,
        db_path: str | Path,
        encryption_service=None,
    ):
        self.db_path = Path(db_path)
        self.encryption_service = encryption_service

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_table_exists()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_table_exists(self) -> None:
        with self._connect() as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        encrypted_value BLOB,
                        is_encrypted INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                columns = self._get_columns(conn, "settings")

                if "encrypted_value" not in columns:
                    conn.execute(
                        """
                        ALTER TABLE settings
                        ADD COLUMN encrypted_value BLOB
                        """
                    )

                if "is_encrypted" not in columns:
                    conn.execute(
                        """
                        ALTER TABLE settings
                        ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0
                        """
                    )

                if "updated_at" not in columns:
                    conn.execute(
                        """
                        ALTER TABLE settings
                        ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                        """
                    )

    def _get_columns(self, conn: sqlite3.Connection, table_name: str) -> set[str]:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row["name"] for row in rows}

    def load(self) -> ClipboardSettings:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT value, encrypted_value, is_encrypted
                FROM settings
                WHERE key = ?
                """,
                (self.SETTINGS_KEY,),
            ).fetchone()

        if row is None:
            return ClipboardSettings()

        try:
            if row["is_encrypted"] and row["encrypted_value"] is not None:
                if self.encryption_service is None:
                    return ClipboardSettings()

                decrypted = self.encryption_service.decrypt(row["encrypted_value"])
                data = json.loads(decrypted)
                return self._settings_from_dict(data)

            if row["value"]:
                data = json.loads(row["value"])
                return self._settings_from_dict(data)

        except Exception:
            return ClipboardSettings()

        return ClipboardSettings()

    def save(self, settings: ClipboardSettings) -> None:
        settings.validate()

        data = self._settings_to_dict(settings)
        value_json = json.dumps(
            data,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        if self.encryption_service is not None:
            encrypted_value = self.encryption_service.encrypt(value_json)

            with self._connect() as conn:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO settings (
                            key,
                            value,
                            encrypted_value,
                            is_encrypted,
                            updated_at
                        )
                        VALUES (?, NULL, ?, 1, CURRENT_TIMESTAMP)
                        ON CONFLICT(key) DO UPDATE SET
                            value = NULL,
                            encrypted_value = excluded.encrypted_value,
                            is_encrypted = 1,
                            updated_at = CURRENT_TIMESTAMP
                        """,
                        (
                            self.SETTINGS_KEY,
                            encrypted_value,
                        ),
                    )

            return

        # Fallback для тестов без encryption_service.
        with self._connect() as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO settings (
                        key,
                        value,
                        encrypted_value,
                        is_encrypted,
                        updated_at
                    )
                    VALUES (?, ?, NULL, 0, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        encrypted_value = NULL,
                        is_encrypted = 0,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        self.SETTINGS_KEY,
                        value_json,
                    ),
                )

    def apply_preset(self, preset_name: str) -> ClipboardSettings:
        if preset_name not in self.PRESETS:
            raise ClipboardSettingsStoreError(
                "Неизвестный профиль настроек clipboard."
            )

        settings = self._settings_from_dict(self.PRESETS[preset_name])
        self.save(settings)

        return settings

    def is_encrypted_storage_enabled(self) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT is_encrypted
                FROM settings
                WHERE key = ?
                """,
                (self.SETTINGS_KEY,),
            ).fetchone()

        if row is None:
            return False

        return bool(row["is_encrypted"])

    def _settings_from_dict(self, data: dict[str, Any]) -> ClipboardSettings:
        security_level = data.get(
            "security_level",
            ClipboardSecurityLevel.BASIC.value,
        )

        try:
            security_level_value = ClipboardSecurityLevel(security_level)
        except ValueError:
            security_level_value = ClipboardSecurityLevel.BASIC

        auto_clear = data.get("auto_clear_seconds", 30)

        if auto_clear == "never":
            auto_clear = None

        settings = ClipboardSettings(
            auto_clear_seconds=auto_clear,
            notifications_enabled=bool(data.get("notifications_enabled", True)),
            warning_before_clear_seconds=int(
                data.get("warning_before_clear_seconds", 5)
            ),
            security_level=security_level_value,
            block_on_suspicious_activity=bool(
                data.get("block_on_suspicious_activity", False)
            ),
            allowed_applications=list(data.get("allowed_applications", [])),
        )

        settings.validate()

        return settings

    def _settings_to_dict(self, settings: ClipboardSettings) -> dict[str, Any]:
        allowed_applications = settings.allowed_applications or []

        return {
            "auto_clear_seconds": settings.auto_clear_seconds,
            "notifications_enabled": settings.notifications_enabled,
            "warning_before_clear_seconds": settings.warning_before_clear_seconds,
            "security_level": settings.security_level.value,
            "block_on_suspicious_activity": settings.block_on_suspicious_activity,
            "allowed_applications": allowed_applications,
        }