from __future__ import annotations

import sqlite3

from src.core.clipboard.clipboard_service import (
    ClipboardSecurityLevel,
    ClipboardSettings,
)
from src.core.clipboard.clipboard_settings_store import ClipboardSettingsStore
from src.core.crypto.key_manager import CachedKeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService


def make_encryption_service() -> AESGCMEncryptionService:
    key_manager = CachedKeyManager(b"K" * 32)
    return AESGCMEncryptionService(key_manager)


def test_clipboard_settings_are_stored_encrypted(tmp_path):
    db_path = tmp_path / "settings.db"
    encryption_service = make_encryption_service()

    store = ClipboardSettingsStore(
        db_path=db_path,
        encryption_service=encryption_service,
    )

    settings = ClipboardSettings(
        auto_clear_seconds=15,
        notifications_enabled=False,
        warning_before_clear_seconds=5,
        security_level=ClipboardSecurityLevel.ADVANCED,
        block_on_suspicious_activity=True,
        allowed_applications=["CryptoSafe Manager"],
    )

    store.save(settings)

    assert store.is_encrypted_storage_enabled() is True

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            """
            SELECT value, encrypted_value, is_encrypted
            FROM settings
            WHERE key = 'clipboard_settings'
            """
        ).fetchone()

    assert row is not None
    assert row["value"] is None
    assert row["encrypted_value"] is not None
    assert row["is_encrypted"] == 1

    raw_blob = bytes(row["encrypted_value"])

    assert b"auto_clear_seconds" not in raw_blob
    assert b"CryptoSafe Manager" not in raw_blob
    assert b"advanced" not in raw_blob

    loaded = store.load()

    assert loaded.auto_clear_seconds == 15
    assert loaded.notifications_enabled is False
    assert loaded.security_level == ClipboardSecurityLevel.ADVANCED
    assert loaded.block_on_suspicious_activity is True
    assert loaded.allowed_applications == ["CryptoSafe Manager"]


def test_clipboard_settings_json_fallback_without_encryption_service(tmp_path):
    db_path = tmp_path / "settings.db"

    store = ClipboardSettingsStore(db_path=db_path)

    settings = ClipboardSettings(
        auto_clear_seconds=30,
        notifications_enabled=True,
        security_level=ClipboardSecurityLevel.BASIC,
        allowed_applications=[],
    )

    store.save(settings)

    assert store.is_encrypted_storage_enabled() is False

    loaded = store.load()

    assert loaded.auto_clear_seconds == 30
    assert loaded.notifications_enabled is True
    assert loaded.security_level == ClipboardSecurityLevel.BASIC