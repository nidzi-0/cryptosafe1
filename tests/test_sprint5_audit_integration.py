from __future__ import annotations

from dataclasses import dataclass

from src.core.audit.audit_event_bridge import AuditEventBridge
from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import AuditLogVerifier


@dataclass(frozen=True)
class ClipboardCopied:
    data_type: str
    source_entry_id: int
    timeout_seconds: int
    copied_at: str


@dataclass(frozen=True)
class EntryCreated:
    entry: dict
    created_at: str


def test_audit_event_bridge_logs_clipboard_event(tmp_path):
    db_path = tmp_path / "audit.db"
    signer = AuditLogSigner(b"K" * 32)
    logger = AuditLogger(db_path, signer)
    verifier = AuditLogVerifier(db_path, signer)
    bridge = AuditEventBridge(logger)

    bridge.handle_event(
        ClipboardCopied(
            data_type="password",
            source_entry_id=12,
            timeout_seconds=30,
            copied_at="2026-01-01T00:00:00+00:00",
        )
    )

    rows = logger.query_logs(event_type="CLIPBOARD_COPIED", limit=10)

    assert rows
    assert rows[0]["entry_id"] == "12"
    assert rows[0]["source"] == "clipboard"

    result = verifier.verify_integrity()

    assert result.verified is True


def test_audit_event_bridge_logs_vault_event_and_redacts_password(tmp_path):
    db_path = tmp_path / "audit.db"
    signer = AuditLogSigner(b"K" * 32)
    logger = AuditLogger(db_path, signer)
    verifier = AuditLogVerifier(db_path, signer)
    bridge = AuditEventBridge(logger)

    bridge.handle_event(
        EntryCreated(
            entry={
                "id": 7,
                "title": "GitHub",
                "username": "user",
                "password": "SecretPassword",
            },
            created_at="2026-01-01T00:00:00+00:00",
        )
    )

    rows = logger.query_logs(event_type="VAULT_ENTRY_CREATED", limit=10)

    assert rows
    assert rows[0]["entry_id"] == "7"

    entry_details = rows[0]["entry_data"]["details"]["entry"]

    assert entry_details["password"] == "[REDACTED]"

    result = verifier.verify_integrity()

    assert result.verified is True