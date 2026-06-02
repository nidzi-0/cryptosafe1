from __future__ import annotations

import sqlite3

from src.core.audit.audit_logger import AuditLogger, AuditSeverity
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import AuditLogVerifier
from src.core.audit.log_formatters import AuditLogExporter


def make_logger(tmp_path):
    db_path = tmp_path / "audit.db"
    master_key = b"K" * 32
    signer = AuditLogSigner(master_key)
    logger = AuditLogger(db_path=db_path, signer=signer)
    verifier = AuditLogVerifier(db_path=db_path, signer=signer)

    return db_path, signer, logger, verifier


def test_audit_logger_creates_signed_hash_chain(tmp_path):
    db_path, signer, logger, verifier = make_logger(tmp_path)

    logger.log_event(
        event_type="AUTH_LOGIN_SUCCESS",
        severity=AuditSeverity.INFO.value,
        source="auth",
        details={"user": "local_user"},
    )

    logger.log_event(
        event_type="VAULT_ENTRY_CREATED",
        severity=AuditSeverity.INFO.value,
        source="vault",
        details={"entry_id": 1, "title": "GitHub"},
        entry_id=1,
    )

    result = verifier.verify_integrity()

    assert result.verified is True
    assert result.total_entries == 3  # genesis + 2 события
    assert result.valid_entries == 3


def test_audit_logger_redacts_sensitive_data(tmp_path):
    db_path, signer, logger, verifier = make_logger(tmp_path)

    logger.log_event(
        event_type="CLIPBOARD_COPY",
        severity=AuditSeverity.INFO.value,
        source="clipboard",
        details={
            "password": "SecretPassword123!",
            "token": "abc",
            "normal": "ok",
        },
    )

    rows = logger.query_logs(search="CLIPBOARD_COPY")

    assert rows

    details = rows[0]["entry_data"]["details"]

    assert details["password"] == "[REDACTED]"
    assert details["token"] == "[REDACTED]"
    assert details["normal"] == "ok"


def test_audit_tampering_is_detected(tmp_path):
    db_path, signer, logger, verifier = make_logger(tmp_path)

    logger.log_event(
        event_type="SECURITY_TEST",
        severity=AuditSeverity.WARN.value,
        source="test",
        details={"message": "before tamper"},
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE audit_log
            SET entry_data = ?
            WHERE event_type = 'SECURITY_TEST'
            """,
            (b'{"tampered":true}',),
        )
        conn.commit()

    result = verifier.verify_integrity()

    assert result.verified is False
    assert result.invalid_entries


def test_audit_export_json_csv_pdf(tmp_path):
    db_path, signer, logger, verifier = make_logger(tmp_path)

    logger.log_event(
        event_type="EXPORT_TEST",
        severity=AuditSeverity.INFO.value,
        source="test",
        details={"message": "export me"},
    )

    exporter = AuditLogExporter(logger, signer)

    json_path = exporter.export_signed_json(tmp_path / "audit.json")
    csv_path = exporter.export_csv(tmp_path / "audit.csv")
    pdf_path = exporter.export_pdf(tmp_path / "audit.pdf")

    assert json_path.exists()
    assert csv_path.exists()
    assert pdf_path.exists()
    assert json_path.read_text(encoding="utf-8")
    assert csv_path.read_text(encoding="utf-8-sig")