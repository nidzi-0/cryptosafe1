from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.core.audit.audit_export_policy import (
    AuditExportPolicy,
    AuditExportPolicyError,
)
from src.core.audit.audit_logger import AuditLogger
from src.core.audit.audit_rotation import AuditLogRotator, AuditRotationPolicy
from src.core.audit.audit_scheduler import (
    AuditVerificationSchedule,
    AuditVerificationScheduler,
)
from src.core.audit.log_formatters import AuditLogExporter
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import AuditLogVerifier


def make_audit_stack(tmp_path):
    db_path = tmp_path / "audit.db"
    signer = AuditLogSigner(b"K" * 32)
    logger = AuditLogger(db_path, signer)
    verifier = AuditLogVerifier(db_path, signer)

    return db_path, signer, logger, verifier


def test_audit_rotation_by_max_entries(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    for i in range(20):
        logger.log_event(
            event_type="ROTATION_TEST",
            severity="INFO",
            source="test",
            details={"i": i},
        )

    rotator = AuditLogRotator(
        db_path=db_path,
        policy=AuditRotationPolicy(
            max_entries=10,
            max_age_days=365,
            archive_enabled=True,
        ),
        audit_logger=logger,
    )

    result = rotator.rotate_if_needed()

    assert result["archived_by_count"] > 0
    assert result["total_archived"] > 0

    # После ротации активный лог может содержать max_entries + событие AUDIT_LOG_ROTATED.
    assert logger.count_logs() <= 11


def test_audit_scheduler_runs_recent_verification(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    for i in range(5):
        logger.log_event(
            event_type="SCHEDULER_TEST",
            severity="INFO",
            source="test",
            details={"i": i},
        )

    captured = []

    scheduler = AuditVerificationScheduler(
        verifier=verifier,
        schedule=AuditVerificationSchedule(
            interval_seconds=60,
            recent_limit=1000,
        ),
        on_result=captured.append,
    )

    result = scheduler.run_once()

    assert result.verified is True
    assert captured
    assert captured[0].verified is True


def test_audit_export_requires_confirmation(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    logger.log_event(
        event_type="EXPORT_POLICY_TEST",
        severity="INFO",
        source="test",
        details={"message": "export"},
    )

    deny_policy = AuditExportPolicy(confirm_callback=lambda: False)

    exporter = AuditLogExporter(
        audit_logger=logger,
        signer=signer,
        export_policy=deny_policy,
    )

    with pytest.raises(AuditExportPolicyError):
        exporter.export_signed_json(tmp_path / "denied.json")

    allow_policy = AuditExportPolicy(confirm_callback=lambda: True)

    exporter = AuditLogExporter(
        audit_logger=logger,
        signer=signer,
        export_policy=allow_policy,
    )

    path = exporter.export_signed_json(tmp_path / "allowed.json")

    assert path.exists()

    rows = logger.query_logs(event_type="AUDIT_LOG_EXPORTED", limit=10)

    assert rows


def test_audit_export_policy_without_confirmation_blocks_export():
    policy = AuditExportPolicy()

    with pytest.raises(AuditExportPolicyError):
        policy.validate_export_allowed()


def test_audit_rotation_by_age(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    logger.log_event(
        event_type="OLD_EVENT",
        severity="INFO",
        source="test",
        details={"message": "old"},
    )

    old_timestamp = (
        datetime.now(timezone.utc) - timedelta(days=400)
    ).isoformat(timespec="seconds")

    import sqlite3

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE audit_log
            SET timestamp = ?
            WHERE event_type = 'OLD_EVENT'
            """,
            (old_timestamp,),
        )
        conn.commit()

    rotator = AuditLogRotator(
        db_path=db_path,
        policy=AuditRotationPolicy(
            max_entries=10_000,
            max_age_days=365,
            archive_enabled=True,
        ),
    )

    result = rotator.rotate_if_needed()

    assert result["archived_by_age"] >= 1