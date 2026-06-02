from __future__ import annotations

import time
import tracemalloc

from src.core.audit.audit_logger import AuditLogger, AuditLoggerAsync
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import AuditLogVerifier


def make_audit_stack(tmp_path):
    db_path = tmp_path / "audit_perf.db"
    signer = AuditLogSigner(b"K" * 32)
    logger = AuditLogger(db_path=db_path, signer=signer)
    verifier = AuditLogVerifier(db_path=db_path, signer=signer)

    return db_path, signer, logger, verifier


def test_perf_1_single_logging_operation_under_10ms(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    measurements = []

    for i in range(50):
        start = time.perf_counter()

        logger.log_event(
            event_type="PERF_SINGLE_LOG",
            severity="INFO",
            source="performance_test",
            details={"i": i},
        )

        elapsed_ms = (time.perf_counter() - start) * 1000
        measurements.append(elapsed_ms)

    average_ms = sum(measurements) / len(measurements)
    assert average_ms < 10.0


def test_perf_2_verify_1000_entries_under_1_second(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    for i in range(1000):
        logger.log_event(
            event_type="PERF_VERIFY_1000",
            severity="INFO",
            source="performance_test",
            details={"i": i},
        )

    start = time.perf_counter()

    result = verifier.verify_recent(limit=1000)

    elapsed = time.perf_counter() - start

    assert result.verified is True
    assert result.total_entries == 1000
    assert elapsed < 1.0


def test_perf_3_query_filter_10000_entries_under_500ms(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    for i in range(10_000):
        event_type = "PERF_QUERY_TARGET" if i % 2 == 0 else "PERF_QUERY_OTHER"

        logger.log_event(
            event_type=event_type,
            severity="INFO",
            source="performance_test",
            details={"i": i, "message": f"event-{i}"},
        )

    start = time.perf_counter()

    rows = logger.query_logs(
        event_type="PERF_QUERY_TARGET",
        limit=10_000,
        offset=0,
    )

    elapsed = time.perf_counter() - start

    assert rows
    assert elapsed < 0.5


def test_perf_4_log_viewer_like_memory_under_50mb_for_10000_entries(tmp_path):
    db_path, signer, logger, verifier = make_audit_stack(tmp_path)

    for i in range(10_000):
        logger.log_event(
            event_type="PERF_MEMORY_VIEWER",
            severity="INFO",
            source="performance_test",
            details={"i": i, "message": f"memory-event-{i}"},
        )

    tracemalloc.start()

    page = logger.query_logs(
        event_type="PERF_MEMORY_VIEWER",
        limit=50,
        offset=0,
    )

    total_count = logger.count_logs()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024

    assert len(page) == 50
    assert total_count >= 10_000
    assert peak_mb < 50.0


def test_perf_5_async_logging_for_non_critical_events(tmp_path):
    db_path = tmp_path / "audit_async_perf.db"
    signer = AuditLogSigner(b"K" * 32)

    logger = AuditLoggerAsync(
        db_path=db_path,
        signer=signer,
    )

    start = time.perf_counter()

    for i in range(1000):
        logger.log_event_async(
            event_type="PERF_ASYNC_LOG",
            severity="INFO",
            source="performance_test",
            details={"i": i},
        )

    enqueue_elapsed = time.perf_counter() - start


    assert enqueue_elapsed < 0.2

    logger.flush_async()

    assert logger.count_logs() >= 1001

    logger.close_async()