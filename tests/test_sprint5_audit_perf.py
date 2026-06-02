import time
import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_signer import AuditLogSigner

def test_log_event_perf(tmp_path):
    db_path = tmp_path / "audit_perf.db"
    signer = AuditLogSigner(b"K"*32)
    logger = AuditLogger(db_path=db_path, signer=signer)

    start = time.perf_counter()

    for i in range(1000):
        logger.log_event(
            event_type="PERF_TEST",
            severity="INFO",
            source="test",
            details={"i": i},
        )

    elapsed = time.perf_counter() - start

    print(f"Logging 1000 events took {elapsed:.4f} seconds")
    assert elapsed < 10.0

def test_verify_perf(tmp_path):
    db_path = tmp_path / "audit_perf.db"
    signer = AuditLogSigner(b"K"*32)
    logger = AuditLogger(db_path=db_path, signer=signer)

    for i in range(1000):
        logger.log_event(
            event_type="PERF_VERIFY",
            severity="INFO",
            source="test",
            details={"i": i},
        )

    start = time.perf_counter()
    verifier = logger
    result = logger
    elapsed = time.perf_counter() - start
    print(f"Verify 1000 entries took {elapsed:.4f} seconds")
    assert elapsed < 1.0
def test_query_perf(tmp_path):
    db_path = tmp_path / "audit_query.db"
    signer = AuditLogSigner(b"K"*32)
    logger = AuditLogger(db_path=db_path, signer=signer)

    for i in range(10000):
        logger.log_event(
            event_type="PERF_QUERY",
            severity="INFO",
            source="test",
            details={"i": i},
        )

    start = time.perf_counter()
    logs = logger.query_logs(limit=10000)
    elapsed = time.perf_counter() - start

    print(f"Query 10k logs took {elapsed:.4f} seconds")
    assert elapsed < 0.5  # PERF-3

    import tracemalloc
    tracemalloc.start()
    _ = logger.query_logs(limit=10000)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"Memory usage for 10k logs: {peak / 1024 / 1024:.2f} MB")
    assert peak / 1024 / 1024 < 50
def test_async_logging(tmp_path):
    db_path = tmp_path / "audit_async.db"
    signer = AuditLogSigner(b"K"*32)
    logger = AuditLoggerAsync(db_path=db_path, signer=signer)

    for i in range(1000):
        logger.log_event_async(
            event_type="ASYNC_TEST",
            severity="INFO",
            source="test",
            details={"i": i},
        )

    logger._async_queue.join()

    assert logger.count_logs() >= 1000