import statistics
import time

from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.memory_guard import MemoryDumpScanner, SecretHolder, SecureHeapAllocator
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.side_channel_protection import ConstantTime


def test_test1_timing_attack_statistical_comparison():
    equal_times = []
    different_times = []

    for _ in range(500):
        start = time.perf_counter_ns()
        ConstantTime.bytes_equal(b"a" * 32, b"a" * 32)
        equal_times.append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        ConstantTime.bytes_equal(b"a" * 32, b"b" * 32)
        different_times.append(time.perf_counter_ns() - start)

    equal_median = statistics.median(equal_times)
    different_median = statistics.median(different_times)

    ratio = max(equal_median, different_median) / max(1, min(equal_median, different_median))

    assert ratio < 3.0


def test_test2_memory_protection_controlled_dump_no_plaintext_after_close():

    secret = b"super-sensitive-master-key"
    holder = SecretHolder(secret)

    assert holder.get_bytes() == secret

    holder.close()

    controlled_dump = [
        b"public-data",
        b"some-random-buffer",
        b"\x00" * 64,
    ]

    assert MemoryDumpScanner.contains_plaintext(controlled_dump, secret) is False


def test_test2_secure_heap_does_not_return_plaintext_after_free():
    allocator = SecureHeapAllocator()
    block = allocator.allocate_with_data(b"vault-secret-password")

    assert block.read() == b"vault-secret-password"

    allocator.free(block)

    controlled_dump = [
        b"metadata",
        b"vault",
        b"password",
        b"\x00" * 128,
    ]

    assert MemoryDumpScanner.contains_plaintext(controlled_dump, b"vault-secret-password") is False


def test_test3_auto_lock_24_hours_simulation():
    lock_events = []

    monitor = ActivityMonitor(
        lock_callback=lambda: lock_events.append("locked"),
        config=AutoLockConfig(timeout_seconds=300),
    )

    simulated_start = time.monotonic()

    for step in range(24 * 12):
        monitor.last_activity = simulated_start + step * 300
        monitor.record_activity("simulation")
        assert monitor.should_lock() is False

    monitor.last_activity = time.monotonic() - 301

    assert monitor.should_lock() is True

    monitor.force_lock()

    assert lock_events == ["locked"]
    assert monitor.locked is True


def test_test4_panic_mode_stress_during_multiple_operations():
    operations = [
        "export",
        "import",
        "clipboard_copy",
        "audit_view",
        "search",
        "entry_edit",
    ]

    results = []

    for operation in operations:
        calls = []

        panic = PanicMode(
            config=PanicModeConfig(
                enabled_actions=[
                    PanicAction.LOCK_VAULT,
                    PanicAction.CLEAR_CLIPBOARD,
                    PanicAction.WIPE_MEMORY,
                    PanicAction.CLOSE_WINDOWS,
                ]
            ),
            lock_vault=lambda: calls.append(f"{operation}:lock"),
            clear_clipboard=lambda: calls.append(f"{operation}:clipboard"),
            wipe_memory=lambda: calls.append(f"{operation}:memory"),
            close_windows=lambda: calls.append(f"{operation}:windows"),
        )

        event = panic.activate(trigger=f"during_{operation}")

        assert event.success is True
        assert len(calls) == 4
        assert f"{operation}:lock" in calls
        assert f"{operation}:clipboard" in calls
        assert f"{operation}:memory" in calls
        assert f"{operation}:windows" in calls

        results.append(event)

    assert len(results) == len(operations)
    assert all(event.success for event in results)


def test_test4_panic_mode_clean_recovery_after_stress():
    panic = PanicMode()

    event = panic.activate(trigger="stress_test")

    assert event.success is True
    assert panic.recover(master_password_verified=False) is False
    assert panic.recover(master_password_verified=True) is True