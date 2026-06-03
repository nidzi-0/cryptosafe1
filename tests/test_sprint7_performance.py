import time

from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.memory_guard import SecretHolder
from src.core.security.panic_mode import PanicMode, PanicModeConfig, PanicAction
from src.core.security.side_channel_protection import ConstantTime
from src.core.security.tray_service import TrayService, TrayState


def test_constant_time_compare_10000_operations_fast_enough():
    start = time.perf_counter()

    for _ in range(10_000):
        ConstantTime.bytes_equal(b"a" * 32, b"a" * 32)
        ConstantTime.bytes_equal(b"a" * 32, b"b" * 32)

    elapsed = time.perf_counter() - start

    assert elapsed < 0.5


def test_secret_holder_create_and_close_1000_times_fast_enough():
    start = time.perf_counter()

    for _ in range(1000):
        holder = SecretHolder(b"secret-value")
        assert holder.get_bytes() == b"secret-value"
        holder.close()

    elapsed = time.perf_counter() - start

    assert elapsed < 2.0


def test_activity_monitor_should_lock_check_has_low_overhead():
    monitor = ActivityMonitor(
        lock_callback=lambda: None,
        config=AutoLockConfig(timeout_seconds=60),
    )

    start = time.perf_counter()

    for _ in range(100_000):
        monitor.should_lock()

    elapsed = time.perf_counter() - start

    assert elapsed < 1.0


def test_panic_mode_activation_under_100ms():
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
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_windows=lambda: calls.append("windows"),
    )

    start = time.perf_counter()
    event = panic.activate("hotkey")
    elapsed = time.perf_counter() - start

    assert event.success is True
    assert elapsed < 0.1


def test_tray_menu_build_10000_times_fast_enough():
    tray = TrayService()
    tray.set_state(TrayState.UNLOCKED)
    tray.set_clipboard_active(True)

    start = time.perf_counter()

    for _ in range(10_000):
        menu = tray.build_menu()
        assert menu

    elapsed = time.perf_counter() - start

    assert elapsed < 1.0