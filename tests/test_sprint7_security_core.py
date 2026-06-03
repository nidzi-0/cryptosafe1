import time

import pytest

from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.memory_guard import MemoryDumpScanner, SecretHolder
from src.core.security.panic_mode import PanicMode, PanicModeConfig, PanicAction
from src.core.security.security_profiles import SecurityProfileManager
from src.core.security.side_channel_protection import ConstantTime, SideChannelProtector


def test_constant_time_bytes_compare_success_and_failure():
    assert ConstantTime.bytes_equal(b"secret", b"secret") is True
    assert ConstantTime.bytes_equal(b"secret", b"public") is False


def test_constant_time_string_compare_success_and_failure():
    assert ConstantTime.string_equal("StrongPassA123!", "StrongPassA123!") is True
    assert ConstantTime.string_equal("StrongPassA123!", "WrongPassB123!") is False


def test_fixed_time_contains_does_not_return_early():
    values = ["alpha", "beta", "gamma", "delta"]

    assert ConstantTime.fixed_time_contains("alpha", values) is True
    assert ConstantTime.fixed_time_contains("delta", values) is True
    assert ConstantTime.fixed_time_contains("missing", values) is False


def test_side_channel_timing_measurement_returns_sample():
    protector = SideChannelProtector()

    sample = protector.measure_operation("compare", lambda: protector.secure_compare_text("a", "a"))

    assert sample.label == "compare"
    assert sample.elapsed_ns > 0


def test_secret_holder_returns_data_and_wipes_on_close():
    secret = b"very-secret-password"

    holder = SecretHolder(secret)
    assert holder.get_bytes() == secret

    info = holder.info
    assert info.size == len(secret)

    holder.close()

    with pytest.raises(Exception):
        holder.get_bytes()


def test_memory_dump_scanner_detects_plaintext_in_controlled_blocks():
    assert MemoryDumpScanner.contains_plaintext([b"abc", b"secret value"], b"secret") is True
    assert MemoryDumpScanner.contains_plaintext([b"abc", b"def"], b"secret") is False


def test_activity_monitor_locks_after_timeout():
    locked = {"value": False}

    def lock_callback():
        locked["value"] = True

    config = AutoLockConfig(timeout_seconds=60)
    monitor = ActivityMonitor(lock_callback=lock_callback, config=config)

    monitor.last_activity = time.monotonic() - 61

    assert monitor.should_lock() is True
    monitor.force_lock()

    assert locked["value"] is True
    assert monitor.locked is True


def test_activity_monitor_resume_after_unlock():
    called = {"count": 0}

    def lock_callback():
        called["count"] += 1

    monitor = ActivityMonitor(lock_callback=lock_callback, config=AutoLockConfig(timeout_seconds=60))
    monitor.force_lock()
    assert monitor.locked is True

    monitor.resume_after_unlock()
    assert monitor.locked is False


def test_activity_monitor_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        AutoLockConfig(timeout_seconds=10).validate()


def test_panic_mode_executes_required_actions():
    executed = []

    panic = PanicMode(
        config=PanicModeConfig(
            enabled_actions=[
                PanicAction.LOCK_VAULT,
                PanicAction.CLEAR_CLIPBOARD,
                PanicAction.WIPE_MEMORY,
                PanicAction.CLOSE_WINDOWS,
            ]
        ),
        lock_vault=lambda: executed.append("lock"),
        clear_clipboard=lambda: executed.append("clipboard"),
        wipe_memory=lambda: executed.append("memory"),
        close_windows=lambda: executed.append("windows"),
    )

    event = panic.activate(trigger="hotkey")

    assert event.success is True
    assert executed == ["lock", "clipboard", "memory", "windows"]
    assert "lock_vault" in event.actions_executed


def test_panic_mode_recovery_requires_master_password():
    panic = PanicMode()

    assert panic.recover(master_password_verified=False) is False
    assert panic.recover(master_password_verified=True) is True


def test_security_profiles_exist_and_validate():
    manager = SecurityProfileManager()

    standard = manager.get_profile("standard")
    enhanced = manager.get_profile("enhanced")
    paranoid = manager.get_profile("paranoid")

    standard.validate()
    enhanced.validate()
    paranoid.validate()

    assert standard.auto_lock_timeout_seconds == 300
    assert enhanced.timing_noise_enabled is True
    assert paranoid.panic_stealth_enabled is True


def test_security_profile_migration_explains_changes_and_applies():
    manager = SecurityProfileManager()

    target = manager.get_profile("paranoid")
    changes = manager.explain_changes(target)

    assert changes

    applied = manager.apply_profile("paranoid")
    assert applied.name.value == "paranoid"