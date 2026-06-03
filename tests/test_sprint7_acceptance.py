import time

from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.memory_guard import SecretHolder
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.security_profiles import SecurityProfileManager
from src.core.security.side_channel_protection import ConstantTime, SideChannelProtector
from src.core.security.tray_service import TrayService, TrayState
from src.gui.sprint7_security_integration import Sprint7SecurityIntegration


def test_sprint7_required_security_modules_are_importable():
    from src.core.security import (
        ActivityMonitor,
        AutoLockConfig,
        ConstantTime,
        MemoryDumpScanner,
        PanicMode,
        SecretHolder,
        SecurityProfileManager,
        SideChannelProtector,
        TrayService,
    )

    assert ConstantTime is not None
    assert SideChannelProtector is not None
    assert SecretHolder is not None
    assert ActivityMonitor is not None
    assert AutoLockConfig is not None
    assert PanicMode is not None
    assert SecurityProfileManager is not None
    assert TrayService is not None
    assert MemoryDumpScanner is not None


def test_sprint7_side_channel_constant_time_comparison_acceptance():
    assert ConstantTime.bytes_equal(b"same-secret", b"same-secret") is True
    assert ConstantTime.bytes_equal(b"same-secret", b"other-value") is False

    assert ConstantTime.string_equal("StrongPassA123!", "StrongPassA123!") is True
    assert ConstantTime.string_equal("StrongPassA123!", "WeakPass") is False


def test_sprint7_side_channel_no_early_return_membership_acceptance():
    values = [f"value-{index}" for index in range(100)]

    assert ConstantTime.fixed_time_contains("value-0", values) is True
    assert ConstantTime.fixed_time_contains("value-99", values) is True
    assert ConstantTime.fixed_time_contains("missing", values) is False


def test_sprint7_memory_guard_acceptance():
    secret = b"master-password-or-key"

    with SecretHolder(secret) as holder:
        assert holder.get_bytes() == secret
        assert holder.info.size == len(secret)

    assert holder.info.size == len(secret)


def test_sprint7_auto_lock_acceptance():
    calls = []

    monitor = ActivityMonitor(
        lock_callback=lambda: calls.append("locked"),
        config=AutoLockConfig(timeout_seconds=60),
    )

    monitor.last_activity = time.monotonic() - 61

    assert monitor.should_lock() is True

    monitor.force_lock()

    assert calls == ["locked"]
    assert monitor.locked is True


def test_sprint7_auto_lock_does_not_trigger_before_timeout():
    calls = []

    monitor = ActivityMonitor(
        lock_callback=lambda: calls.append("locked"),
        config=AutoLockConfig(timeout_seconds=60),
    )

    monitor.last_activity = time.monotonic() - 10

    assert monitor.should_lock() is False
    assert calls == []


def test_sprint7_panic_mode_acceptance():
    calls = []

    panic = PanicMode(
        config=PanicModeConfig(
            enabled_actions=[
                PanicAction.LOCK_VAULT,
                PanicAction.CLEAR_CLIPBOARD,
                PanicAction.WIPE_MEMORY,
                PanicAction.CLOSE_WINDOWS,
            ],
            stealth_mode=True,
        ),
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_windows=lambda: calls.append("windows"),
        show_fake_error=lambda message: calls.append("fake_error"),
    )

    event = panic.activate("hotkey")

    assert event.success is True
    assert calls == ["lock", "clipboard", "memory", "windows", "fake_error"]
    assert "lock_vault" in event.actions_executed
    assert "clear_clipboard" in event.actions_executed
    assert "wipe_memory" in event.actions_executed
    assert "close_windows" in event.actions_executed
    assert "fake_error" in event.actions_executed


def test_sprint7_tray_acceptance():
    calls = []

    tray = TrayService(
        lock_vault=lambda: calls.append("lock"),
        unlock_vault=lambda: calls.append("unlock"),
        show_main_window=lambda: calls.append("show"),
        clear_clipboard=lambda: calls.append("clear"),
        activate_panic=lambda: calls.append("panic"),
        open_settings=lambda: calls.append("settings"),
        exit_application=lambda: calls.append("exit"),
    )

    tray.start()
    assert tray.status.background_running is True

    tray.set_state(TrayState.UNLOCKED)
    tray.set_clipboard_active(True)

    menu_actions = {item.action for item in tray.build_menu()}
    assert {"lock", "show", "quick_search", "clear_clipboard", "panic", "settings", "exit"} <= menu_actions

    tray.execute_menu_action("lock")
    tray.execute_menu_action("unlock")
    tray.execute_menu_action("show")
    tray.execute_menu_action("clear_clipboard")
    tray.execute_menu_action("panic")
    tray.execute_menu_action("settings")

    assert "lock" in calls
    assert "unlock" in calls
    assert "show" in calls
    assert "clear" in calls
    assert "panic" in calls
    assert "settings" in calls

    tray.execute_menu_action("exit")

    assert "exit" in calls
    assert tray.is_running() is False


def test_sprint7_security_profiles_acceptance():
    manager = SecurityProfileManager()

    standard = manager.get_profile("standard")
    enhanced = manager.get_profile("enhanced")
    paranoid = manager.get_profile("paranoid")

    standard.validate()
    enhanced.validate()
    paranoid.validate()

    assert standard.auto_lock_timeout_seconds == 300
    assert enhanced.timing_noise_enabled is True
    assert paranoid.auto_lock_timeout_seconds == 60
    assert paranoid.start_minimized_to_tray is True


def test_sprint7_gui_integration_acceptance():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_sensitive_windows=lambda: calls.append("windows"),
        audit_log=lambda event, details: calls.append(event),
        auto_lock_timeout_seconds=60,
    )

    integration.start()
    integration.mark_unlocked()

    assert integration.status().vault_locked is False
    assert integration.status().tray_running is True

    panic_event = integration.handle_hotkey("Ctrl+Shift+Esc")

    assert panic_event is not None
    assert panic_event.success is True
    assert "lock" in calls
    assert "clipboard" in calls
    assert "memory" in calls
    assert "windows" in calls
    assert integration.status().vault_locked is True

    integration.stop()
    assert integration.status().tray_running is False


def test_sprint7_security_profile_rolls_into_gui_integration():
    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
    )

    profile = integration.apply_security_profile("paranoid")

    assert profile.name.value == "paranoid"
    assert integration.status().auto_lock_timeout_seconds == 60
    assert integration.tray_service.status.minimized_to_tray is True


def test_sprint7_timing_measurement_acceptance():
    protector = SideChannelProtector()

    samples = [
        protector.measure_operation(
            "compare",
            lambda: protector.secure_compare_bytes(b"a" * 32, b"a" * 32),
        )
        for _ in range(10)
    ]

    ratio = protector.timing_variance_ratio(samples)

    assert ratio >= 1.0