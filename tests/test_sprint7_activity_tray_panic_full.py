from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.screen_lock_detector import ScreenLockDetector, ScreenLockState
from src.core.security.shake_detector import ShakeDetector
from src.core.security.tray_service import TrayService, TrayState


def test_act1_screen_lock_detector_triggers_auto_lock_callback():
    events = []

    detector = ScreenLockDetector(
        on_lock_detected=lambda event: events.append(event)
    )

    detector.inject_state_for_testing(ScreenLockState.LOCKED)

    assert len(events) == 1
    assert events[0].state == ScreenLockState.LOCKED


def test_act1_activity_monitor_screen_lock_forces_lock():
    calls = []

    monitor = ActivityMonitor(
        lock_callback=lambda: calls.append("locked"),
        config=AutoLockConfig(timeout_seconds=300),
    )

    monitor.record_screen_lock()

    assert calls == ["locked"]
    assert monitor.locked is True


def test_tray1_icon_color_changes_by_security_state():
    tray = TrayService()

    tray.set_state(TrayState.LOCKED)
    assert tray.status.icon.color == "red"

    tray.set_state(TrayState.UNLOCKED)
    assert tray.status.icon.color == "green"

    tray.set_state(TrayState.WARNING)
    assert tray.status.icon.color == "yellow"


def test_tray1_icon_animates_during_crypto_operation():
    tray = TrayService()

    icon = tray.animate_crypto_operation()

    assert tray.status.state == TrayState.BUSY
    assert icon.animated is True
    assert icon.color == "blue"


def test_tray3_background_operation_maintains_monitoring_state():
    tray = TrayService()

    tray.start()
    tray.minimize_to_tray()
    tray.set_clipboard_active(True)

    assert tray.status.background_running is True
    assert tray.status.minimized_to_tray is True
    assert tray.status.clipboard_active is True

    tray.stop()
    assert tray.status.background_running is False


def test_panic1_mouse_shake_activation():
    calls = []

    detector = ShakeDetector(
        on_shake=lambda: calls.append("panic")
    )

    positions = [
        (0, 0),
        (80, 0),
        (-80, 0),
        (90, 0),
        (-90, 0),
        (100, 0),
        (-100, 0),
    ]

    triggered = False

    for x, y in positions:
        if detector.record_position(x, y):
            triggered = True

    assert triggered is True
    assert calls == ["panic"]


def test_panic3_stealth_decoy_and_redirect_callbacks():
    calls = []

    panic = PanicMode(
        config=PanicModeConfig(
            stealth_mode=True,
            enabled_actions=[
                PanicAction.LOCK_VAULT,
                PanicAction.CLEAR_CLIPBOARD,
                PanicAction.WIPE_MEMORY,
                PanicAction.CLOSE_WINDOWS,
            ],
            decoy_application="calculator",
            safe_redirect_url="https://example.com",
        ),
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_windows=lambda: calls.append("windows"),
        show_fake_error=lambda message: calls.append("fake_error"),
        launch_decoy_application=lambda app: calls.append(f"decoy:{app}"),
        redirect_to_safe_website=lambda url: calls.append(f"redirect:{url}"),
    )

    event = panic.activate("mouse_shake")

    assert event.success is True
    assert "lock" in calls
    assert "clipboard" in calls
    assert "memory" in calls
    assert "windows" in calls
    assert "fake_error" in calls
    assert "decoy:calculator" in calls
    assert "redirect:https://example.com" in calls
    assert "launch_decoy" in event.actions_executed
    assert "redirect_safe_site" in event.actions_executed


def test_panic4_recovery_requires_master_password_after_activation():
    panic = PanicMode()

    event = panic.activate("tray_menu")

    assert event.success is True
    assert panic.recover(master_password_verified=False) is False
    assert panic.recover(master_password_verified=True) is True