import time

from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.security_profiles import SecurityProfileManager
from src.core.security.tray_service import TrayService, TrayState


def test_tray_service_menu_contains_required_sprint7_actions():
    tray = TrayService()
    menu = tray.build_menu()

    actions = {item.action for item in menu}

    assert "lock" in actions or "unlock" in actions
    assert "show" in actions
    assert "quick_search" in actions
    assert "clear_clipboard" in actions
    assert "panic" in actions
    assert "settings" in actions
    assert "exit" in actions


def test_tray_service_lock_unlock_actions_call_callbacks():
    calls = []

    tray = TrayService(
        lock_vault=lambda: calls.append("lock"),
        unlock_vault=lambda: calls.append("unlock"),
    )

    tray.set_state(TrayState.UNLOCKED)
    tray.execute_menu_action("lock")

    assert "lock" in calls
    assert tray.status.state == TrayState.LOCKED

    tray.execute_menu_action("unlock")

    assert "unlock" in calls
    assert tray.status.state == TrayState.UNLOCKED


def test_tray_service_background_operation_and_minimize_restore():
    calls = []

    tray = TrayService(show_main_window=lambda: calls.append("show"))

    tray.start()
    assert tray.is_running() is True
    assert tray.status.background_running is True

    tray.minimize_to_tray()
    assert tray.status.minimized_to_tray is True

    tray.restore_from_tray()
    assert tray.status.minimized_to_tray is False
    assert calls == ["show"]

    tray.stop()
    assert tray.is_running() is False


def test_tray_service_quick_search_is_disabled_when_locked():
    tray = TrayService(quick_search=lambda query: [{"title": query}])
    tray.set_state(TrayState.LOCKED)

    menu = tray.build_menu()
    quick_search_item = next(item for item in menu if item.action == "quick_search")

    assert quick_search_item.enabled is False


def test_tray_service_quick_search_works_when_unlocked():
    tray = TrayService(quick_search=lambda query: [{"title": query}])
    tray.set_state(TrayState.UNLOCKED)

    result = tray.execute_menu_action("quick_search", query="mail")

    assert result == [{"title": "mail"}]


def test_panic_mode_integrates_with_tray_action():
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

    tray = TrayService(activate_panic=lambda: panic.activate("tray_menu"))

    tray.execute_menu_action("panic")

    assert calls == ["lock", "clipboard", "memory", "windows"]
    assert tray.status.state == TrayState.LOCKED
    assert panic.last_event is not None
    assert panic.last_event.trigger == "tray_menu"


def test_auto_lock_triggers_panic_safe_lock_callbacks():
    calls = []

    def lock_callback():
        calls.append("auto_lock")

    monitor = ActivityMonitor(
        lock_callback=lock_callback,
        config=AutoLockConfig(timeout_seconds=60),
    )

    monitor.last_activity = time.monotonic() - 61

    assert monitor.should_lock() is True

    monitor.force_lock()

    assert calls == ["auto_lock"]
    assert monitor.locked is True


def test_security_profile_can_configure_auto_lock_and_tray_behavior():
    manager = SecurityProfileManager()

    paranoid = manager.apply_profile("paranoid")

    assert paranoid.auto_lock_timeout_seconds == 60
    assert paranoid.start_minimized_to_tray is True
    assert paranoid.panic_stealth_enabled is True


def test_security_notification_is_stored_in_tray_status():
    tray = TrayService()

    tray.notify_security_event("Vault auto-locked after inactivity")

    assert tray.status.notifications == ["Vault auto-locked after inactivity"]