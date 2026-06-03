import pytest

from src.core.security.activity_monitor import AutoLockConfig
from src.core.security.memory_guard import SecretHolder
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.security_profiles import SecurityProfileManager
from src.core.security.side_channel_protection import ConstantTime
from src.core.security.tray_service import TrayService, TrayState


def test_sprint7_constant_time_comparison_rejects_wrong_types():
    assert ConstantTime.bytes_equal(b"abc", "abc") is False
    assert ConstantTime.string_equal("abc", b"abc") is False


def test_sprint7_constant_time_select_requires_equal_length():
    with pytest.raises(ValueError):
        ConstantTime.constant_time_select(True, b"short", b"longer")


def test_sprint7_secret_holder_cannot_read_after_close():
    holder = SecretHolder(b"secret")
    assert holder.get_bytes() == b"secret"

    holder.close()

    with pytest.raises(Exception):
        holder.get_bytes()


def test_sprint7_auto_lock_config_rejects_too_short_timeout():
    with pytest.raises(ValueError):
        AutoLockConfig(timeout_seconds=30).validate()


def test_sprint7_auto_lock_config_rejects_too_long_timeout():
    with pytest.raises(ValueError):
        AutoLockConfig(timeout_seconds=9 * 60 * 60).validate()


def test_sprint7_auto_lock_config_rejects_unknown_device_profile():
    with pytest.raises(ValueError):
        AutoLockConfig(timeout_seconds=300, device_profile="phone").validate()


def test_sprint7_panic_mode_continues_to_return_failed_event_on_callback_error():
    def broken_callback():
        raise RuntimeError("boom")

    panic = PanicMode(
        config=PanicModeConfig(
            enabled_actions=[
                PanicAction.LOCK_VAULT,
                PanicAction.CLEAR_CLIPBOARD,
            ]
        ),
        lock_vault=lambda: None,
        clear_clipboard=broken_callback,
    )

    event = panic.activate("hotkey")

    assert event.success is False
    assert event.error == "boom"
    assert "lock_vault" in event.actions_executed


def test_sprint7_panic_recovery_requires_verified_master_password():
    panic = PanicMode()

    assert panic.recover(master_password_verified=False) is False
    assert panic.recover(master_password_verified=True) is True


def test_sprint7_tray_quick_search_disabled_when_locked():
    tray = TrayService(quick_search=lambda query: [{"title": query}])
    tray.set_state(TrayState.LOCKED)

    quick_search = next(item for item in tray.build_menu() if item.action == "quick_search")

    assert quick_search.enabled is False


def test_sprint7_tray_clear_clipboard_disabled_when_clipboard_inactive():
    tray = TrayService()
    tray.set_clipboard_active(False)

    clear_item = next(item for item in tray.build_menu() if item.action == "clear_clipboard")

    assert clear_item.enabled is False


def test_sprint7_tray_unknown_action_is_rejected():
    tray = TrayService()

    with pytest.raises(ValueError):
        tray.execute_menu_action("unknown-action")


def test_sprint7_security_profile_rejects_unknown_profile():
    manager = SecurityProfileManager()

    with pytest.raises(ValueError):
        manager.get_profile("unknown")