from src.core.clipboard.clipboard_service import ClipboardService, ClipboardSettings
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.tray_service import TrayService, TrayState
from src.core.vault.password_generator import PasswordGenerator


def test_sprint7_does_not_break_password_generator():
    generator = PasswordGenerator()

    password = generator.generate(
        length=16,
        use_uppercase=True,
        use_lowercase=True,
        use_digits=True,
        use_special=True,
    )

    result = generator.analyze_strength(password)

    assert len(password) == 16
    assert result["score"] >= 3


def test_sprint7_can_clear_existing_clipboard_service_from_panic_mode():
    service = ClipboardService(
        settings=ClipboardSettings(auto_clear_seconds=30)
    )

    service.copy_to_clipboard(
        data="secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert service.get_status().active is True

    panic = PanicMode(
        config=PanicModeConfig(
            enabled_actions=[PanicAction.CLEAR_CLIPBOARD]
        ),
        clear_clipboard=lambda: service.clear_clipboard(reason="panic"),
    )

    event = panic.activate("test")

    assert event.success is True
    assert service.get_status().active is False

    service.close()


def test_sprint7_tray_state_can_reflect_clipboard_service_activity():
    service = ClipboardService(
        settings=ClipboardSettings(auto_clear_seconds=30)
    )
    tray = TrayService()

    service.copy_to_clipboard(
        data="secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    tray.set_clipboard_active(service.get_status().active)

    assert tray.status.clipboard_active is True

    clear_item = next(item for item in tray.build_menu() if item.action == "clear_clipboard")
    assert clear_item.enabled is True

    service.close()


def test_sprint7_tray_lock_state_does_not_require_real_gui():
    tray = TrayService()

    tray.set_state(TrayState.UNLOCKED)
    assert tray.status.state == TrayState.UNLOCKED
    assert "unlocked" in tray.status.tooltip.lower()

    tray.set_state(TrayState.LOCKED)
    assert tray.status.state == TrayState.LOCKED
    assert "locked" in tray.status.tooltip.lower()