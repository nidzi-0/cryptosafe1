import pytest

from src.core.security.session_recovery import (
    MasterPasswordRequiredError,
    SessionIntegrityError,
    SessionRecoveryManager,
    VaultSessionState,
    WindowState,
)
from src.gui.sprint7_security_integration import Sprint7SecurityIntegration


def test_act4_resume_from_lock_requires_master_password():
    manager = SessionRecoveryManager()

    state = VaultSessionState(
        selected_entry_ids=[1, 2],
        search_query="mail",
        window_state=WindowState(geometry="1000x700+10+10"),
    )

    manager.create_snapshot(state)

    with pytest.raises(MasterPasswordRequiredError):
        manager.restore_snapshot(master_password_verified=False)

    restored = manager.restore_snapshot(master_password_verified=True)

    assert restored.selected_entry_ids == [1, 2]
    assert restored.search_query == "mail"
    assert restored.window_state.geometry == "1000x700+10+10"


def test_act4_session_integrity_is_verified():
    manager = SessionRecoveryManager()

    manager.create_snapshot(
        VaultSessionState(
            selected_entry_ids=[1],
            search_query="bank",
            active_security_profile="standard",
        )
    )

    tampered = manager.tamper_snapshot_for_testing()

    with pytest.raises(SessionIntegrityError):
        manager.restore_snapshot(
            master_password_verified=True,
            snapshot=tampered,
        )


def test_act4_restore_previous_state_without_data_loss():
    manager = SessionRecoveryManager()

    original = VaultSessionState(
        selected_entry_ids=[10, 20, 30],
        search_query="github",
        table_scroll_position=0.55,
        password_visibility_enabled=False,
        active_security_profile="enhanced",
        window_state=WindowState(
            geometry="1200x800+50+60",
            is_visible=True,
            minimized_to_tray=False,
        ),
    )

    manager.create_snapshot(original)
    restored = manager.restore_snapshot(master_password_verified=True)

    assert restored.selected_entry_ids == original.selected_entry_ids
    assert restored.search_query == original.search_query
    assert restored.table_scroll_position == original.table_scroll_position
    assert restored.active_security_profile == original.active_security_profile
    assert restored.window_state.geometry == original.window_state.geometry


def test_tray4_minimize_to_tray_hides_window_and_saves_state():
    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
    )

    snapshot = integration.minimize_to_tray_with_snapshot(
        selected_entry_ids=[5],
        search_query="work",
        table_scroll_position=0.25,
        password_visibility_enabled=False,
        window_geometry="900x600+100+100",
    )

    assert integration.tray_service.status.minimized_to_tray is True
    assert integration.session_recovery.verify_snapshot(snapshot) is True

    restored = integration.restore_from_tray_with_state(
        master_password_verified=True,
    )

    assert restored.selected_entry_ids == [5]
    assert restored.search_query == "work"
    assert restored.window_state.geometry == "900x600+100+100"


def test_tray4_start_minimized_to_tray_option_from_paranoid_profile():
    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
    )

    profile = integration.apply_security_profile("paranoid")

    assert profile.start_minimized_to_tray is True
    assert integration.tray_service.status.minimized_to_tray is True


def test_panic4_recovery_allows_normal_unlock_and_restores_session():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_sensitive_windows=lambda: calls.append("windows"),
        audit_log=lambda event, details: calls.append(event),
    )

    integration.create_session_snapshot(
        selected_entry_ids=[7],
        search_query="panic-safe",
        table_scroll_position=0.75,
        window_geometry="1000x700+1+1",
    )

    event = integration.activate_panic("hotkey")

    assert event.success is True
    assert integration.status().vault_locked is True

    restored = integration.recover_from_panic(master_password_verified=True)

    assert restored.selected_entry_ids == [7]
    assert restored.search_query == "panic-safe"
    assert integration.status().vault_locked is False
    assert "panic_recovery_completed" in calls


def test_panic4_recovery_rejects_without_master_password():
    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
    )

    integration.create_session_snapshot(
        selected_entry_ids=[1],
        search_query="secret",
    )

    integration.activate_panic("hotkey")

    with pytest.raises(MasterPasswordRequiredError):
        integration.recover_from_panic(master_password_verified=False)


def test_panic4_logs_panic_events_in_audit_log():
    events = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
        audit_log=lambda event, details: events.append((event, details)),
    )

    integration.create_session_snapshot(search_query="audit")
    integration.activate_panic("tray_menu")
    integration.recover_from_panic(master_password_verified=True)

    event_names = [event for event, _details in events]

    assert "panic_mode_activated" in event_names
    assert "panic_recovery_completed" in event_names