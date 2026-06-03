from src.gui.sprint7_security_integration import Sprint7SecurityIntegration


def test_sprint7_gui_integration_start_stop_status():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_sensitive_windows=lambda: calls.append("windows"),
        audit_log=lambda event, details: calls.append(event),
    )

    integration.start()
    status = integration.status()

    assert status.tray_running is True
    assert status.auto_lock_enabled is True
    assert status.vault_locked is True

    integration.stop()

    assert integration.status().tray_running is False


def test_sprint7_gui_integration_mark_unlocked_and_locked():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
    )

    integration.mark_unlocked()

    assert integration.status().vault_locked is False

    integration.mark_locked()

    assert integration.status().vault_locked is True


def test_sprint7_gui_integration_auto_lock_calls_lock_callback():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
        auto_lock_timeout_seconds=60,
    )

    integration.mark_unlocked()
    integration.lock_due_to_inactivity()

    assert calls == ["lock"]
    assert integration.status().vault_locked is True


def test_sprint7_gui_integration_panic_hotkey_executes_callbacks():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
        clear_clipboard=lambda: calls.append("clipboard"),
        wipe_memory=lambda: calls.append("memory"),
        close_sensitive_windows=lambda: calls.append("windows"),
    )

    event = integration.handle_hotkey("Ctrl+Shift+Esc")

    assert event is not None
    assert event.success is True
    assert calls == ["lock", "clipboard", "memory", "windows"]
    assert integration.status().vault_locked is True


def test_sprint7_gui_integration_security_profile_paranoid():
    calls = []

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: calls.append("lock"),
        audit_log=lambda event, details: calls.append(event),
    )

    profile = integration.apply_security_profile("paranoid")

    assert profile.name.value == "paranoid"
    assert integration.status().auto_lock_timeout_seconds == 60
    assert integration.tray_service.status.minimized_to_tray is True
    assert "security_profile_applied" in calls


def test_sprint7_gui_integration_quick_search_from_tray():
    entries = [
        {"title": "mail", "username": "user@mail.com", "url": "https://mail.example"},
        {"title": "bank", "username": "user", "url": "https://bank.example"},
    ]

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
        quick_search=lambda query: [entry for entry in entries if query in entry["title"]],
    )

    integration.mark_unlocked()

    result = integration.tray_service.execute_menu_action("quick_search", "mail")

    assert result == [entries[0]]