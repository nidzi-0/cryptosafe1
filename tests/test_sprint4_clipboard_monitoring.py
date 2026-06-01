from __future__ import annotations

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.clipboard_service import (
    ClipboardAccessDetected,
    ClipboardSecurityAlert,
    ClipboardService,
    ClipboardSettings,
    EphemeralClipboardTransfer,
)
from src.core.clipboard.platform_adapter import ClipboardAdapter


class InMemoryClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        self.content = ""

    def copy_to_clipboard(self, data: str) -> bool:
        self.content = data
        return True

    def clear_clipboard(self) -> bool:
        self.content = ""
        return True

    def get_clipboard_content(self) -> str:
        return self.content


def test_monitor_detects_external_clipboard_change():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )
    service.subscribe(events.append)

    service.copy_to_clipboard(
        data="secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    monitor = ClipboardMonitor(
        platform_adapter=adapter,
        clipboard_service=service,
        poll_interval_seconds=0.01,
    )

    monitor._last_seen_content = "secret"

    adapter.content = "changed-outside"

    monitor.check_once()

    assert service.get_status().active is False
    assert any(isinstance(event, ClipboardAccessDetected) for event in events)
    assert any(isinstance(event, ClipboardSecurityAlert) for event in events)


def test_monitor_detects_expected_content_mismatch():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )
    service.subscribe(events.append)

    service.copy_to_clipboard(
        data="expected-secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    adapter.content = "mismatch"

    result = service.verify_system_clipboard_snapshot()

    assert result is False
    assert service.get_status().active is False
    assert any(isinstance(event, ClipboardAccessDetected) for event in events)


def test_block_future_copies_when_suspicious_activity_detected():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(
            auto_clear_seconds=30,
            block_on_suspicious_activity=True,
        ),
    )

    service.copy_to_clipboard(
        data="secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    service.on_external_clipboard_change_detected("possible_external_access")

    assert service.get_status().active is False
    assert service.get_suspicious_events_count() == 1

    try:
        service.copy_to_clipboard(
            data="new-secret",
            data_type="password",
            source_entry_id=1,
            vault_unlocked=True,
        )
        assert False, "copy_to_clipboard должен был быть заблокирован"
    except Exception as exc:
        assert "заблокировано" in str(exc).lower()


def test_clipboard_history_is_not_stored_beyond_current_item():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="first-secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    service.copy_to_clipboard(
        data="second-secret",
        data_type="password",
        source_entry_id=2,
        vault_unlocked=True,
    )

    assert service.get_current_plaintext_for_testing() == "second-secret"
    assert not hasattr(service, "clipboard_history")


def test_ephemeral_clipboard_does_not_touch_system_clipboard():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )
    service.subscribe(events.append)

    service.copy_to_clipboard(
        data="ephemeral-secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
        ephemeral=True,
    )

    status = service.get_status()

    assert status.active is True
    assert status.ephemeral is True
    assert adapter.content == ""
    assert service.get_ephemeral_secret_for_internal_transfer() == "ephemeral-secret"
    assert any(isinstance(event, EphemeralClipboardTransfer) for event in events)

    service.clear_clipboard(reason="manual")

    assert service.get_status().active is False
    assert service.get_ephemeral_secret_for_internal_transfer() == ""