from __future__ import annotations

import time

import pytest

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.clipboard_service import (
    ClipboardCleared,
    ClipboardCopied,
    ClipboardSecurityAlert,
    ClipboardService,
    ClipboardServiceError,
    ClipboardSettings,
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


def test_clipboard_copy_and_manual_clear():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )
    service.subscribe(events.append)

    status = service.copy_to_clipboard(
        data="SecretPassword123!",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert status.active is True
    assert adapter.content == "SecretPassword123!"
    assert service.get_current_plaintext_for_testing() == "SecretPassword123!"

    service.clear_clipboard(reason="manual")

    assert adapter.content == ""
    assert service.get_status().active is False

    assert any(isinstance(event, ClipboardCopied) for event in events)
    assert any(isinstance(event, ClipboardCleared) for event in events)


def test_clipboard_auto_clear_timing():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=5),
    )

    service.copy_to_clipboard(
        data="AutoClearSecret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert adapter.content == "AutoClearSecret"

    # В тесте не ждём 5 секунд, а напрямую вызываем timeout handler.
    service._on_timeout()

    assert adapter.content == ""
    assert service.get_status().active is False


def test_clipboard_replaces_old_content():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="FirstSecret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert adapter.content == "FirstSecret"

    service.copy_to_clipboard(
        data="SecondSecret",
        data_type="password",
        source_entry_id=2,
        vault_unlocked=True,
    )

    assert adapter.content == "SecondSecret"
    assert service.get_current_plaintext_for_testing() == "SecondSecret"


def test_clipboard_requires_unlocked_vault():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    with pytest.raises(ClipboardServiceError):
        service.copy_to_clipboard(
            data="Secret",
            data_type="password",
            source_entry_id=1,
            vault_unlocked=False,
        )


def test_clipboard_input_validation_and_sanitization():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    with pytest.raises(ClipboardServiceError):
        service.copy_to_clipboard(
            data="",
            data_type="password",
            source_entry_id=1,
            vault_unlocked=True,
        )

    service.copy_to_clipboard(
        data="  abc\x00def  ",
        data_type="text",
        source_entry_id=None,
        vault_unlocked=True,
    )

    assert adapter.content == "abcdef"


def test_clipboard_external_change_detection_clears_content():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(
            auto_clear_seconds=30,
            block_on_suspicious_activity=True,
        ),
    )
    service.subscribe(events.append)

    service.copy_to_clipboard(
        data="Secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    adapter.content = "external-change"
    service.on_external_clipboard_change_detected()

    assert service.get_status().active is False
    assert adapter.content == ""

    assert any(isinstance(event, ClipboardSecurityAlert) for event in events)

    with pytest.raises(ClipboardServiceError):
        service.copy_to_clipboard(
            data="AnotherSecret",
            data_type="password",
            source_entry_id=1,
            vault_unlocked=True,
        )


def test_clipboard_monitor_detects_external_change():
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="Secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    monitor = ClipboardMonitor(
        platform_adapter=adapter,
        clipboard_service=service,
        poll_interval_seconds=0.05,
    )

    monitor.start()

    try:
        adapter.content = "external"
        time.sleep(0.15)
    finally:
        monitor.stop()

    assert service.get_status().active is False


def test_clipboard_never_auto_clear_allowed():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=None),
    )

    service.copy_to_clipboard(
        data="NoAutoClear",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    status = service.get_status()

    assert status.active is True
    assert status.remaining_seconds == 0.0

    service.clear_clipboard(reason="manual")