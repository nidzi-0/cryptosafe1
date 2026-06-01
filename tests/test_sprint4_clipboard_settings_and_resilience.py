from __future__ import annotations

import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from src.core.clipboard.clipboard_service import (
    ClipboardCleared,
    ClipboardCopied,
    ClipboardSecurityLevel,
    ClipboardService,
    ClipboardSettings,
)
from src.core.clipboard.clipboard_settings_store import ClipboardSettingsStore
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


def test_clipboard_settings_persist_across_restarts(tmp_path):
    db_path = tmp_path / "settings.db"

    store = ClipboardSettingsStore(db_path)

    settings = ClipboardSettings(
        auto_clear_seconds=15,
        notifications_enabled=False,
        warning_before_clear_seconds=5,
        security_level=ClipboardSecurityLevel.ADVANCED,
        block_on_suspicious_activity=True,
        allowed_applications=["CryptoSafe Manager"],
    )

    store.save(settings)

    store_after_restart = ClipboardSettingsStore(db_path)
    loaded = store_after_restart.load()

    assert loaded.auto_clear_seconds == 15
    assert loaded.notifications_enabled is False
    assert loaded.security_level == ClipboardSecurityLevel.ADVANCED
    assert loaded.block_on_suspicious_activity is True
    assert loaded.allowed_applications == ["CryptoSafe Manager"]


def test_clipboard_preset_profiles(tmp_path):
    db_path = tmp_path / "settings.db"

    store = ClipboardSettingsStore(db_path)

    public_settings = store.apply_preset("public_computer")

    assert public_settings.auto_clear_seconds == 5
    assert public_settings.security_level == ClipboardSecurityLevel.PARANOID
    assert public_settings.block_on_suspicious_activity is True

    secure_settings = store.apply_preset("secure")

    assert secure_settings.auto_clear_seconds == 15
    assert secure_settings.security_level == ClipboardSecurityLevel.ADVANCED


def test_clipboard_warning_event_before_clear():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(
            auto_clear_seconds=10,
            warning_before_clear_seconds=5,
        ),
    )
    service.subscribe(events.append)

    service.copy_to_clipboard(
        data="warning-secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    service._on_warning()

    assert any(event.__class__.__name__ == "ClipboardWarning" for event in events)


def test_clipboard_crash_recovery_clear():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="crash-secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert adapter.content == "crash-secret"

    service._crash_recovery_clear()

    assert adapter.content == ""
    assert service.get_status().active is False


def test_clipboard_concurrent_rapid_copy_operations_no_leakage():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )
    service.subscribe(events.append)

    def copy_one(i: int):
        service.copy_to_clipboard(
            data=f"secret-{i}",
            data_type="password",
            source_entry_id=i,
            vault_unlocked=True,
        )
        return i

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(copy_one, i) for i in range(30)]

        for future in as_completed(futures):
            future.result()

    assert adapter.content.startswith("secret-")
    assert service.get_status().active is True

    copied_events = [event for event in events if isinstance(event, ClipboardCopied)]

    assert len(copied_events) == 30
    assert service.get_current_plaintext_for_testing() == adapter.content


def test_clipboard_memory_overhead_under_10mb():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    tracemalloc.start()

    for i in range(100):
        service.copy_to_clipboard(
            data=f"memory-secret-{i}",
            data_type="password",
            source_entry_id=i,
            vault_unlocked=True,
        )

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024

    assert peak_mb < 10.0


def test_clipboard_copy_operation_under_100ms():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    start = time.perf_counter()

    service.copy_to_clipboard(
        data="fast-secret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    elapsed = time.perf_counter() - start

    assert elapsed < 0.1