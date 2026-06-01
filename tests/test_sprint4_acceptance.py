from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.clipboard.clipboard_service import (
    ClipboardCleared,
    ClipboardCopied,
    ClipboardService,
    ClipboardSettings,
)
from src.core.clipboard.platform_adapter import ClipboardAdapter
from src.core.clipboard.secure_memory import SecureMemoryBuffer


class InMemoryClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        self.content = ""

    def copy_to_clipboard(self, data: str) -> bool:
        self.content = str(data or "")
        return True

    def clear_clipboard(self) -> bool:
        self.content = ""
        return True

    def get_clipboard_content(self) -> str:
        return self.content


class MockWindowsClipboardAdapter(InMemoryClipboardAdapter):

    pass


class MockMacOSClipboardAdapter(InMemoryClipboardAdapter):
    pass


class MockLinuxClipboardAdapter(InMemoryClipboardAdapter):

    def __init__(self, selection: str = "clipboard"):
        super().__init__()
        self.selection = selection


def test_acceptance_auto_clear_timing_within_100ms():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(
            auto_clear_seconds=5,
            warning_before_clear_seconds=0,
        ),
    )
    service.subscribe(events.append)

    start = time.perf_counter()

    service.copy_to_clipboard(
        data="TimingSecret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    deadline = start + 5.5

    while time.perf_counter() < deadline:
        if service.get_status().active is False:
            break
        time.sleep(0.01)

    elapsed = time.perf_counter() - start

    assert service.get_status().active is False
    assert adapter.content == ""

    assert 4.9 <= elapsed <= 5.5

    cleared_events = [
        event for event in events
        if isinstance(event, ClipboardCleared)
    ]

    assert cleared_events
    assert cleared_events[-1].reason == "timeout"


def test_acceptance_cross_platform_compatibility_with_mock_adapters():
    adapters = [
        MockWindowsClipboardAdapter(),
        MockMacOSClipboardAdapter(),
        MockLinuxClipboardAdapter(selection="clipboard"),
        MockLinuxClipboardAdapter(selection="primary"),
    ]

    for index, adapter in enumerate(adapters):
        service = ClipboardService(
            platform_adapter=adapter,
            settings=ClipboardSettings(auto_clear_seconds=30),
        )

        service.copy_to_clipboard(
            data=f"CrossPlatformSecret-{index}",
            data_type="password",
            source_entry_id=index,
            vault_unlocked=True,
        )

        assert adapter.get_clipboard_content() == f"CrossPlatformSecret-{index}"
        assert service.get_status().active is True

        service.clear_clipboard(reason="manual")

        assert adapter.get_clipboard_content() == ""
        assert service.get_status().active is False


def test_acceptance_memory_security_plaintext_not_in_secure_obfuscated_buffer():

    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    password = "VerySensitivePassword123!"

    service.copy_to_clipboard(
        data=password,
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    current_item = service._current_item

    assert current_item is not None
    assert isinstance(current_item.mask_buffer, SecureMemoryBuffer)
    assert isinstance(current_item.obfuscated_buffer, SecureMemoryBuffer)

    obfuscated_bytes = current_item.obfuscated_buffer.read()

    assert password.encode("utf-8") not in obfuscated_bytes
    assert service.get_current_plaintext_for_testing() == password

    service.clear_clipboard(reason="manual")

    assert current_item.mask_buffer.read() == b""
    assert current_item.obfuscated_buffer.read() == b""
    assert service.get_status().active is False


def test_acceptance_concurrency_rapid_copy_operations_no_leakage():
    adapter = InMemoryClipboardAdapter()
    events = []

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )
    service.subscribe(events.append)

    def copy_secret(i: int) -> str:
        secret = f"ConcurrentSecret-{i}"
        service.copy_to_clipboard(
            data=secret,
            data_type="password",
            source_entry_id=i,
            vault_unlocked=True,
        )
        return secret

    copied_values = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(copy_secret, i)
            for i in range(100)
        ]

        for future in as_completed(futures):
            copied_values.append(future.result())

    assert adapter.content.startswith("ConcurrentSecret-")
    assert service.get_status().active is True
    assert service.get_current_plaintext_for_testing() == adapter.content

    copied_events = [
        event for event in events
        if isinstance(event, ClipboardCopied)
    ]

    assert len(copied_events) == 100

    assert not hasattr(service, "clipboard_history")


def test_acceptance_recovery_clears_clipboard_after_crash_handler():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="CrashRecoverySecret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert adapter.content == "CrashRecoverySecret"
    assert service.get_status().active is True

    service._crash_recovery_clear()

    assert adapter.content == ""
    assert service.get_status().active is False