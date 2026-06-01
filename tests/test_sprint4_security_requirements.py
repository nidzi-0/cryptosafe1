from __future__ import annotations

from src.core.clipboard.clipboard_service import (
    ClipboardSecurityLevel,
    ClipboardService,
    ClipboardSettings,
)
from src.core.clipboard.platform_adapter import ClipboardAdapter


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


def test_sec1_clipboard_data_not_persisted_to_disk():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="NoPersistenceSecret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert not hasattr(service, "clipboard_history")
    assert not hasattr(service, "clipboard_file_path")
    assert service.get_current_plaintext_for_testing() == "NoPersistenceSecret"

    service.clear_clipboard(reason="manual")

    assert service.get_current_plaintext_for_testing() == ""


def test_sec2_paranoid_mode_uses_ephemeral_for_sensitive_data():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(
            auto_clear_seconds=30,
            security_level=ClipboardSecurityLevel.PARANOID,
        ),
    )

    service.copy_to_clipboard(
        data="ParanoidSecretPassword",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    status = service.get_status()

    assert status.active is True
    assert status.ephemeral is True
    assert adapter.content == ""
    assert service.get_ephemeral_secret_for_internal_transfer() == "ParanoidSecretPassword"


def test_sec2_basic_mode_allows_system_clipboard_for_non_paranoid():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(
            auto_clear_seconds=30,
            security_level=ClipboardSecurityLevel.BASIC,
        ),
    )

    service.copy_to_clipboard(
        data="BasicSecretPassword",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    status = service.get_status()

    assert status.active is True
    assert status.ephemeral is False
    assert adapter.content == "BasicSecretPassword"


def test_sec3_clear_on_lock_immediately_clears_clipboard():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="LockSecret",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert adapter.content == "LockSecret"

    service.clear_on_lock()

    assert adapter.content == ""
    assert service.get_status().active is False


def test_sec4_input_validation_and_sanitization():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="  abc\x00def\r\nnext  ",
        data_type="text",
        source_entry_id=None,
        vault_unlocked=True,
    )

    assert adapter.content == "abcdef\nnext"

    try:
        service.copy_to_clipboard(
            data="   ",
            data_type="text",
            source_entry_id=None,
            vault_unlocked=True,
        )
        assert False, "Пустое значение должно быть запрещено."
    except Exception as exc:
        assert "пустое" in str(exc).lower()