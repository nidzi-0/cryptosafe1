from __future__ import annotations

from src.core.clipboard.clipboard_service import ClipboardService, ClipboardSettings
from src.core.clipboard.platform_adapter import ClipboardAdapter
from src.core.clipboard.screenshot_protection import ScreenshotProtection
from src.core.clipboard.secure_memory import SecureMemoryBuffer


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


def test_secure_memory_buffer_read_and_zero():
    secret = b"super-secret-password"
    buffer = SecureMemoryBuffer(secret)

    assert buffer.read() == secret

    buffer.zero()

    assert buffer.read() == b"\x00" * len(secret)

    buffer.close()

    assert buffer.read() == b""


def test_clipboard_item_uses_secure_memory_and_wipes_on_clear():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    service.copy_to_clipboard(
        data="SecretPassword123!",
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    assert service.get_current_plaintext_for_testing() == "SecretPassword123!"

    current_item = service._current_item

    assert current_item is not None
    assert hasattr(current_item, "mask_buffer")
    assert hasattr(current_item, "obfuscated_buffer")

    service.clear_clipboard(reason="manual")

    assert adapter.content == ""
    assert service.get_status().active is False
    assert current_item.mask_buffer.read() == b""
    assert current_item.obfuscated_buffer.read() == b""


def test_clipboard_xor_obfuscation_does_not_store_plaintext_in_obfuscated_buffer():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    password = "PlainTextPassword!"

    service.copy_to_clipboard(
        data=password,
        data_type="password",
        source_entry_id=1,
        vault_unlocked=True,
    )

    current_item = service._current_item

    assert current_item is not None
    assert password.encode("utf-8") not in current_item.obfuscated_buffer.read()
    assert service.get_current_plaintext_for_testing() == password


def test_clipboard_requires_unlocked_vault_for_security():
    adapter = InMemoryClipboardAdapter()

    service = ClipboardService(
        platform_adapter=adapter,
        settings=ClipboardSettings(auto_clear_seconds=30),
    )

    try:
        service.copy_to_clipboard(
            data="secret",
            data_type="password",
            source_entry_id=1,
            vault_unlocked=False,
        )
        assert False, "Операция должна быть запрещена при заблокированном vault."
    except Exception as exc:
        assert "заблокировано" in str(exc).lower()


def test_screenshot_protection_graceful_fallback():
    protection = ScreenshotProtection()

    result = protection.enable_for_window(None)

    assert result in {True, False}
    assert protection.is_enabled() in {True, False}

    disable_result = protection.disable_for_window(None)

    assert disable_result in {True, False}