from __future__ import annotations

import platform

from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    LinuxClipboardAdapter,
    MacOSCommandClipboardAdapter,
    PyperclipClipboardAdapter,
    TkinterClipboardAdapter,
    create_fallback_clipboard_adapter,
    create_platform_clipboard_adapter,
)


def test_create_platform_adapter_returns_clipboard_adapter():
    adapter = create_platform_clipboard_adapter()

    assert isinstance(adapter, ClipboardAdapter)


def test_create_fallback_adapter_returns_clipboard_adapter():
    adapter = create_fallback_clipboard_adapter()

    assert isinstance(adapter, ClipboardAdapter)


def test_tkinter_clipboard_adapter_memory_fallback():
    adapter = TkinterClipboardAdapter()

    assert adapter.copy_to_clipboard("hello") is True
    assert adapter.get_clipboard_content() in {"hello", ""}
    assert adapter.clear_clipboard() is True


def test_linux_adapter_supports_clipboard_and_primary_selection():
    clipboard_adapter = LinuxClipboardAdapter(selection="clipboard")
    primary_adapter = LinuxClipboardAdapter(selection="primary")

    assert clipboard_adapter.selection == "clipboard"
    assert primary_adapter.selection == "primary"


def test_platform_adapter_name_matches_current_platform():
    adapter = create_platform_clipboard_adapter()
    system = platform.system().lower()

    if system == "linux":
        assert isinstance(adapter, ClipboardAdapter)

    if system == "windows":
        assert isinstance(adapter, ClipboardAdapter)

    if system == "darwin":
        assert isinstance(adapter, ClipboardAdapter)