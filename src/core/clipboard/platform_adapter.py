from __future__ import annotations

import platform
import shutil
import subprocess
from abc import ABC, abstractmethod


class ClipboardAdapterError(Exception):
    """Базовая ошибка платформенного адаптера буфера обмена."""


class ClipboardAdapter(ABC):
    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        pass

    @abstractmethod
    def clear_clipboard(self) -> bool:
        pass

    @abstractmethod
    def get_clipboard_content(self) -> str:
        pass


class WindowsClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        try:
            import win32clipboard
        except Exception as exc:
            raise ClipboardAdapterError(
                "win32clipboard недоступен. Установите pywin32 или используйте fallback."
            ) from exc

        self.win32clipboard = win32clipboard

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.SetClipboardText(
                str(data or ""),
                self.win32clipboard.CF_UNICODETEXT,
            )
            self.win32clipboard.CloseClipboard()
            return True
        except Exception:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass
            return False

    def clear_clipboard(self) -> bool:
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.CloseClipboard()
            return True
        except Exception:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass
            return False

    def get_clipboard_content(self) -> str:
        try:
            self.win32clipboard.OpenClipboard()

            if not self.win32clipboard.IsClipboardFormatAvailable(
                self.win32clipboard.CF_UNICODETEXT
            ):
                self.win32clipboard.CloseClipboard()
                return ""

            data = self.win32clipboard.GetClipboardData(
                self.win32clipboard.CF_UNICODETEXT
            )
            self.win32clipboard.CloseClipboard()

            return str(data or "")
        except Exception:
            try:
                self.win32clipboard.CloseClipboard()
            except Exception:
                pass
            return ""


class MacOSPyObjCClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        try:
            from AppKit import NSPasteboard, NSPasteboardTypeString
        except Exception as exc:
            raise ClipboardAdapterError(
                "pyobjc/AppKit недоступен. Установите pyobjc или используйте fallback."
            ) from exc

        self.NSPasteboard = NSPasteboard
        self.NSPasteboardTypeString = NSPasteboardTypeString
        self.pasteboard = NSPasteboard.generalPasteboard()

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.pasteboard.clearContents()
            self.pasteboard.declareTypes_owner_(
                [self.NSPasteboardTypeString],
                None,
            )
            return bool(
                self.pasteboard.setString_forType_(
                    str(data or ""),
                    self.NSPasteboardTypeString,
                )
            )
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self.pasteboard.clearContents()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> str:
        try:
            value = self.pasteboard.stringForType_(self.NSPasteboardTypeString)
            return str(value or "")
        except Exception:
            return ""


class MacOSCommandClipboardAdapter(ClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        try:
            process = subprocess.Popen(
                ["pbcopy"],
                stdin=subprocess.PIPE,
                text=True,
            )
            process.communicate(str(data or ""), timeout=2)
            return process.returncode == 0
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> str:
        try:
            result = subprocess.run(
                ["pbpaste"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            return result.stdout or ""
        except Exception:
            return ""


class LinuxClipboardAdapter(ClipboardAdapter):
    VALID_SELECTIONS = {"clipboard", "primary"}

    def __init__(self, selection: str = "clipboard"):
        selection = selection.lower().strip()

        if selection not in self.VALID_SELECTIONS:
            raise ClipboardAdapterError(
                "Linux selection должен быть 'clipboard' или 'primary'."
            )

        self.selection = selection

    def copy_to_clipboard(self, data: str) -> bool:
        data = str(data or "")
        if self.selection == "clipboard":
            if self._copy_with_wl_clipboard(data):
                return True

        if self._copy_with_xclip(data):
            return True

        if self._copy_with_xsel(data):
            return True

        return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> str:
        if self.selection == "clipboard":
            value = self._paste_with_wl_clipboard()

            if value is not None:
                return value

        value = self._paste_with_xclip()

        if value is not None:
            return value

        value = self._paste_with_xsel()

        if value is not None:
            return value

        return ""

    def _copy_with_wl_clipboard(self, data: str) -> bool:
        if shutil.which("wl-copy") is None:
            return False

        try:
            process = subprocess.Popen(
                ["wl-copy"],
                stdin=subprocess.PIPE,
                text=True,
            )
            process.communicate(data, timeout=2)
            return process.returncode == 0
        except Exception:
            return False

    def _paste_with_wl_clipboard(self) -> str | None:
        if shutil.which("wl-paste") is None:
            return None

        try:
            result = subprocess.run(
                ["wl-paste"],
                capture_output=True,
                text=True,
                timeout=2,
            )

            if result.returncode == 0:
                return result.stdout or ""

            return None
        except Exception:
            return None

    def _copy_with_xclip(self, data: str) -> bool:
        if shutil.which("xclip") is None:
            return False

        selection_arg = "clipboard" if self.selection == "clipboard" else "primary"

        try:
            process = subprocess.Popen(
                ["xclip", "-selection", selection_arg],
                stdin=subprocess.PIPE,
                text=True,
            )
            process.communicate(data, timeout=2)
            return process.returncode == 0
        except Exception:
            return False

    def _paste_with_xclip(self) -> str | None:
        if shutil.which("xclip") is None:
            return None

        selection_arg = "clipboard" if self.selection == "clipboard" else "primary"

        try:
            result = subprocess.run(
                ["xclip", "-selection", selection_arg, "-o"],
                capture_output=True,
                text=True,
                timeout=2,
            )

            if result.returncode == 0:
                return result.stdout or ""

            return None
        except Exception:
            return None

    def _copy_with_xsel(self, data: str) -> bool:
        if shutil.which("xsel") is None:
            return False

        if self.selection == "clipboard":
            command = ["xsel", "--clipboard", "--input"]
        else:
            command = ["xsel", "--primary", "--input"]

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                text=True,
            )
            process.communicate(data, timeout=2)
            return process.returncode == 0
        except Exception:
            return False

    def _paste_with_xsel(self) -> str | None:
        if shutil.which("xsel") is None:
            return None

        if self.selection == "clipboard":
            command = ["xsel", "--clipboard", "--output"]
        else:
            command = ["xsel", "--primary", "--output"]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=2,
            )

            if result.returncode == 0:
                return result.stdout or ""

            return None
        except Exception:
            return None


class PyperclipClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        try:
            import pyperclip
        except Exception as exc:
            raise ClipboardAdapterError(
                "pyperclip недоступен. Установите pyperclip или используйте tkinter fallback."
            ) from exc

        self.pyperclip = pyperclip

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.pyperclip.copy(str(data or ""))
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> str:
        try:
            return str(self.pyperclip.paste() or "")
        except Exception:
            return ""


class TkinterClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        self._last_value = ""

    def copy_to_clipboard(self, data: str) -> bool:
        self._last_value = str(data or "")

        try:
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(self._last_value)
            root.update()
            root.destroy()
            return True
        except Exception:
            return True

    def clear_clipboard(self) -> bool:
        self._last_value = ""

        try:
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.update()
            root.destroy()
            return True
        except Exception:
            return True

    def get_clipboard_content(self) -> str:
        try:
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
            value = root.clipboard_get()
            root.destroy()
            return str(value or "")
        except Exception:
            return self._last_value


# Оставляем старое имя для совместимости с уже написанными импортами.
FallbackClipboardAdapter = PyperclipClipboardAdapter


def create_fallback_clipboard_adapter() -> ClipboardAdapter:
    try:
        return PyperclipClipboardAdapter()
    except Exception:
        return TkinterClipboardAdapter()


def create_platform_clipboard_adapter() -> ClipboardAdapter:
    system = platform.system().lower()

    if system == "windows":
        try:
            return WindowsClipboardAdapter()
        except Exception:
            return create_fallback_clipboard_adapter()

    if system == "darwin":
        try:
            return MacOSPyObjCClipboardAdapter()
        except Exception:
            try:
                return MacOSCommandClipboardAdapter()
            except Exception:
                return create_fallback_clipboard_adapter()

    if system == "linux":
        try:
            return LinuxClipboardAdapter(selection="clipboard")
        except Exception:
            return create_fallback_clipboard_adapter()

    return create_fallback_clipboard_adapter()