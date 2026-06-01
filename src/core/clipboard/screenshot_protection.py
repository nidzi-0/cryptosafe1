from __future__ import annotations

import platform


class ScreenshotProtectionError(Exception):
    """Ошибка защиты от скриншотов."""


class ScreenshotProtection:
    def __init__(self):
        self.enabled = False
        self.last_warning = ""

    def enable_for_window(self, window=None) -> bool:
        system = platform.system().lower()

        if system == "windows":
            return self._enable_windows(window)

        self.enabled = False
        self.last_warning = (
            "Anti-screenshot protection недоступна для текущей платформы "
            "в учебной реализации."
        )
        return False

    def disable_for_window(self, window=None) -> bool:
        system = platform.system().lower()

        if system == "windows":
            return self._disable_windows(window)

        self.enabled = False
        return True

    def _enable_windows(self, window=None) -> bool:
        try:
            import ctypes

            if window is None:
                self.enabled = False
                self.last_warning = "Не передан window handle."
                return False

            hwnd = None

            if hasattr(window, "winfo_id"):
                hwnd = int(window.winfo_id())
            else:
                hwnd = int(window)

            user32 = ctypes.windll.user32

            WDA_EXCLUDEFROMCAPTURE = 0x11

            result = user32.SetWindowDisplayAffinity(
                ctypes.c_void_p(hwnd),
                ctypes.c_uint(WDA_EXCLUDEFROMCAPTURE),
            )

            self.enabled = bool(result)
            return self.enabled
        except Exception as exc:
            self.enabled = False
            self.last_warning = str(exc)
            return False

    def _disable_windows(self, window=None) -> bool:
        try:
            import ctypes

            if window is None:
                self.enabled = False
                return True

            if hasattr(window, "winfo_id"):
                hwnd = int(window.winfo_id())
            else:
                hwnd = int(window)

            user32 = ctypes.windll.user32
            WDA_NONE = 0x0

            user32.SetWindowDisplayAffinity(
                ctypes.c_void_p(hwnd),
                ctypes.c_uint(WDA_NONE),
            )

            self.enabled = False
            return True
        except Exception:
            self.enabled = False
            return False

    def is_enabled(self) -> bool:
        return self.enabled