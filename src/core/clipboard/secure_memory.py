from __future__ import annotations

import ctypes
import os
import platform


class SecureMemoryError(Exception):
    """Ошибка защищённой памяти."""


class SecureMemoryBuffer:
    def __init__(self, data: bytes):
        if data is None:
            data = b""

        if not isinstance(data, bytes):
            data = bytes(data)

        self.size = len(data)
        self._closed = False
        self._locked = False

        self._buffer = ctypes.create_string_buffer(max(self.size, 1))

        if self.size:
            ctypes.memmove(self._buffer, data, self.size)

        self._address = ctypes.addressof(self._buffer)

        self._lock_memory()

    def _lock_memory(self) -> None:
        system = platform.system().lower()

        if system == "windows":
            self._lock_windows()
        else:
            self._lock_unix()

    def _unlock_memory(self) -> None:
        system = platform.system().lower()

        if system == "windows":
            self._unlock_windows()
        else:
            self._unlock_unix()

    def _lock_windows(self) -> None:
        try:
            kernel32 = ctypes.windll.kernel32
            result = kernel32.VirtualLock(
                ctypes.c_void_p(self._address),
                ctypes.c_size_t(max(self.size, 1)),
            )
            self._locked = bool(result)
        except Exception:
            self._locked = False

    def _unlock_windows(self) -> None:
        if not self._locked:
            return

        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualUnlock(
                ctypes.c_void_p(self._address),
                ctypes.c_size_t(max(self.size, 1)),
            )
        except Exception:
            pass

        self._locked = False

    def _lock_unix(self) -> None:
        if os.name == "nt":
            return

        try:
            libc = ctypes.CDLL(None)
            result = libc.mlock(
                ctypes.c_void_p(self._address),
                ctypes.c_size_t(max(self.size, 1)),
            )
            self._locked = result == 0
        except Exception:
            self._locked = False

    def _unlock_unix(self) -> None:
        if not self._locked:
            return

        try:
            libc = ctypes.CDLL(None)
            libc.munlock(
                ctypes.c_void_p(self._address),
                ctypes.c_size_t(max(self.size, 1)),
            )
        except Exception:
            pass

        self._locked = False

    def read(self) -> bytes:
        if self._closed:
            return b""

        if self.size <= 0:
            return b""

        return ctypes.string_at(self._address, self.size)

    def write(self, data: bytes) -> None:
        if self._closed:
            raise SecureMemoryError("Буфер уже очищен.")

        if not isinstance(data, bytes):
            data = bytes(data)

        if len(data) > self.size:
            raise SecureMemoryError("Новые данные больше размера буфера.")

        self.zero()

        if data:
            ctypes.memmove(self._buffer, data, len(data))

    def zero(self) -> None:
        if self._closed:
            return

        ctypes.memset(
            ctypes.c_void_p(self._address),
            0,
            max(self.size, 1),
        )

    def close(self) -> None:
        if self._closed:
            return

        self.zero()
        self._unlock_memory()
        self._closed = True

    def is_locked(self) -> bool:
        return self._locked

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass