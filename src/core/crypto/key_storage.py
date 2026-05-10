from __future__ import annotations

import os
import sys
import time
import ctypes
import secrets
from dataclasses import dataclass
from typing import Optional


@dataclass
class CachedKey:
    key: bytearray
    created_at: float
    last_used_at: float


def wipe_bytearray(buf: bytearray) -> None:
    if not isinstance(buf, bytearray):
        raise TypeError("Ожидается bytearray")

    for i in range(len(buf)):
        buf[i] = secrets.randbelow(256)

    for i in range(len(buf)):
        buf[i] = 0


class ProtectedMemory:
    def __init__(self, buf: bytearray) -> None:
        self.buf = buf
        self.locked = False
        self.protected = False

    def lock(self) -> None:
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            try:
                libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else "libc.dylib")
                address = ctypes.addressof(ctypes.c_char.from_buffer(self.buf))
                size = len(self.buf)
                result = libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
                self.locked = result == 0
            except Exception:
                self.locked = False

    def unlock(self) -> None:
        if not self.locked:
            return

        if sys.platform.startswith("linux") or sys.platform == "darwin":
            try:
                libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else "libc.dylib")
                address = ctypes.addressof(ctypes.c_char.from_buffer(self.buf))
                size = len(self.buf)
                libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            except Exception:
                pass

        self.locked = False

    def protect(self) -> None:
        if self.protected:
            return

        if os.name == "nt":
            try:
                crypt32 = ctypes.windll.crypt32
                buffer_type = ctypes.c_char * len(self.buf)
                buffer = buffer_type.from_buffer(self.buf)

                CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
                ok = crypt32.CryptProtectMemory(
                    buffer,
                    len(self.buf),
                    CRYPTPROTECTMEMORY_SAME_PROCESS,
                )

                self.protected = bool(ok)
            except Exception:
                self.protected = False

    def unprotect(self) -> None:
        if not self.protected:
            return

        if os.name == "nt":
            try:
                crypt32 = ctypes.windll.crypt32
                buffer_type = ctypes.c_char * len(self.buf)
                buffer = buffer_type.from_buffer(self.buf)

                CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
                ok = crypt32.CryptUnprotectMemory(
                    buffer,
                    len(self.buf),
                    CRYPTPROTECTMEMORY_SAME_PROCESS,
                )

                if ok:
                    self.protected = False
            except Exception:
                pass


class KeyCache:
    def __init__(self, ttl_seconds: int = 3600, clear_on_focus_lost: bool = True) -> None:
        self.ttl_seconds = ttl_seconds
        self.clear_on_focus_lost = clear_on_focus_lost

        self._cached_key: Optional[CachedKey] = None
        self._protected_memory: Optional[ProtectedMemory] = None
        self._unlocked: bool = False
        self._app_active: bool = True

    def store_key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("Ключ шифрования должен иметь длину 32 байта")

        if not self._app_active:
            raise ValueError("Нельзя кэшировать ключ, пока приложение неактивно")

        self.clear()

        now = time.time()
        key_buffer = bytearray(key)

        self._protected_memory = ProtectedMemory(key_buffer)
        self._protected_memory.lock()
        self._protected_memory.protect()

        self._cached_key = CachedKey(
            key=key_buffer,
            created_at=now,
            last_used_at=now,
        )
        self._unlocked = True

    def get_key(self) -> bytes | None:
        if not self._unlocked:
            return None

        if not self._app_active:
            self.clear()
            return None

        if self._cached_key is None:
            return None

        if self.is_expired():
            self.clear()
            return None

        if self._protected_memory is not None:
            self._protected_memory.unprotect()

        key_copy = bytes(self._cached_key.key)

        if self._protected_memory is not None:
            self._protected_memory.protect()

        self._cached_key.last_used_at = time.time()
        return key_copy

    def is_unlocked(self) -> bool:
        return (
            self._unlocked
            and self._app_active
            and self._cached_key is not None
            and not self.is_expired()
        )

    def is_expired(self) -> bool:
        if self._cached_key is None:
            return True

        return (time.time() - self._cached_key.last_used_at) >= self.ttl_seconds

    def set_unlocked(self, unlocked: bool) -> None:
        if not unlocked:
            self.clear()
            return

        self._unlocked = True

    def set_app_active(self, active: bool) -> None:
        self._app_active = active

        if not active and self.clear_on_focus_lost:
            self.clear()

    def clear(self) -> None:
        if self._protected_memory is not None:
            self._protected_memory.unprotect()

        if self._cached_key is not None:
            wipe_bytearray(self._cached_key.key)

        if self._protected_memory is not None:
            self._protected_memory.unlock()

        self._protected_memory = None
        self._cached_key = None
        self._unlocked = False

    def on_focus_lost(self) -> None:
        self.set_app_active(False)

    def on_focus_restored(self) -> None:
        self._app_active = True

    def on_window_minimized(self) -> None:
        self.set_app_active(False)

    def on_logout(self) -> None:
        self.clear()

    def on_application_close(self) -> None:
        self.clear()

    def on_auto_lock(self) -> None:
        self.clear()