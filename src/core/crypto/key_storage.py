from __future__ import annotations

import time
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
        raise TypeError("Ожидается объект типа bytearray")

    for i in range(len(buf)):
        buf[i] = secrets.randbelow(256)

    for i in range(len(buf)):
        buf[i] = 0


class KeyCache:
    def __init__(self, ttl_seconds: int = 3600, clear_on_focus_lost: bool = True) -> None:
        self.ttl_seconds = ttl_seconds
        self.clear_on_focus_lost = clear_on_focus_lost
        self._cached_key: Optional[CachedKey] = None
        self._unlocked: bool = False

    def store_key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("Ключ шифрования должен иметь длину 32 байта")

        now = time.time()
        self._cached_key = CachedKey(
            key=bytearray(key),
            created_at=now,
            last_used_at=now,
        )
        self._unlocked = True

    def get_key(self) -> bytes | None:
        if self._cached_key is None or not self._unlocked:
            return None

        if self.is_expired():
            self.clear()
            return None

        self._cached_key.last_used_at = time.time()
        return bytes(self._cached_key.key)

    def is_unlocked(self) -> bool:
        return self._unlocked and self._cached_key is not None and not self.is_expired()

    def is_expired(self) -> bool:
        if self._cached_key is None:
            return True

        return (time.time() - self._cached_key.last_used_at) >= self.ttl_seconds

    def clear(self) -> None:
        if self._cached_key is not None:
            wipe_bytearray(self._cached_key.key)

        self._cached_key = None
        self._unlocked = False

    def on_focus_lost(self) -> None:
        if self.clear_on_focus_lost:
            self.clear()

    def on_logout(self) -> None:
        self.clear()

    def on_application_close(self) -> None:
        self.clear()

    def on_auto_lock(self) -> None:
        self.clear()


class OSKeychainStorage:
    def __init__(self, service_name: str = "CryptoSafeManager") -> None:
        self.service_name = service_name
        self._file_fallback: dict[str, str] = {}

    def store_secret(self, username: str, secret: str) -> bool:
        try:
            import keyring

            keyring.set_password(self.service_name, username, secret)
            return True
        except Exception:
            self._file_fallback[username] = secret
            return False

    def load_secret(self, username: str) -> str | None:
        try:
            import keyring

            value = keyring.get_password(self.service_name, username)
            if value is not None:
                return value
        except Exception:
            pass

        return self._file_fallback.get(username)

    def delete_secret(self, username: str) -> None:
        try:
            import keyring

            keyring.delete_password(self.service_name, username)
        except Exception:
            pass

        self._file_fallback.pop(username, None)