from __future__ import annotations


class KeyManagerError(Exception):
    """Базовая ошибка менеджера ключей."""


class EncryptionKeyNotAvailableError(KeyManagerError):
    """Ошибка, если ключ шифрования недоступен."""


class InvalidEncryptionKeyError(KeyManagerError):
    """Ошибка некорректного ключа шифрования."""


class CachedKeyManager:
    KEY_SIZE = 32

    def __init__(self, encryption_key: bytes | None = None):
        self._encryption_key: bytes | None = None

        if encryption_key is not None:
            self.set_encryption_key(encryption_key)

    def set_encryption_key(self, encryption_key: bytes) -> None:
        self._validate_key(encryption_key)
        self._encryption_key = encryption_key

    def get_encryption_key(self) -> bytes:
        if self._encryption_key is None:
            raise EncryptionKeyNotAvailableError(
                "Ключ шифрования недоступен. Хранилище не разблокировано."
            )

        return self._encryption_key

    def clear_encryption_key(self) -> None:
        self._encryption_key = None

    def is_unlocked(self) -> bool:
        return self._encryption_key is not None

    def _validate_key(self, encryption_key: bytes) -> None:
        if not isinstance(encryption_key, bytes):
            raise InvalidEncryptionKeyError(
                "Ключ шифрования должен быть bytes."
            )

        if len(encryption_key) != self.KEY_SIZE:
            raise InvalidEncryptionKeyError(
                f"Ключ шифрования должен быть длиной {self.KEY_SIZE} байта."
            )