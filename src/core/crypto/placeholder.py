from __future__ import annotations

from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    def __init__(self, key_manager) -> None:
        self.key_manager = key_manager

    def encrypt(self, data: bytes) -> bytes:
        key = self._get_key()
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes) -> bytes:
        key = self._get_key()
        return self._xor(ciphertext, key)

    def _get_key(self) -> bytes:
        if hasattr(self.key_manager, "get_encryption_key"):
            key = self.key_manager.get_encryption_key()
        elif hasattr(self.key_manager, "get_active_key"):
            key = self.key_manager.get_active_key()
        elif hasattr(self.key_manager, "get_key"):
            key = self.key_manager.get_key()
        else:
            raise ValueError("Менеджер ключей не поддерживает получение ключа шифрования")

        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("Ключ шифрования недоступен")

        return bytes(key)

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("данные должны быть типа bytes или bytearray")

        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("ключ должен быть непустым и иметь тип bytes или bytearray")

        out = bytearray(len(data))

        for i, b in enumerate(data):
            out[i] = b ^ key[i % len(key)]

        return bytes(out)