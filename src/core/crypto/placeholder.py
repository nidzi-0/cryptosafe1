from __future__ import annotations

from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    def __init__(self, key_manager_or_key=None) -> None:
        self.key_manager = None
        self.key = None

        if isinstance(key_manager_or_key, (bytes, bytearray)):
            self.key = bytes(key_manager_or_key)
        elif key_manager_or_key is not None:
            self.key_manager = key_manager_or_key
        else:
            self.key = b"cryptosafe-placeholder-key-32!!"[:32]

    def _get_key(self) -> bytes:
        if self.key_manager is not None:
            if hasattr(self.key_manager, "get_encryption_key"):
                return self.key_manager.get_encryption_key()
            if hasattr(self.key_manager, "get_key"):
                return self.key_manager.get_key()
            if hasattr(self.key_manager, "key"):
                return self.key_manager.key

            raise ValueError("Unsupported key manager")

        if not self.key:
            raise ValueError("Encryption key is empty")

        return self.key

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        key = self._get_key()
        if not key:
            raise ValueError("Encryption key is empty")

        return bytes(
            byte ^ key[index % len(key)]
            for index, byte in enumerate(data)
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        return self.encrypt(ciphertext)