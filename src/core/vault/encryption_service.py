from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionError(Exception):
    """Базовая ошибка сервиса шифрования."""


class VaultDecryptionError(VaultEncryptionError):
    """Ошибка расшифровки данных."""


class InvalidEncryptionKeyError(VaultEncryptionError):
    """Ошибка некорректного ключа шифрования."""


class AESGCMEncryptionService:
    """
    Сервис шифрования AES-256-GCM.

    Формат хранения:
        nonce + ciphertext

    nonce — 12 байт.
    ciphertext — зашифрованные данные вместе с authentication tag.
    """

    NONCE_SIZE = 12
    KEY_SIZE = 32

    def __init__(self, key: bytes):
        self._validate_key(key)
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def _validate_key(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise InvalidEncryptionKeyError(
                "Ключ шифрования должен быть bytes."
            )

        if len(key) != self.KEY_SIZE:
            raise InvalidEncryptionKeyError(
                f"Ключ шифрования должен быть длиной {self.KEY_SIZE} байта."
            )

    def encrypt(self, plaintext: str | bytes) -> bytes:
        if plaintext is None:
            plaintext = ""

        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        elif isinstance(plaintext, bytes):
            plaintext_bytes = plaintext
        else:
            plaintext_bytes = str(plaintext).encode("utf-8")

        nonce = os.urandom(self.NONCE_SIZE)

        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext_bytes,
            None,
        )

        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> str:
        if encrypted_data is None:
            return ""

        if isinstance(encrypted_data, memoryview):
            encrypted_data = encrypted_data.tobytes()

        if not isinstance(encrypted_data, bytes):
            raise VaultDecryptionError(
                "Зашифрованные данные должны быть bytes."
            )

        if len(encrypted_data) <= self.NONCE_SIZE:
            raise VaultDecryptionError(
                "Зашифрованные данные повреждены или слишком короткие."
            )

        nonce = encrypted_data[: self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE :]

        try:
            plaintext = self.aesgcm.decrypt(
                nonce,
                ciphertext,
                None,
            )
        except InvalidTag as exc:
            raise VaultDecryptionError(
                "Не удалось расшифровать данные. "
                "Возможно, неверный мастер-пароль или данные повреждены."
            ) from exc
        except Exception as exc:
            raise VaultDecryptionError(
                f"Ошибка расшифровки данных: {exc}"
            ) from exc

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VaultDecryptionError(
                "Расшифрованные данные имеют неверную кодировку."
            ) from exc