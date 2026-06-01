from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionError(Exception):
    """Базовая ошибка сервиса шифрования."""


class VaultDecryptionError(VaultEncryptionError):
    """Ошибка расшифровки данных."""


class InvalidEncryptionKeyError(VaultEncryptionError):
    """Ошибка некорректного ключа шифрования."""


@runtime_checkable
class KeyManagerProtocol(Protocol):
    def get_encryption_key(self) -> bytes:
        ...


class AESGCMEncryptionService:
    NONCE_SIZE = 12
    KEY_SIZE = 32
    CURRENT_VERSION = 1

    def __init__(self, key_source: bytes | KeyManagerProtocol):
        self.key_source = key_source

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _get_key(self) -> bytes:
        if isinstance(self.key_source, bytes):
            key = self.key_source
        elif isinstance(self.key_source, KeyManagerProtocol):
            key = self.key_source.get_encryption_key()
        else:
            raise InvalidEncryptionKeyError(
                "Источник ключа должен быть bytes или KeyManager "
                "с методом get_encryption_key()."
            )

        self._validate_key(key)

        return key

    def _get_aesgcm(self) -> AESGCM:
        return AESGCM(self._get_key())

    def _validate_key(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise InvalidEncryptionKeyError("Ключ шифрования должен быть bytes.")

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

        ciphertext = self._get_aesgcm().encrypt(
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
            raise VaultDecryptionError("Зашифрованные данные должны быть bytes.")

        if len(encrypted_data) <= self.NONCE_SIZE:
            raise VaultDecryptionError(
                "Зашифрованные данные повреждены или слишком короткие."
            )

        nonce = encrypted_data[: self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE :]

        try:
            plaintext = self._get_aesgcm().decrypt(
                nonce,
                ciphertext,
                None,
            )
        except InvalidTag as exc:
            raise VaultDecryptionError(
                "Не удалось расшифровать данные. "
                "Возможно, неверный ключ или данные повреждены."
            ) from exc
        except Exception as exc:
            raise VaultDecryptionError(f"Ошибка расшифровки данных: {exc}") from exc

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VaultDecryptionError(
                "Расшифрованные данные имеют неверную кодировку."
            ) from exc

    def encrypt_entry(self, entry_data: dict[str, Any]) -> bytes:
        created_at = entry_data.get("created_at") or self._now()

        shared_metadata = entry_data.get("shared_metadata", {})

        if shared_metadata is None:
            shared_metadata = {}

        if not isinstance(shared_metadata, dict):
            shared_metadata = {
                "raw": str(shared_metadata),
            }

        package = {
            "version": self.CURRENT_VERSION,
            "created_at": str(created_at),

            # Основные поля Sprint 3
            "title": str(entry_data.get("title", "")),
            "username": str(entry_data.get("username", "")),
            "password": str(entry_data.get("password", "")),
            "url": str(entry_data.get("url", "")),
            "notes": str(entry_data.get("notes", "")),
            "category": str(entry_data.get("category", "")),
            "tags": str(entry_data.get("tags", "")),

            # FUTURE-1: поля для будущих спринтов
            "totp_secret": str(entry_data.get("totp_secret", "")),
            "shared_metadata": shared_metadata,
        }

        json_payload = json.dumps(
            package,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        return self.encrypt(json_payload)

    def decrypt_entry(self, encrypted_data: bytes) -> dict[str, Any]:
        json_payload = self.decrypt(encrypted_data)

        try:
            package = json.loads(json_payload)
        except json.JSONDecodeError as exc:
            raise VaultDecryptionError(
                "Расшифрованный пакет записи не является корректным JSON."
            ) from exc

        if not isinstance(package, dict):
            raise VaultDecryptionError(
                "Расшифрованный пакет записи должен быть JSON-объектом."
            )

        version = package.get("version")

        if version != self.CURRENT_VERSION:
            raise VaultDecryptionError(
                f"Неподдерживаемая версия пакета записи: {version}."
            )

        return package