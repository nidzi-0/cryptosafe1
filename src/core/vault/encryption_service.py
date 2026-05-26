from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionService:
    VERSION = 1
    NONCE_SIZE = 12

    def __init__(self, key_manager) -> None:
        self.key_manager = key_manager

    def _get_key(self) -> bytes:
        key = self.key_manager.get_encryption_key()

        if key is None:
            raise ValueError("Хранилище заблокировано")

        if len(key) != 32:
            raise ValueError("Ключ AES-256 должен быть 32 байта")

        return key

    def encrypt_entry(self, data: dict) -> bytes:
        key = self._get_key()
        aesgcm = AESGCM(key)

        nonce = os.urandom(self.NONCE_SIZE)

        payload = {
            "title": data.get("title", ""),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "url": data.get("url", ""),
            "notes": data.get("notes", ""),
            "category": data.get("category", ""),
            "totp_secret": data.get("totp_secret", ""),
            "share_metadata": data.get("share_metadata", {}),
            "created_at": data.get("created_at") or datetime.now(timezone.utc).isoformat(),
            "version": self.VERSION,
        }

        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return nonce + ciphertext

    def decrypt_entry(self, encrypted_blob: bytes) -> dict:
        if not encrypted_blob or len(encrypted_blob) <= self.NONCE_SIZE:
            raise ValueError("Некорректные зашифрованные данные")

        key = self._get_key()
        aesgcm = AESGCM(key)

        nonce = encrypted_blob[:self.NONCE_SIZE]
        ciphertext = encrypted_blob[self.NONCE_SIZE:]

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode("utf-8"))