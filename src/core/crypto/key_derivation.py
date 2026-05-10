from __future__ import annotations

import os
import re
import secrets
import hashlib
import base64
from dataclasses import dataclass
from typing import Dict, List

from argon2 import PasswordHasher, Type
from argon2.low_level import hash_secret_raw


@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16


@dataclass(frozen=True)
class PBKDF2Params:
    iterations: int = 100_000
    salt_len: int = 16
    key_len: int = 32


@dataclass(frozen=True)
class PasswordValidationResult:
    valid: bool
    errors: List[str]


COMMON_WEAK_PATTERNS = {
    "password",
    "password123",
    "qwerty",
    "qwerty123",
    "123456",
    "123456789",
    "admin",
    "admin123",
    "letmein",
    "welcome",
}


class PasswordPolicy:
    def __init__(self, min_length: int = 12) -> None:
        self.min_length = min_length

    def validate(self, password: str) -> PasswordValidationResult:
        errors: List[str] = []

        if not isinstance(password, str):
            return PasswordValidationResult(False, ["Пароль должен быть строкой"])

        if len(password) < self.min_length:
            errors.append(f"Минимальная длина пароля: {self.min_length} символов")

        if not re.search(r"[A-ZА-Я]", password):
            errors.append("Пароль должен содержать заглавную букву")

        if not re.search(r"[a-zа-я]", password):
            errors.append("Пароль должен содержать строчную букву")

        if not re.search(r"\d", password):
            errors.append("Пароль должен содержать цифру")

        if not re.search(r"[^A-Za-zА-Яа-я0-9]", password):
            errors.append("Пароль должен содержать специальный символ")

        normalized = password.lower()

        for pattern in COMMON_WEAK_PATTERNS:
            if pattern in normalized:
                errors.append("Пароль содержит распространённый слабый шаблон")
                break

        return PasswordValidationResult(valid=len(errors) == 0, errors=errors)


class KeyDerivationManager:
    def __init__(
        self,
        argon2_params: Argon2Params | None = None,
        pbkdf2_params: PBKDF2Params | None = None,
    ) -> None:
        self.argon2_params = argon2_params or Argon2Params()
        self.pbkdf2_params = pbkdf2_params or PBKDF2Params()
        self._validate_params()

        self.argon2_hasher = PasswordHasher(
            time_cost=self.argon2_params.time_cost,
            memory_cost=self.argon2_params.memory_cost,
            parallelism=self.argon2_params.parallelism,
            hash_len=self.argon2_params.hash_len,
            salt_len=self.argon2_params.salt_len,
            type=Type.ID,
        )

    def _validate_params(self) -> None:
        if self.argon2_params.time_cost < 3:
            raise ValueError("time_cost Argon2 должен быть не меньше 3")

        if self.argon2_params.memory_cost < 65536:
            raise ValueError("memory_cost Argon2 должен быть не меньше 65536 KiB")

        if self.argon2_params.memory_cost > 262144:
            raise ValueError("memory_cost Argon2 слишком большой")

        if self.argon2_params.parallelism < 1 or self.argon2_params.parallelism > 8:
            raise ValueError("parallelism Argon2 должен быть от 1 до 8")

        if self.argon2_params.hash_len != 32:
            raise ValueError("hash_len Argon2 должен быть равен 32 байтам")

        if self.argon2_params.salt_len < 16:
            raise ValueError("salt_len Argon2 должен быть не меньше 16 байт")

        if self.pbkdf2_params.iterations < 100_000:
            raise ValueError("iterations PBKDF2 должен быть не меньше 100000")

        if self.pbkdf2_params.salt_len < 16:
            raise ValueError("salt_len PBKDF2 должен быть не меньше 16 байт")

        if self.pbkdf2_params.key_len != 32:
            raise ValueError("key_len PBKDF2 должен быть равен 32 байтам")

    def create_auth_hash(self, password: str) -> str:
        return self.argon2_hasher.hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            params = self._parse_argon2_hash(stored_hash)

            calculated_hash = hash_secret_raw(
                secret=password.encode("utf-8"),
                salt=params["salt"],
                time_cost=params["time_cost"],
                memory_cost=params["memory_cost"],
                parallelism=params["parallelism"],
                hash_len=len(params["hash"]),
                type=Type.ID,
            )

            return secrets.compare_digest(calculated_hash, params["hash"])

        except Exception:
            dummy_actual = hash_secret_raw(
                secret=b"dummy-password",
                salt=b"0" * 16,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID,
            )
            dummy_expected = b"0" * 32
            secrets.compare_digest(dummy_actual, dummy_expected)
            return False

    @staticmethod
    def _decode_argon2_base64(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding)

    def _parse_argon2_hash(self, stored_hash: str) -> dict:
        parts = stored_hash.split("$")

        if len(parts) != 6:
            raise ValueError("Некорректный формат Argon2-хэша")

        algorithm = parts[1]

        if algorithm != "argon2id":
            raise ValueError("Ожидался Argon2id")

        params_part = parts[3]
        salt_part = parts[4]
        hash_part = parts[5]

        parsed_params = {}

        for item in params_part.split(","):
            key, value = item.split("=")
            parsed_params[key] = int(value)

        return {
            "time_cost": parsed_params["t"],
            "memory_cost": parsed_params["m"],
            "parallelism": parsed_params["p"],
            "salt": self._decode_argon2_base64(salt_part),
            "hash": self._decode_argon2_base64(hash_part),
        }

    def generate_encryption_salt(self) -> bytes:
        return os.urandom(self.pbkdf2_params.salt_len)

    def derive_key(
        self,
        password: str,
        salt: bytes,
        purpose: str = "encryption",
    ) -> bytes:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль должен быть непустой строкой")

        if not isinstance(salt, (bytes, bytearray)) or len(salt) < self.pbkdf2_params.salt_len:
            raise ValueError("Соль PBKDF2 должна быть байтами длиной не менее 16")

        allowed_purposes = {
            "encryption",
            "audit",
            "export",
            "totp",
        }

        if purpose not in allowed_purposes:
            raise ValueError(f"Неизвестный тип ключа: {purpose}")

        purpose_bytes = purpose.encode("utf-8")

        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8") + purpose_bytes,
            bytes(salt),
            self.pbkdf2_params.iterations,
            dklen=self.pbkdf2_params.key_len,
        )

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        return self.derive_key(password, salt, purpose="encryption")

    def export_params(self) -> Dict[str, int | str]:
        return {
            "argon2_time_cost": self.argon2_params.time_cost,
            "argon2_memory_cost": self.argon2_params.memory_cost,
            "argon2_parallelism": self.argon2_params.parallelism,
            "argon2_hash_len": self.argon2_params.hash_len,
            "argon2_salt_len": self.argon2_params.salt_len,
            "pbkdf2_iterations": self.pbkdf2_params.iterations,
            "pbkdf2_salt_len": self.pbkdf2_params.salt_len,
            "pbkdf2_key_len": self.pbkdf2_params.key_len,
            "supported_key_purposes": "encryption,audit,export,totp",
        }