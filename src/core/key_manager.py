from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class KeyDerivationParams:
    iterations: int = 200_000


class KeyManager:
    def derive_key(self, password: str, salt: bytes, params: KeyDerivationParams | None = None) -> bytes:
        if params is None:
            params = KeyDerivationParams()

        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Пароль должен быть строкой длиной не менее 8 символов")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("Соль должна иметь тип bytes или bytearray и длину не менее 16 байт")

        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes(salt), params.iterations, dklen=32)

    def store_key(self) -> None:
        raise NotImplementedError("Заглушка")

    def load_key(self) -> None:
        raise NotImplementedError("Заглушка")


def generate_salt(n: int = 16) -> bytes:
    return os.urandom(n)