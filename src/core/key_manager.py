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
            raise ValueError("Password must be a string with length >= 8")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("Salt must be bytes (>=16)")

        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes(salt), params.iterations, dklen=32)

    def store_key(self) -> None:
        raise NotImplementedError("Sprint 1 placeholder")

    def load_key(self) -> None:
        raise NotImplementedError("Sprint 1 placeholder")


def generate_salt(n: int = 16) -> bytes:
    return os.urandom(n)