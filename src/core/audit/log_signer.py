from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class AuditSigningError(Exception):
    """Ошибка подписи audit log."""


@dataclass(frozen=True)
class SigningKeyInfo:
    algorithm: str
    public_key_hex: str


class AuditLogSigner:

    HKDF_SALT = b"CryptoSafe Manager Audit Log v1"
    HKDF_INFO = b"audit-signing"
    ED25519_KEY_SIZE = 32

    def __init__(
        self,
        master_key: bytes,
        algorithm: str = "ed25519",
    ):
        if not isinstance(master_key, bytes):
            raise AuditSigningError("master_key должен быть bytes.")

        if len(master_key) < 32:
            raise AuditSigningError("master_key должен быть не короче 32 байт.")

        self.algorithm = algorithm.lower().strip()
        self._signing_key = self._derive_signing_key(master_key)

        if self.algorithm == "ed25519":
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                self._signing_key
            )
            self._public_key = self._private_key.public_key()
        elif self.algorithm == "hmac-sha256":
            self._private_key = None
            self._public_key = None
        else:
            raise AuditSigningError("Поддерживаются только ed25519 и hmac-sha256.")

    def _derive_signing_key(self, master_key: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.ED25519_KEY_SIZE,
            salt=self.HKDF_SALT,
            info=self.HKDF_INFO,
        )

        return hkdf.derive(master_key)

    def sign(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise AuditSigningError("Данные для подписи должны быть bytes.")

        if self.algorithm == "ed25519":
            return self._private_key.sign(data)

        return hmac.new(
            self._signing_key,
            data,
            hashlib.sha256,
        ).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        if not isinstance(data, bytes) or not isinstance(signature, bytes):
            return False

        if self.algorithm == "ed25519":
            try:
                self._public_key.verify(signature, data)
                return True
            except InvalidSignature:
                return False
            except Exception:
                return False

        expected = hmac.new(
            self._signing_key,
            data,
            hashlib.sha256,
        ).digest()

        return hmac.compare_digest(expected, signature)

    def get_public_key_hex(self) -> str:
        if self.algorithm == "ed25519":
            public_key_bytes = self._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return public_key_bytes.hex()

        return ""

    def get_key_info(self) -> SigningKeyInfo:
        return SigningKeyInfo(
            algorithm=self.algorithm,
            public_key_hex=self.get_public_key_hex(),
        )