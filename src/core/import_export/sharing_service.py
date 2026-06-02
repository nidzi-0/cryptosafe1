import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SharingServiceError(Exception):
    pass


class SharingService:
    SALT_SIZE = 16
    NONCE_SIZE = 12
    AES_KEY_SIZE = 32
    HMAC_KEY_SIZE = 32
    PBKDF2_ITERATIONS = 100_000
    MIN_EXPIRATION_DAYS = 1
    MAX_EXPIRATION_DAYS = 30

    def __init__(
        self,
        db_connection: Any,
        crypto_service: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        sharer: str = "local_user",
        sender_private_key: Optional[Any] = None,
        sender_public_key: Optional[Union[bytes, Any]] = None,
    ):
        self.db = db_connection
        self.crypto = crypto_service
        self.audit_logger = audit_logger
        self.sharer = sharer

        if sender_private_key is not None:
            self.sender_private_key = sender_private_key
            self.sender_public_key = sender_private_key.public_key()
        elif sender_public_key is not None:
            self.sender_private_key = None
            self.sender_public_key = self._load_public_key(sender_public_key)
        else:
            self.sender_private_key = ec.generate_private_key(ec.SECP256R1())
            self.sender_public_key = self.sender_private_key.public_key()

    def share_entry(
        self,
        entry_id: str,
        recipient: str,
        permissions: Dict[str, Any],
        expires_in: int = 7,
        password: Optional[str] = None,
        public_key: Optional[Union[bytes, Any]] = None,
        encryption_method: str = "password",
    ) -> Dict[str, Any]:
        if public_key is not None:
            return self.share_entry_with_public_key(
                entry_id=entry_id,
                recipient=recipient,
                public_key=public_key,
                permissions=permissions,
                expires_in=expires_in,
            )

        if password is not None:
            return self.share_entry_with_password(
                entry_id=entry_id,
                recipient=recipient,
                password=password,
                permissions=permissions,
                expires_in=expires_in,
            )

        entry = self._get_entry(entry_id)
        expires_at = self._build_expiration(expires_in)
        permissions = self._normalize_permissions(permissions)
        share_id = str(uuid.uuid4())

        package = self._create_plain_package(
            entry=entry,
            share_id=share_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
        )

        self._store_share_record(
            share_id=share_id,
            entry_id=entry_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
            encryption_method="none",
            package_checksum=self._package_checksum(package),
        )

        self._audit(
            "share_created",
            {
                "entry_id": entry_id,
                "recipient": recipient,
                "share_id": share_id,
                "encryption_method": "none",
            },
        )

        return {
            "share_id": share_id,
            "package": package,
            "expires_at": expires_at.isoformat(),
            "permissions": permissions,
            "encryption_method": "none",
        }

    def share_entry_with_password(
        self,
        entry_id: str,
        recipient: str,
        password: str,
        permissions: Dict[str, Any],
        expires_in: int = 7,
    ) -> Dict[str, Any]:
        if not password:
            raise SharingServiceError("Share password is required")

        entry = self._get_entry(entry_id)
        expires_at = self._build_expiration(expires_in)
        permissions = self._normalize_permissions(permissions)
        share_id = str(uuid.uuid4())

        plain_package = self._create_plain_package(
            entry=entry,
            share_id=share_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
        )

        encrypted_package = self._encrypt_package_with_password(
            package=plain_package,
            password=password,
        )

        self._store_share_record(
            share_id=share_id,
            entry_id=entry_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
            encryption_method="password",
            package_checksum=self._package_checksum(encrypted_package),
        )

        self._audit(
            "share_created",
            {
                "entry_id": entry_id,
                "recipient": recipient,
                "share_id": share_id,
                "encryption_method": "password",
            },
        )

        return {
            "share_id": share_id,
            "package": encrypted_package,
            "expires_at": expires_at.isoformat(),
            "permissions": permissions,
            "encryption_method": "password",
        }

    def share_entry_with_public_key(
        self,
        entry_id: str,
        recipient: str,
        public_key: Union[bytes, Any],
        permissions: Dict[str, Any],
        expires_in: int = 7,
    ) -> Dict[str, Any]:
        entry = self._get_entry(entry_id)
        expires_at = self._build_expiration(expires_in)
        permissions = self._normalize_permissions(permissions)
        share_id = str(uuid.uuid4())

        public_key_obj = self._load_public_key(public_key)

        plain_package = self._create_plain_package(
            entry=entry,
            share_id=share_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
        )

        encrypted_package = self._encrypt_package_with_public_key(
            package=plain_package,
            public_key=public_key_obj,
        )

        encryption_method = encrypted_package["encryption"]["method"]

        self._store_share_record(
            share_id=share_id,
            entry_id=entry_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
            encryption_method=encryption_method,
            package_checksum=self._package_checksum(encrypted_package),
        )

        self._audit(
            "share_created",
            {
                "entry_id": entry_id,
                "recipient": recipient,
                "share_id": share_id,
                "encryption_method": encryption_method,
            },
        )

        return {
            "share_id": share_id,
            "package": encrypted_package,
            "expires_at": expires_at.isoformat(),
            "permissions": permissions,
            "encryption_method": encryption_method,
        }

    def decrypt_shared_package_with_password(
        self,
        package: Dict[str, Any],
        password: str,
    ) -> Dict[str, Any]:
        if not password:
            raise SharingServiceError("Share password is required")

        self._validate_encrypted_package(package)

        encryption = package["encryption"]

        if encryption.get("method") != "password":
            raise SharingServiceError("Package is not encrypted with password")

        try:
            salt = self._b64d(encryption["salt"])
            nonce = self._b64d(encryption["nonce"])
            ciphertext = self._b64d(package["data"])
        except Exception as exc:
            raise SharingServiceError("Invalid encrypted package encoding") from exc

        self._verify_ciphertext_hash(package, ciphertext)

        aes_key, hmac_key = self._derive_password_keys(password=password, salt=salt)
        self._verify_hmac(package, hmac_key, ciphertext)

        try:
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise SharingServiceError("Failed to decrypt shared package") from exc

        self._verify_plaintext_hash(package, plaintext)

        return self._load_plain_package(plaintext)

    def decrypt_shared_package_with_private_key(
        self,
        package: Dict[str, Any],
        private_key: Union[bytes, Any],
        password: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        self._validate_encrypted_package(package)

        encryption = package["encryption"]
        method = encryption.get("method")
        private_key_obj = self._load_private_key(private_key, password=password)

        if method == "rsa":
            plain = self._decrypt_rsa_package(package, private_key_obj)
        elif method == "ecc":
            plain = self._decrypt_ecc_package(package, private_key_obj)
        else:
            raise SharingServiceError(f"Unsupported private key encryption method: {method}")

        return plain

    def import_shared_entry(
        self,
        package: Dict[str, Any],
        password: Optional[str] = None,
        private_key: Optional[Union[bytes, Any]] = None,
        private_key_password: Optional[bytes] = None,
        save_to_vault: bool = False,
    ) -> Dict[str, Any]:
        if package.get("cryptosafe_shared_entry") is True:
            plain_package = package
        elif password is not None:
            plain_package = self.decrypt_shared_package_with_password(package, password)
        elif private_key is not None:
            plain_package = self.decrypt_shared_package_with_private_key(
                package=package,
                private_key=private_key,
                password=private_key_password,
            )
        else:
            raise SharingServiceError("Password or private key is required")

        self._validate_plain_package(plain_package)
        self._validate_not_expired(plain_package)

        entry = plain_package["entry"]

        if save_to_vault:
            self._save_entry_to_vault(entry)
            self._audit(
                "shared_entry_imported",
                {
                    "share_id": plain_package.get("share_id"),
                    "saved_to_vault": True,
                },
            )

            return {
                "status": "saved",
                "share_id": plain_package.get("share_id"),
                "entry": entry,
            }

        self._audit(
            "shared_entry_opened_temporarily",
            {
                "share_id": plain_package.get("share_id"),
                "saved_to_vault": False,
            },
        )

        return {
            "status": "temporary",
            "share_id": plain_package.get("share_id"),
            "entry": entry,
        }

    def _create_plain_package(
        self,
        entry: Dict[str, Any],
        share_id: str,
        recipient: str,
        permissions: Dict[str, Any],
        expires_at: datetime,
    ) -> Dict[str, Any]:
        filtered_entry = self._filter_entry_for_sharing(entry, permissions)

        package = {
            "version": "1.0",
            "cryptosafe_shared_entry": True,
            "share_id": share_id,
            "sharer": self.sharer,
            "recipient": recipient,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
            "permissions": permissions,
            "entry": filtered_entry,
        }

        package["integrity"] = {
            "hash_algorithm": "SHA256",
            "package_hash": self._package_checksum_without_integrity(package),
        }

        return package

    def _encrypt_package_with_password(
        self,
        package: Dict[str, Any],
        password: str,
    ) -> Dict[str, Any]:
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        aes_key, hmac_key = self._derive_password_keys(password=password, salt=salt)

        plaintext = json.dumps(package, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        hmac_value = self._create_hmac(hmac_key, ciphertext)

        return {
            "version": "1.0",
            "cryptosafe_shared_package": True,
            "share_id": package["share_id"],
            "created_at": package["created_at"],
            "expires_at": package["expires_at"],
            "recipient": package["recipient"],
            "sender_public_key": None,
            "encryption": {
                "method": "password",
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-HMAC-SHA256",
                "iterations": self.PBKDF2_ITERATIONS,
                "salt": self._b64e(salt),
                "nonce": self._b64e(nonce),
            },
            "data": self._b64e(ciphertext),
            "integrity": {
                "hash_algorithm": "SHA256",
                "hmac_algorithm": "HMAC-SHA256",
                "hmac": hmac_value,
                "plaintext_hash": hashlib.sha256(plaintext).hexdigest(),
                "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest(),
            },
        }

    def _encrypt_package_with_public_key(
        self,
        package: Dict[str, Any],
        public_key: Any,
    ) -> Dict[str, Any]:
        if isinstance(public_key, rsa.RSAPublicKey):
            return self._encrypt_package_with_rsa(package, public_key)

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return self._encrypt_package_with_ecc(package, public_key)

        raise SharingServiceError("Unsupported public key type")

    def _encrypt_package_with_rsa(
        self,
        package: Dict[str, Any],
        public_key: rsa.RSAPublicKey,
    ) -> Dict[str, Any]:
        aes_key = os.urandom(self.AES_KEY_SIZE)
        hmac_key = os.urandom(self.HMAC_KEY_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)

        plaintext = json.dumps(package, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        hmac_value = self._create_hmac(hmac_key, ciphertext)

        key_package = {
            "aes_key": self._b64e(aes_key),
            "hmac_key": self._b64e(hmac_key),
        }

        encrypted_key = public_key.encrypt(
            json.dumps(key_package, sort_keys=True).encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return {
            "version": "1.0",
            "cryptosafe_shared_package": True,
            "share_id": package["share_id"],
            "created_at": package["created_at"],
            "expires_at": package["expires_at"],
            "recipient": package["recipient"],
            "sender_public_key": self._b64e(self._serialize_sender_public_key()),
            "encryption": {
                "method": "rsa",
                "algorithm": "RSA-OAEP/AES-256-GCM",
                "key_algorithm": "RSA-OAEP-SHA256",
                "data_algorithm": "AES-256-GCM",
                "nonce": self._b64e(nonce),
                "encrypted_key": self._b64e(encrypted_key),
            },
            "data": self._b64e(ciphertext),
            "integrity": {
                "hash_algorithm": "SHA256",
                "hmac_algorithm": "HMAC-SHA256",
                "hmac": hmac_value,
                "plaintext_hash": hashlib.sha256(plaintext).hexdigest(),
                "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest(),
            },
        }

    def _encrypt_package_with_ecc(
        self,
        package: Dict[str, Any],
        recipient_public_key: ec.EllipticCurvePublicKey,
    ) -> Dict[str, Any]:
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)
        aes_key, hmac_key = self._derive_ecdh_keys(shared_secret, salt)

        plaintext = json.dumps(package, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        hmac_value = self._create_hmac(hmac_key, ciphertext)

        ephemeral_public_pem = ephemeral_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "version": "1.0",
            "cryptosafe_shared_package": True,
            "share_id": package["share_id"],
            "created_at": package["created_at"],
            "expires_at": package["expires_at"],
            "recipient": package["recipient"],
            "sender_public_key": self._b64e(self._serialize_sender_public_key()),
            "encryption": {
                "method": "ecc",
                "algorithm": "ECDH-P-256/AES-256-GCM",
                "key_algorithm": "ECDH-P-256-HKDF-SHA256",
                "data_algorithm": "AES-256-GCM",
                "salt": self._b64e(salt),
                "nonce": self._b64e(nonce),
                "ephemeral_public_key": self._b64e(ephemeral_public_pem),
            },
            "data": self._b64e(ciphertext),
            "integrity": {
                "hash_algorithm": "SHA256",
                "hmac_algorithm": "HMAC-SHA256",
                "hmac": hmac_value,
                "plaintext_hash": hashlib.sha256(plaintext).hexdigest(),
                "ciphertext_hash": hashlib.sha256(ciphertext).hexdigest(),
            },
        }

    def _decrypt_rsa_package(
        self,
        package: Dict[str, Any],
        private_key: rsa.RSAPrivateKey,
    ) -> Dict[str, Any]:
        encryption = package["encryption"]

        try:
            nonce = self._b64d(encryption["nonce"])
            encrypted_key = self._b64d(encryption["encrypted_key"])
            ciphertext = self._b64d(package["data"])
        except Exception as exc:
            raise SharingServiceError("Invalid RSA package encoding") from exc

        self._verify_ciphertext_hash(package, ciphertext)

        try:
            decrypted_key_package = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            key_package = json.loads(decrypted_key_package.decode("utf-8"))
            aes_key = self._b64d(key_package["aes_key"])
            hmac_key = self._b64d(key_package["hmac_key"])

            self._verify_hmac(package, hmac_key, ciphertext)
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

        except Exception as exc:
            raise SharingServiceError("Failed to decrypt RSA shared package") from exc

        self._verify_plaintext_hash(package, plaintext)

        return self._load_plain_package(plaintext)

    def _decrypt_ecc_package(
        self,
        package: Dict[str, Any],
        private_key: ec.EllipticCurvePrivateKey,
    ) -> Dict[str, Any]:
        encryption = package["encryption"]

        try:
            salt = self._b64d(encryption["salt"])
            nonce = self._b64d(encryption["nonce"])
            ephemeral_public_pem = self._b64d(encryption["ephemeral_public_key"])
            ciphertext = self._b64d(package["data"])
        except Exception as exc:
            raise SharingServiceError("Invalid ECC package encoding") from exc

        self._verify_ciphertext_hash(package, ciphertext)

        try:
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_pem)
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            aes_key, hmac_key = self._derive_ecdh_keys(shared_secret, salt)

            self._verify_hmac(package, hmac_key, ciphertext)
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

        except Exception as exc:
            raise SharingServiceError("Failed to decrypt ECC shared package") from exc

        self._verify_plaintext_hash(package, plaintext)

        return self._load_plain_package(plaintext)

    def _derive_password_keys(self, password: str, salt: bytes) -> tuple[bytes, bytes]:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_SIZE + self.HMAC_KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )

        material = kdf.derive(password.encode("utf-8"))

        return (
            material[: self.AES_KEY_SIZE],
            material[self.AES_KEY_SIZE :],
        )

    def _derive_ecdh_keys(self, shared_secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_SIZE + self.HMAC_KEY_SIZE,
            salt=salt,
            info=b"cryptosafe-sharing-ecdh",
        )

        material = hkdf.derive(shared_secret)

        return (
            material[: self.AES_KEY_SIZE],
            material[self.AES_KEY_SIZE :],
        )

    def _create_hmac(self, hmac_key: bytes, data: bytes) -> str:
        return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()

    def _verify_hmac(self, package: Dict[str, Any], hmac_key: bytes, data: bytes) -> None:
        expected_hmac = package.get("integrity", {}).get("hmac")

        if not expected_hmac:
            raise SharingServiceError("Missing HMAC")

        actual_hmac = self._create_hmac(hmac_key, data)

        if not hmac.compare_digest(expected_hmac, actual_hmac):
            raise SharingServiceError("Shared package HMAC verification failed")

    def _filter_entry_for_sharing(
        self,
        entry: Dict[str, Any],
        permissions: Dict[str, Any],
    ) -> Dict[str, Any]:
        result = dict(entry)

        if not permissions.get("include_password", True):
            result.pop("password", None)

        return result

    def _normalize_permissions(self, permissions: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "read": bool(permissions.get("read", True)),
            "edit": bool(permissions.get("edit", False)),
            "include_password": bool(permissions.get("include_password", True)),
        }

    def _build_expiration(self, expires_in: int) -> datetime:
        if not isinstance(expires_in, int):
            raise SharingServiceError("Expiration must be integer number of days")

        if expires_in < self.MIN_EXPIRATION_DAYS or expires_in > self.MAX_EXPIRATION_DAYS:
            raise SharingServiceError("Expiration must be between 1 and 30 days")

        return datetime.utcnow() + timedelta(days=expires_in)

    def _validate_plain_package(self, package: Dict[str, Any]) -> None:
        if not isinstance(package, dict):
            raise SharingServiceError("Shared package must be a dictionary")

        if package.get("cryptosafe_shared_entry") is not True:
            raise SharingServiceError("Not a CryptoSafe shared entry")

        required = [
            "version",
            "share_id",
            "sharer",
            "recipient",
            "created_at",
            "expires_at",
            "permissions",
            "entry",
            "integrity",
        ]

        for field in required:
            if field not in package:
                raise SharingServiceError(f"Shared entry missing field: {field}")

        expected_hash = package.get("integrity", {}).get("package_hash")
        actual_hash = self._package_checksum_without_integrity(package)

        if expected_hash != actual_hash:
            raise SharingServiceError("Shared entry integrity check failed")

    def _validate_encrypted_package(self, package: Dict[str, Any]) -> None:
        if not isinstance(package, dict):
            raise SharingServiceError("Shared package must be a dictionary")

        if package.get("cryptosafe_shared_package") is not True:
            raise SharingServiceError("Not a CryptoSafe encrypted shared package")

        required = [
            "version",
            "share_id",
            "expires_at",
            "encryption",
            "data",
            "integrity",
        ]

        for field in required:
            if field not in package:
                raise SharingServiceError(f"Encrypted shared package missing field: {field}")

        integrity = package.get("integrity", {})

        if "hmac" not in integrity:
            raise SharingServiceError("Encrypted shared package missing HMAC")

        if "ciphertext_hash" not in integrity:
            raise SharingServiceError("Encrypted shared package missing ciphertext hash")

        if "plaintext_hash" not in integrity:
            raise SharingServiceError("Encrypted shared package missing plaintext hash")

    def _validate_not_expired(self, package: Dict[str, Any]) -> None:
        try:
            expires_at = datetime.fromisoformat(package["expires_at"])
        except Exception as exc:
            raise SharingServiceError("Invalid expiration timestamp") from exc

        if datetime.utcnow() > expires_at:
            raise SharingServiceError("Shared entry has expired")

    def _load_plain_package(self, plaintext: bytes) -> Dict[str, Any]:
        try:
            package = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise SharingServiceError("Failed to parse decrypted shared package") from exc

        self._validate_plain_package(package)
        self._validate_not_expired(package)

        return package

    def _verify_ciphertext_hash(self, package: Dict[str, Any], ciphertext: bytes) -> None:
        expected_hash = package.get("integrity", {}).get("ciphertext_hash")

        if not expected_hash:
            raise SharingServiceError("Missing ciphertext hash")

        actual_hash = hashlib.sha256(ciphertext).hexdigest()

        if expected_hash != actual_hash:
            raise SharingServiceError("Shared package ciphertext integrity check failed")

    def _verify_plaintext_hash(self, package: Dict[str, Any], plaintext: bytes) -> None:
        expected_hash = package.get("integrity", {}).get("plaintext_hash")

        if not expected_hash:
            raise SharingServiceError("Missing plaintext hash")

        actual_hash = hashlib.sha256(plaintext).hexdigest()

        if expected_hash != actual_hash:
            raise SharingServiceError("Shared package plaintext integrity check failed")

    def _store_share_record(
        self,
        share_id: str,
        entry_id: str,
        recipient: str,
        permissions: Dict[str, Any],
        expires_at: datetime,
        encryption_method: str,
        package_checksum: str,
    ) -> None:
        shared_at = datetime.utcnow().isoformat()

        try:
            self.db.execute(
                """
                INSERT INTO shared_entries
                (shared_id, original_entry_id, encryption_method, recipient_info, permissions, shared_at, expires_at, package_checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    share_id,
                    entry_id,
                    encryption_method,
                    recipient,
                    json.dumps(permissions, ensure_ascii=False),
                    shared_at,
                    expires_at.isoformat(),
                    package_checksum,
                ),
            )

            if hasattr(self.db, "commit"):
                self.db.commit()

        except Exception:
            try:
                self.db.execute(
                    """
                    INSERT INTO shared_entries
                    (share_id, original_entry_id, recipient, permissions, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        share_id,
                        entry_id,
                        recipient,
                        json.dumps(permissions, ensure_ascii=False),
                        expires_at.isoformat(),
                        shared_at,
                    ),
                )

                if hasattr(self.db, "commit"):
                    self.db.commit()

            except Exception:
                pass

    def _save_entry_to_vault(self, entry: Dict[str, Any]) -> None:
        if hasattr(self.db, "upsert_entry"):
            self.db.upsert_entry(entry)
            return

        if hasattr(self.db, "create_entry"):
            self.db.create_entry(
                title=entry.get("title", ""),
                username=entry.get("username", ""),
                password=entry.get("password", ""),
                url=entry.get("url", ""),
                notes=entry.get("notes", ""),
            )
            return

        if hasattr(self.db, "entry_manager") and hasattr(self.db.entry_manager, "upsert_entry"):
            self.db.entry_manager.upsert_entry(entry)
            return

        raise SharingServiceError("Vault does not support saving shared entries")

    def _get_entry(self, entry_id: str) -> Dict[str, Any]:
        if hasattr(self.db, "get_entry"):
            entry = self.db.get_entry(entry_id)
        elif hasattr(self.db, "entry_manager") and hasattr(self.db.entry_manager, "get_entry"):
            entry = self.db.entry_manager.get_entry(entry_id)
        else:
            raise SharingServiceError("Database does not support get_entry")

        if entry is None:
            raise ValueError(f"Entry not found: {entry_id}")

        return dict(entry)

    def _load_public_key(self, public_key: Union[bytes, Any]) -> Any:
        if isinstance(public_key, bytes):
            return serialization.load_pem_public_key(public_key)

        return public_key

    def _load_private_key(
        self,
        private_key: Union[bytes, Any],
        password: Optional[bytes] = None,
    ) -> Any:
        if isinstance(private_key, bytes):
            return serialization.load_pem_private_key(private_key, password=password)

        return private_key

    def _serialize_sender_public_key(self) -> bytes:
        return self.sender_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _package_checksum(self, package: Dict[str, Any]) -> str:
        raw = json.dumps(package, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _package_checksum_without_integrity(self, package: Dict[str, Any]) -> str:
        copied = dict(package)
        copied.pop("integrity", None)
        raw = json.dumps(copied, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _audit(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.audit_logger:
            try:
                if hasattr(self.audit_logger, "log_event"):
                    self.audit_logger.log_event(event_type, details)
                elif hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(event_type, details)
            except Exception:
                pass

    @staticmethod
    def _b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _b64d(data: str) -> bytes:
        return base64.b64decode(data.encode("ascii"))