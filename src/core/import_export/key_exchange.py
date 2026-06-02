import base64
import hashlib
import json
import os
import time
import zlib
from datetime import datetime
from typing import Any, Dict, List, Optional

import qrcode
import qrcode.image.svg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class QRCodeService:
    DEFAULT_TTL_SECONDS = 300
    DEFAULT_CHUNK_SIZE = 2953

    def __init__(self):
        self.qr_factory = qrcode.image.svg.SvgPathImage

    def generate_qr_payload_chunks(
        self,
        data: bytes,
        payload_type: str = "generic",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> List[str]:
        timestamp = int(time.time())
        nonce = os.urandom(8).hex()

        payload = {
            "type": payload_type,
            "timestamp": timestamp,
            "ttl": ttl_seconds,
            "nonce": nonce,
            "data": base64.b64encode(data).decode("ascii"),
        }

        checksum_data = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")

        payload["checksum"] = hashlib.sha256(checksum_data).hexdigest()

        serialized = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")

        chunks = []

        for i in range(0, len(serialized), chunk_size):
            chunk = serialized[i:i + chunk_size]
            chunk_num = i // chunk_size + 1
            total_chunks = (len(serialized) + chunk_size - 1) // chunk_size

            chunk_data = {
                "chunk": chunk_num,
                "total": total_chunks,
                "data": base64.b64encode(chunk).decode("ascii"),
                "checksum": hashlib.sha256(chunk).hexdigest()[:8],
            }

            chunks.append(
                json.dumps(
                    chunk_data,
                    separators=(",", ":"),
                )
            )

        return chunks

    def generate_qr_code(
        self,
        data: bytes,
        payload_type: str = "generic",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> List[str]:
        chunks = self.generate_qr_payload_chunks(
            data=data,
            payload_type=payload_type,
            chunk_size=chunk_size,
            ttl_seconds=ttl_seconds,
        )

        qr_codes = []

        for chunk in chunks:
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=8,
                border=4,
            )

            qr.add_data(chunk)
            qr.make(fit=True)

            img = qr.make_image(image_factory=self.qr_factory)
            qr_codes.append(img.to_string())

        return qr_codes

    def decode_qr_chunks(
        self,
        chunks: List[str],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> Optional[bytes]:
        validated_chunks = []

        for chunk_str in chunks:
            try:
                chunk_data = json.loads(chunk_str)
                data = base64.b64decode(chunk_data["data"])

                if hashlib.sha256(data).hexdigest()[:8] != chunk_data["checksum"]:
                    return None

                validated_chunks.append((chunk_data["chunk"], data))

            except Exception:
                return None

        validated_chunks.sort(key=lambda item: item[0])
        total_data = b"".join(data for _, data in validated_chunks)

        try:
            payload = json.loads(total_data.decode("utf-8"))

            now = int(time.time())

            if now > payload["timestamp"] + payload.get("ttl", ttl_seconds):
                return None

            checksum = payload.get("checksum")

            payload_without_checksum = {
                key: value
                for key, value in payload.items()
                if key != "checksum"
            }

            checksum_data = json.dumps(
                payload_without_checksum,
                separators=(",", ":"),
            ).encode("utf-8")

            if hashlib.sha256(checksum_data).hexdigest() != checksum:
                return None

            return base64.b64decode(payload["data"])

        except Exception:
            pass

        try:
            return zlib.decompress(total_data)
        except Exception:
            return None

    def scan_qr_image_file(self, image_path: str) -> Optional[str]:
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
        except Exception:
            return None

        try:
            image = Image.open(image_path)
            decoded_items = decode(image)
        except Exception:
            return None

        if not decoded_items:
            return None

        try:
            return decoded_items[0].data.decode("utf-8")
        except Exception:
            return None


class KeyExchangeService:
    def __init__(self):
        self.contacts: Dict[str, Dict[str, Any]] = {}

    def generate_rsa_keypair(self, key_size: int = 2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_ecc_keypair(self, curve: ec.EllipticCurve = ec.SECP256R1()):
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, public_key) -> bytes:
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def serialize_private_key(
        self,
        private_key,
        password: Optional[bytes] = None,
    ) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        return private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )

    def load_public_key(self, data: bytes):
        return serialization.load_pem_public_key(data)

    def load_private_key(
        self,
        data: bytes,
        password: Optional[bytes] = None,
    ):
        return serialization.load_pem_private_key(
            data,
            password=password,
        )

    def public_key_fingerprint(self, public_key_bytes: bytes) -> str:
        return hashlib.sha256(public_key_bytes).hexdigest()[:16]

    def add_contact_public_key(
        self,
        identifier: str,
        public_key_bytes: bytes,
        key_type: str = "RSA",
        contact_name: Optional[str] = None,
    ) -> str:
        fingerprint = self.public_key_fingerprint(public_key_bytes)
        now = datetime.utcnow().isoformat()

        self.contacts[identifier] = {
            "contact_name": contact_name or identifier,
            "identifier": identifier,
            "public_key": public_key_bytes,
            "key_type": key_type,
            "fingerprint": fingerprint,
            "revoked": False,
            "created_at": now,
            "updated_at": now,
            "last_used_at": None,
        }

        return fingerprint

    def get_contact_public_key(self, identifier: str) -> Optional[bytes]:
        contact = self.contacts.get(identifier)

        if not contact:
            return None

        if contact.get("revoked"):
            return None

        contact["last_used_at"] = datetime.utcnow().isoformat()

        return contact.get("public_key")

    def revoke_contact_key(self, identifier: str) -> None:
        if identifier not in self.contacts:
            return

        self.contacts[identifier]["revoked"] = True
        self.contacts[identifier]["updated_at"] = datetime.utcnow().isoformat()

    def rotate_contact_key(
        self,
        identifier: str,
        new_public_key_bytes: bytes,
        key_type: Optional[str] = None,
    ) -> str:
        fingerprint = self.public_key_fingerprint(new_public_key_bytes)
        now = datetime.utcnow().isoformat()

        if identifier not in self.contacts:
            self.contacts[identifier] = {
                "contact_name": identifier,
                "identifier": identifier,
                "public_key": new_public_key_bytes,
                "key_type": key_type or "RSA",
                "fingerprint": fingerprint,
                "revoked": False,
                "created_at": now,
                "updated_at": now,
                "last_used_at": None,
            }

            return fingerprint

        self.contacts[identifier]["public_key"] = new_public_key_bytes
        self.contacts[identifier]["fingerprint"] = fingerprint
        self.contacts[identifier]["revoked"] = False

        if key_type:
            self.contacts[identifier]["key_type"] = key_type

        self.contacts[identifier]["updated_at"] = now

        return fingerprint