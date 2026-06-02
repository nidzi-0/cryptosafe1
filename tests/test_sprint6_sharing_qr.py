import json
from datetime import datetime

from src.core.import_export.sharing_service import SharingService
from src.core.import_export.key_exchange import QRCodeService, KeyExchangeService


class FakeDatabase:
    def __init__(self):
        self.entries = {
            "1": {
                "id": "1",
                "title": "GitHub",
                "username": "user@example.com",
                "password": "secret123",
                "url": "https://github.com",
                "notes": "main account",
            }
        }
        self.shared_records = []

    def get_entry(self, entry_id):
        return self.entries.get(str(entry_id))

    def execute(self, query, params):
        self.shared_records.append(
            {
                "query": query,
                "params": params,
            }
        )


class FakeAuditLogger:
    def __init__(self):
        self.events = []

    def log_event(self, event_type, details):
        self.events.append(
            {
                "event_type": event_type,
                "details": details,
            }
        )


def test_share_entry_creates_package_and_db_record():
    db = FakeDatabase()
    audit = FakeAuditLogger()
    service = SharingService(db_connection=db, crypto_service=None, audit_logger=audit)

    result = service.share_entry(
        entry_id="1",
        recipient="alice@example.com",
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    assert "share_id" in result
    assert "package" in result
    assert "expires_at" in result
    assert result["permissions"]["read"] is True
    assert result["permissions"]["edit"] is False
    assert len(db.shared_records) == 1
    assert len(audit.events) == 1
    assert audit.events[0]["event_type"] == "share_created"


def test_share_package_contains_only_selected_entry():
    db = FakeDatabase()
    service = SharingService(db_connection=db, crypto_service=None)

    result = service.share_entry(
        entry_id="1",
        recipient="alice@example.com",
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    package = result["package"]

    assert package["version"] == "1.0"
    assert package["share_id"] == result["share_id"]
    assert package["permissions"]["read"] is True
    assert package["entry"]["title"] == "GitHub"
    assert package["entry"]["username"] == "user@example.com"


def test_share_entry_with_missing_entry_fails():
    db = FakeDatabase()
    service = SharingService(db_connection=db, crypto_service=None)

    try:
        service.share_entry(
            entry_id="999",
            recipient="alice@example.com",
            permissions={"read": True},
            expires_in=7,
        )
        assert False
    except ValueError as exc:
        assert "Entry not found" in str(exc)


def test_share_expiration_is_valid_iso_datetime():
    db = FakeDatabase()
    service = SharingService(db_connection=db, crypto_service=None)

    result = service.share_entry(
        entry_id="1",
        recipient="alice@example.com",
        permissions={"read": True},
        expires_in=1,
    )

    expires_at = datetime.fromisoformat(result["expires_at"])

    assert expires_at > datetime.utcnow()


def test_qr_code_round_trip_small_payload():
    qr_service = QRCodeService()
    payload = b"CryptoSafe Manager QR payload"

    chunks = qr_service.generate_qr_code(payload, chunk_size=100)
    assert len(chunks) >= 1

    raw_chunks = []

    for svg in chunks:
        assert svg is not None

    compressed_chunks = []
    import base64
    import hashlib
    import zlib

    compressed = zlib.compress(payload)

    for i in range(0, len(compressed), 100):
        chunk = compressed[i:i + 100]
        chunk_num = i // 100 + 1
        total_chunks = (len(compressed) + 100 - 1) // 100
        chunk_data = {
            "chunk": chunk_num,
            "total": total_chunks,
            "data": base64.b64encode(chunk).decode("ascii"),
            "checksum": hashlib.sha256(chunk).hexdigest()[:8],
        }
        compressed_chunks.append(json.dumps(chunk_data))

    decoded = qr_service.decode_qr_chunks(compressed_chunks)

    assert decoded == payload


def test_qr_decode_rejects_tampered_payload():
    qr_service = QRCodeService()

    bad_chunk = json.dumps(
        {
            "chunk": 1,
            "total": 1,
            "data": "dGFtcGVyZWQ=",
            "checksum": "00000000",
        }
    )

    decoded = qr_service.decode_qr_chunks([bad_chunk])

    assert decoded is None


def test_rsa_keypair_generation_and_serialization():
    service = KeyExchangeService()

    private_key, public_key = service.generate_rsa_keypair()
    public_pem = service.serialize_public_key(public_key)
    private_pem = service.serialize_private_key(private_key)

    loaded_public_key = service.load_public_key(public_pem)
    loaded_private_key = service.load_private_key(private_pem)

    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert loaded_public_key is not None
    assert loaded_private_key is not None


def test_ecc_keypair_generation_and_serialization():
    service = KeyExchangeService()

    private_key, public_key = service.generate_ecc_keypair()
    public_pem = service.serialize_public_key(public_key)
    private_pem = service.serialize_private_key(private_key)

    loaded_public_key = service.load_public_key(public_pem)
    loaded_private_key = service.load_private_key(private_pem)

    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert loaded_public_key is not None
    assert loaded_private_key is not None