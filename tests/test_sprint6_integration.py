import base64
import hashlib
import json
import zlib
from datetime import datetime
from pathlib import Path

from src.core.import_export.exporter import VaultExporter, ExportOptions
from src.core.import_export.importer import VaultImporter
from src.core.import_export.sharing_service import SharingService
from src.core.import_export.key_exchange import QRCodeService, KeyExchangeService


class FakeEntryManager:
    def __init__(self):
        self.entries = {
            "1": {
                "id": "1",
                "title": "GitHub",
                "username": "user@example.com",
                "password": "secret123",
                "url": "https://github.com",
                "notes": "main account",
            },
            "2": {
                "id": "2",
                "title": "Mail",
                "username": "mail@example.com",
                "password": "mailpass",
                "url": "https://mail.example.com",
                "notes": "mail account",
            },
            "3": {
                "id": "3",
                "title": "Bank",
                "username": "bank_user",
                "password": "bank_password",
                "url": "https://bank.example.com",
                "notes": "<script>alert(1)</script>",
            },
        }
        self.imported = []
        self.cleared = False

    def list_entries(self):
        return list(self.entries.values())

    def get_entry(self, entry_id):
        return self.entries.get(str(entry_id))

    def upsert_entry(self, entry):
        self.imported.append(entry)

    def create_entry(self, title, username, password, url, notes):
        self.imported.append(
            {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
            }
        )

    def clear_all(self):
        self.cleared = True
        self.imported.clear()


class FakeDatabase:
    def __init__(self, entry_manager):
        self.entry_manager = entry_manager
        self.shared_records = []

    def get_entry(self, entry_id):
        return self.entry_manager.get_entry(entry_id)

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


def build_qr_payload_chunks(payload, chunk_size=256):
    compressed = zlib.compress(payload)
    result = []

    for i in range(0, len(compressed), chunk_size):
        chunk = compressed[i:i + chunk_size]
        chunk_num = i // chunk_size + 1
        total_chunks = (len(compressed) + chunk_size - 1) // chunk_size

        chunk_data = {
            "chunk": chunk_num,
            "total": total_chunks,
            "data": base64.b64encode(chunk).decode("ascii"),
            "checksum": hashlib.sha256(chunk).hexdigest()[:8],
        }

        result.append(json.dumps(chunk_data))

    return result


def test_sprint6_full_export_import_share_qr_flow(tmp_path: Path):
    entry_manager = FakeEntryManager()
    audit_logger = FakeAuditLogger()

    exporter = VaultExporter(entry_manager, audit_logger=audit_logger)
    importer = VaultImporter(entry_manager, audit_logger=audit_logger)

    export_path = tmp_path / "cryptosafe_export.json"

    package_path = exporter.export_to_file(
        output_path=export_path,
        password="export-password",
        options=ExportOptions(
            format="encrypted_json",
            include_notes=True,
            encryption_bits=256,
            compress=True,
        ),
    )

    assert package_path.exists()

    with export_path.open("r", encoding="utf-8") as file:
        package = json.load(file)

    assert package["cryptosafe_export"] is True
    assert package["metadata"]["entry_count"] == 3
    assert package["encryption"]["algorithm"] == "AES-256-GCM"
    assert package["encryption"]["compressed"] is True

    dry_run_result = importer.import_package(
        package=package,
        password="export-password",
        dry_run=True,
    )

    assert dry_run_result["status"] == "dry_run"
    assert dry_run_result["entry_count"] == 3
    assert dry_run_result["entries"][0]["title"] == "GitHub"

    merge_result = importer.import_package(
        package=package,
        password="export-password",
        mode="merge",
    )

    assert merge_result["status"] == "success"
    assert merge_result["imported"] == 3
    assert len(entry_manager.imported) == 3

    db = FakeDatabase(entry_manager)
    sharing_service = SharingService(
        db_connection=db,
        crypto_service=None,
        audit_logger=audit_logger,
    )

    share_result = sharing_service.share_entry(
        entry_id="1",
        recipient="alice@example.com",
        permissions={
            "read": True,
            "edit": False,
        },
        expires_in=7,
    )

    assert "share_id" in share_result
    assert "package" in share_result
    assert len(db.shared_records) == 1

    share_package = share_result["package"]

    assert share_package["entry"]["title"] == "GitHub"
    assert share_package["permissions"]["read"] is True
    assert share_package["permissions"]["edit"] is False
    assert datetime.fromisoformat(share_result["expires_at"]) > datetime.utcnow()

    qr_service = QRCodeService()

    share_payload = json.dumps(
        share_package,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")

    qr_images = qr_service.generate_qr_code(
        data=share_payload,
        chunk_size=256,
    )

    assert len(qr_images) >= 1

    qr_chunks = build_qr_payload_chunks(
        payload=share_payload,
        chunk_size=256,
    )

    restored_payload = qr_service.decode_qr_chunks(qr_chunks)

    assert restored_payload == share_payload

    restored_share_package = json.loads(restored_payload.decode("utf-8"))

    assert restored_share_package["share_id"] == share_package["share_id"]
    assert restored_share_package["entry"]["title"] == "GitHub"
    assert restored_share_package["entry"]["username"] == "user@example.com"

    key_service = KeyExchangeService()

    rsa_private_key, rsa_public_key = key_service.generate_rsa_keypair()
    ecc_private_key, ecc_public_key = key_service.generate_ecc_keypair()

    rsa_public_pem = key_service.serialize_public_key(rsa_public_key)
    rsa_private_pem = key_service.serialize_private_key(rsa_private_key)

    ecc_public_pem = key_service.serialize_public_key(ecc_public_key)
    ecc_private_pem = key_service.serialize_private_key(ecc_private_key)

    assert rsa_public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert rsa_private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert ecc_public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert ecc_private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    loaded_rsa_public = key_service.load_public_key(rsa_public_pem)
    loaded_rsa_private = key_service.load_private_key(rsa_private_pem)

    loaded_ecc_public = key_service.load_public_key(ecc_public_pem)
    loaded_ecc_private = key_service.load_private_key(ecc_private_pem)

    assert loaded_rsa_public is not None
    assert loaded_rsa_private is not None
    assert loaded_ecc_public is not None
    assert loaded_ecc_private is not None

    event_types = [event["event_type"] for event in audit_logger.events]

    assert "vault_exported" in event_types
    assert "export_file_created" in event_types
    assert "vault_imported" in event_types
    assert "share_created" in event_types


def test_sprint6_selected_export_replace_import():
    entry_manager = FakeEntryManager()

    exporter = VaultExporter(entry_manager)
    importer = VaultImporter(entry_manager)

    package = exporter.export_vault(
        password="export-password",
        entry_ids=["2"],
        options=ExportOptions(
            format="encrypted_json",
            include_notes=False,
            encryption_bits=128,
            compress=False,
        ),
    )

    assert package["metadata"]["entry_count"] == 1
    assert package["encryption"]["algorithm"] == "AES-128-GCM"

    result = importer.import_package(
        package=package,
        password="export-password",
        mode="replace",
    )

    assert result["status"] == "success"
    assert result["imported"] == 1
    assert entry_manager.cleared is True
    assert len(entry_manager.imported) == 1
    assert entry_manager.imported[0]["title"] == "Mail"
    assert "notes" not in entry_manager.imported[0]


def test_sprint6_import_sanitizes_malicious_content():
    entry_manager = FakeEntryManager()

    exporter = VaultExporter(entry_manager)
    importer = VaultImporter(entry_manager)

    package = exporter.export_vault(
        password="export-password",
        entry_ids=["3"],
        options=ExportOptions(format="encrypted_json"),
    )

    result = importer.import_package(
        package=package,
        password="export-password",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 1
    assert "<script>" not in result["entries"][0]["notes"]
    assert "&lt;script" in result["entries"][0]["notes"]


def test_sprint6_tampered_export_package_rejected():
    entry_manager = FakeEntryManager()

    exporter = VaultExporter(entry_manager)
    importer = VaultImporter(entry_manager)

    package = exporter.export_vault(
        password="export-password",
        options=ExportOptions(format="encrypted_json"),
    )

    package["integrity"]["plaintext_hash"] = "0" * 64

    try:
        importer.import_package(
            package=package,
            password="export-password",
            dry_run=True,
        )
        assert False
    except Exception as exc:
        assert "Integrity check failed" in str(exc)


def test_sprint6_wrong_export_password_rejected():
    entry_manager = FakeEntryManager()

    exporter = VaultExporter(entry_manager)
    importer = VaultImporter(entry_manager)

    package = exporter.export_vault(
        password="correct-password",
        options=ExportOptions(format="encrypted_json"),
    )

    try:
        importer.import_package(
            package=package,
            password="wrong-password",
            dry_run=True,
        )
        assert False
    except Exception as exc:
        assert "Failed to decrypt package" in str(exc)


def test_sprint6_qr_rejects_invalid_chunk():
    qr_service = QRCodeService()

    invalid_chunk = json.dumps(
        {
            "chunk": 1,
            "total": 1,
            "data": "Q3J5cHRvU2FmZQ==",
            "checksum": "bad00000",
        }
    )

    result = qr_service.decode_qr_chunks([invalid_chunk])

    assert result is None