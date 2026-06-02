import base64
import hashlib
import json
import time
import tracemalloc
from pathlib import Path

from src.core.import_export.exporter import VaultExporter, ExportOptions
from src.core.import_export.importer import VaultImporter
from src.core.import_export.key_exchange import QRCodeService


class FakeLargeEntryManager:
    def __init__(self, count=1000):
        self.entries = {}
        self.imported = []

        for i in range(count):
            entry_id = str(i + 1)
            self.entries[entry_id] = {
                "id": entry_id,
                "title": f"Service {i + 1}",
                "username": f"user{i + 1}@example.com",
                "password": f"Password-{i + 1}-Strong!",
                "url": f"https://service{i + 1}.example.com",
                "notes": f"Generated note for service {i + 1}",
            }

    def list_entries(self):
        return list(self.entries.values())

    def get_entry(self, entry_id):
        return self.entries.get(str(entry_id))

    def upsert_entry(self, entry):
        self.imported.append(entry)

    def clear_all(self):
        self.imported.clear()


def build_qr_payload_chunks(payload, payload_type="encrypted_entry", chunk_size=512, ttl_seconds=300):
    timestamp = int(time.time())
    nonce = "test-nonce-123456"

    payload_package = {
        "type": payload_type,
        "timestamp": timestamp,
        "ttl": ttl_seconds,
        "nonce": nonce,
        "data": base64.b64encode(payload).decode("ascii"),
    }

    checksum_data = json.dumps(
        payload_package,
        separators=(",", ":"),
    ).encode("utf-8")

    payload_package["checksum"] = hashlib.sha256(checksum_data).hexdigest()

    serialized = json.dumps(
        payload_package,
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

        chunks.append(json.dumps(chunk_data))

    return chunks


def test_qr_code_1kb_payload_generation_and_integrity():
    qr_service = QRCodeService()
    payload = b"A" * 1024

    start = time.perf_counter()
    qr_images = qr_service.generate_qr_code(
        data=payload,
        payload_type="encrypted_entry",
        chunk_size=512,
        ttl_seconds=300,
    )
    elapsed = time.perf_counter() - start

    assert len(qr_images) >= 1
    assert all(image is not None for image in qr_images)
    assert elapsed < 1.0

    chunks = build_qr_payload_chunks(
        payload=payload,
        payload_type="encrypted_entry",
        chunk_size=512,
        ttl_seconds=300,
    )

    decoded = qr_service.decode_qr_chunks(chunks)

    assert decoded == payload


def test_qr_code_rejects_malformed_payload():
    qr_service = QRCodeService()

    malformed_chunks = [
        json.dumps(
            {
                "chunk": 1,
                "total": 1,
                "data": "not-valid-base64",
                "checksum": "12345678",
            }
        )
    ]

    decoded = qr_service.decode_qr_chunks(malformed_chunks)

    assert decoded is None


def test_qr_code_rejects_expired_payload():
    qr_service = QRCodeService()
    payload = b"A" * 1024

    old_timestamp = int(time.time()) - 600

    payload_package = {
        "type": "encrypted_entry",
        "timestamp": old_timestamp,
        "ttl": 300,
        "nonce": "expired-test-nonce",
        "data": base64.b64encode(payload).decode("ascii"),
    }

    checksum_data = json.dumps(
        payload_package,
        separators=(",", ":"),
    ).encode("utf-8")

    payload_package["checksum"] = hashlib.sha256(checksum_data).hexdigest()

    serialized = json.dumps(
        payload_package,
        separators=(",", ":"),
    ).encode("utf-8")

    chunk = {
        "chunk": 1,
        "total": 1,
        "data": base64.b64encode(serialized).decode("ascii"),
        "checksum": hashlib.sha256(serialized).hexdigest()[:8],
    }

    decoded = qr_service.decode_qr_chunks([json.dumps(chunk)])

    assert decoded is None


def test_performance_export_1000_entries_under_5_seconds():
    manager = FakeLargeEntryManager(count=1000)
    exporter = VaultExporter(manager)

    tracemalloc.start()
    start = time.perf_counter()

    package = exporter.export_vault(
        password="performance-password",
        options=ExportOptions(
            format="encrypted_json",
            include_notes=True,
            encryption_bits=256,
            compress=False,
        ),
    )

    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    package_size = len(json.dumps(package).encode("utf-8"))

    assert package["metadata"]["entry_count"] == 1000
    assert elapsed < 5.0
    assert peak < package_size * 4


def test_performance_import_1000_entries_under_10_seconds():
    manager = FakeLargeEntryManager(count=1000)
    exporter = VaultExporter(manager)

    package = exporter.export_vault(
        password="performance-password",
        options=ExportOptions(
            format="encrypted_json",
            include_notes=True,
            encryption_bits=256,
            compress=False,
        ),
    )

    import_manager = FakeLargeEntryManager(count=0)
    importer = VaultImporter(import_manager)

    tracemalloc.start()
    start = time.perf_counter()

    result = importer.import_package(
        package=package,
        password="performance-password",
        mode="merge",
    )

    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    package_size = len(json.dumps(package).encode("utf-8"))

    assert result["status"] == "success"
    assert result["imported"] == 1000
    assert len(import_manager.imported) == 1000
    assert elapsed < 10.0
    assert peak < package_size * 4