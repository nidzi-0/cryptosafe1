import json
from pathlib import Path

import pytest

from src.core.import_export.exporter import VaultExporter, ExportOptions
from src.core.import_export.importer import VaultImporter


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
        }
        self.imported = []

    def list_entries(self):
        return list(self.entries.values())

    def get_entry(self, entry_id):
        return self.entries.get(str(entry_id))

    def upsert_entry(self, entry):
        self.imported.append(entry)

    def clear_all(self):
        self.imported.clear()


def test_export_encrypted_json_contains_metadata():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)

    package = exporter.export_vault(
        password="export-password",
        options=ExportOptions(format="encrypted_json"),
    )

    assert package["cryptosafe_export"] is True
    assert package["version"] == "1.0"
    assert "metadata" in package
    assert "encryption" in package
    assert "data" in package
    assert "integrity" in package
    assert package["metadata"]["entry_count"] == 2
    assert package["encryption"]["algorithm"] == "AES-256-GCM"


def test_export_selected_entries_only():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)

    package = exporter.export_vault(
        password="export-password",
        entry_ids=["1"],
        options=ExportOptions(format="encrypted_json"),
    )

    assert package["metadata"]["entry_count"] == 1


def test_export_without_notes():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)

    package = exporter.export_vault(
        password="export-password",
        options=ExportOptions(format="encrypted_json", include_notes=False),
    )

    importer = VaultImporter(manager)
    result = importer.import_package(
        package=package,
        password="export-password",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 2
    assert "notes" not in result["entries"][0]


def test_round_trip_export_import_dry_run():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)
    importer = VaultImporter(manager)

    package = exporter.export_vault(
        password="export-password",
        options=ExportOptions(format="encrypted_json"),
    )

    result = importer.import_package(
        package=package,
        password="export-password",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 2
    assert result["entries"][0]["title"] == "GitHub"
    assert result["entries"][1]["title"] == "Mail"


def test_round_trip_export_import_merge():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)
    importer = VaultImporter(manager)

    package = exporter.export_vault(
        password="export-password",
        options=ExportOptions(format="encrypted_json"),
    )

    result = importer.import_package(
        package=package,
        password="export-password",
        mode="merge",
    )

    assert result["status"] == "success"
    assert result["imported"] == 2
    assert len(manager.imported) == 2


def test_import_wrong_password_fails():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)
    importer = VaultImporter(manager)

    package = exporter.export_vault(
        password="correct-password",
        options=ExportOptions(format="encrypted_json"),
    )

    with pytest.raises(Exception):
        importer.import_package(
            package=package,
            password="wrong-password",
            dry_run=True,
        )


def test_export_to_file(tmp_path: Path):
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)

    output_path = tmp_path / "vault_export.json"

    result_path = exporter.export_to_file(
        output_path=output_path,
        password="export-password",
        options=ExportOptions(format="encrypted_json"),
    )

    assert result_path.exists()

    with output_path.open("r", encoding="utf-8") as f:
        package = json.load(f)

    assert package["cryptosafe_export"] is True
    assert package["metadata"]["entry_count"] == 2


def test_plaintext_csv_export_requires_explicit_permission():
    manager = FakeEntryManager()
    exporter = VaultExporter(manager)

    package = exporter.export_vault(
        password="export-password",
        options=ExportOptions(format="csv", plaintext_allowed=True),
    )

    assert package["format"] == "csv"
    assert package["plaintext"] is True
    assert "GitHub" in package["data"]
    assert "Mail" in package["data"]
def test_export_requires_master_password_when_enabled():
    manager = FakeEntryManager()

    def verifier(password):
        return password == "correct-master"

    exporter = VaultExporter(
        manager,
        master_password_verifier=verifier,
    )

    package = exporter.export_vault(
        password="export-password",
        master_password="correct-master",
        options=ExportOptions(
            format="encrypted_json",
            require_master_confirmation=True,
        ),
    )

    assert package["cryptosafe_export"] is True
    assert package["metadata"]["master_confirmation_required"] is True


def test_export_rejects_wrong_master_password_when_enabled():
    manager = FakeEntryManager()

    def verifier(password):
        return password == "correct-master"

    exporter = VaultExporter(
        manager,
        master_password_verifier=verifier,
    )

    with pytest.raises(Exception):
        exporter.export_vault(
            password="export-password",
            master_password="wrong-master",
            options=ExportOptions(
                format="encrypted_json",
                require_master_confirmation=True,
            ),
        )