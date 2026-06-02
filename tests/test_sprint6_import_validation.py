import json
from pathlib import Path

import pytest

from src.core.import_export.exporter import VaultExporter, ExportOptions
from src.core.import_export.importer import VaultImporter, VaultImportError


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
            }
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


def test_import_encrypted_json_native_format_dry_run():
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
    assert result["entry_count"] == 1
    assert result["entries"][0]["title"] == "GitHub"


def test_import_plain_csv_multiple_dialects_comma():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nMail,mail@example.com,mailpass,https://mail.example.com,note"

    result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 1
    assert result["entries"][0]["title"] == "Mail"


def test_import_plain_csv_multiple_dialects_semicolon():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title;username;password;url;notes\nForum;forum_user;forumpass;https://forum.example.com;forum note"

    result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 1
    assert result["entries"][0]["title"] == "Forum"


def test_import_lastpass_csv():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "url,username,password,extra,name,grouping,fav\nhttps://site.example.com,bob,pass123,extra note,Site,,0"

    result = importer.import_raw(
        raw_data=raw_csv,
        import_format="lastpass_csv",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 1
    assert result["entries"][0]["title"] == "Site"
    assert result["entries"][0]["notes"] == "extra note"


def test_import_bitwarden_json():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_json = json.dumps(
        {
            "items": [
                {
                    "type": 1,
                    "name": "Bitwarden Item",
                    "notes": "bw note",
                    "login": {
                        "username": "bw_user",
                        "password": "bw_pass",
                        "uris": [
                            {
                                "uri": "https://bitwarden.example.com",
                            }
                        ],
                    },
                }
            ]
        }
    )

    result = importer.import_raw(
        raw_data=raw_json,
        import_format="bitwarden_json",
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entry_count"] == 1
    assert result["entries"][0]["title"] == "Bitwarden Item"
    assert result["entries"][0]["username"] == "bw_user"


def test_import_modes_merge_replace_and_dry_run():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nNew,new_user,new_pass,https://new.example.com,note"

    dry_run_result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        dry_run=True,
    )

    assert dry_run_result["status"] == "dry_run"
    assert len(manager.imported) == 0

    merge_result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        mode="merge",
    )

    assert merge_result["status"] == "success"
    assert merge_result["imported"] == 1
    assert len(manager.imported) == 1

    replace_result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        mode="replace",
    )

    assert replace_result["status"] == "success"
    assert manager.cleared is True


def test_import_detects_duplicates_skip():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nGitHub,user@example.com,newpass,https://github.com,note"

    result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        duplicate_handling="skip",
    )

    assert result["status"] == "success"
    assert result["duplicates"] == 1
    assert result["skipped"] == 1
    assert result["imported"] == 0


def test_import_detects_duplicates_error():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nGitHub,user@example.com,newpass,https://github.com,note"

    with pytest.raises(VaultImportError):
        importer.import_raw(
            raw_data=raw_csv,
            import_format="csv",
            duplicate_handling="error",
        )


def test_import_sanitizes_script_content():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nBad,user,pass,https://bad.example.com,<script>alert(1)</script>"

    result = importer.import_raw(
        raw_data=raw_csv,
        import_format="csv",
        dry_run=True,
    )

    assert "<script>" not in result["entries"][0]["notes"]
    assert "&lt;script" in result["entries"][0]["notes"]


def test_import_rejects_malicious_javascript_url():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nBad,user,pass,javascript:alert(1),note"

    with pytest.raises(VaultImportError):
        importer.import_raw(
            raw_data=raw_csv,
            import_format="csv",
            dry_run=True,
        )


def test_import_rejects_invalid_mode():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    raw_csv = "title,username,password,url,notes\nA,u,p,https://a.example.com,n"

    with pytest.raises(VaultImportError):
        importer.import_raw(
            raw_data=raw_csv,
            import_format="csv",
            mode="bad",
        )


def test_import_rejects_large_file(tmp_path: Path):
    manager = FakeEntryManager()
    importer = VaultImporter(manager, max_file_size=10)

    file_path = tmp_path / "large.csv"
    file_path.write_text("title,username,password,url,notes\nTooLarge,u,p,https://a.example.com,n", encoding="utf-8")

    with pytest.raises(VaultImportError):
        importer.import_file(
            file_path=file_path,
            import_format="csv",
        )


def test_import_file_auto_detects_lastpass_csv(tmp_path: Path):
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    file_path = tmp_path / "lastpass.csv"
    file_path.write_text(
        "url,username,password,extra,name,grouping,fav\nhttps://lp.example.com,lp_user,lp_pass,lp note,LP,,0",
        encoding="utf-8",
    )

    result = importer.import_file(
        file_path=file_path,
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entries"][0]["title"] == "LP"


def test_import_file_auto_detects_bitwarden_json(tmp_path: Path):
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    file_path = tmp_path / "bitwarden.json"
    file_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "name": "BW",
                        "notes": "note",
                        "login": {
                            "username": "bw",
                            "password": "pass",
                            "uris": [
                                {
                                    "uri": "https://bw.example.com",
                                }
                            ],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = importer.import_file(
        file_path=file_path,
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["entries"][0]["title"] == "BW"


def test_import_wrong_encryption_package_rejected_before_decryption():
    manager = FakeEntryManager()
    importer = VaultImporter(manager)

    package = {
        "cryptosafe_export": True,
        "encryption": {
            "algorithm": "BAD",
            "salt": "abc",
            "nonce": "abc",
            "iterations": 100000,
        },
        "data": "abc",
        "integrity": {
            "plaintext_hash": "0" * 64,
        },
    }

    with pytest.raises(VaultImportError):
        importer.import_package(
            package=package,
            password="password",
            dry_run=True,
        )