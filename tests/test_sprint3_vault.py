from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from src.core.crypto.key_manager import CachedKeyManager
from src.core.vault.encryption_service import (
    AESGCMEncryptionService,
    VaultDecryptionError,
)
from src.core.vault.entry_manager import (
    EntryCreated,
    EntryDeleted,
    EntryManager,
    EntryValidationError,
    EntryUpdated,
)
from src.core.vault.password_generator import PasswordGenerator


def make_encryption_service() -> AESGCMEncryptionService:
    key_manager = CachedKeyManager(b"K" * 32)
    return AESGCMEncryptionService(key_manager)


def make_manager(tmp_path) -> EntryManager:
    db_path = tmp_path / "test_vault.db"
    encryption_service = make_encryption_service()

    return EntryManager(
        db_path=db_path,
        encryption_service=encryption_service,
    )


def test_encryption_decryption_cycle_and_blob_has_no_plaintext():
    service = make_encryption_service()

    data = {
        "title": "GitHub",
        "username": "user@example.com",
        "password": "StrongPass123!",
        "url": "https://github.com",
        "notes": "secret notes",
        "category": "Work",
        "tags": "git,code",
    }

    encrypted_data = service.encrypt_entry(data)

    assert isinstance(encrypted_data, bytes)
    assert len(encrypted_data) > 12

    assert b"GitHub" not in encrypted_data
    assert b"user@example.com" not in encrypted_data
    assert b"StrongPass123!" not in encrypted_data
    assert b"https://github.com" not in encrypted_data
    assert b"secret notes" not in encrypted_data

    restored = service.decrypt_entry(encrypted_data)

    assert restored["version"] == 1
    assert restored["title"] == data["title"]
    assert restored["username"] == data["username"]
    assert restored["password"] == data["password"]
    assert restored["url"] == data["url"]
    assert restored["notes"] == data["notes"]
    assert restored["category"] == data["category"]
    assert restored["tags"] == data["tags"]
    assert "created_at" in restored


def test_aes_gcm_detects_tampering():
    service = make_encryption_service()

    encrypted_data = service.encrypt_entry(
        {
            "title": "Example",
            "username": "user@example.com",
            "password": "StrongPass123!",
            "url": "https://example.com",
            "notes": "secret",
            "category": "Test",
            "tags": "test",
        }
    )

    tampered = bytearray(encrypted_data)
    tampered[-1] ^= 1

    with pytest.raises(VaultDecryptionError):
        service.decrypt_entry(bytes(tampered))


def test_entry_manager_crud_100_entries_integrity_events_and_deleted_entries(tmp_path):
    manager = make_manager(tmp_path)

    created_entries = []

    for i in range(100):
        entry = manager.create_entry(
            {
                "title": f"Entry {i}",
                "username": f"user{i}@example.com",
                "password": f"StrongPass{i}!A1",
                "url": f"https://example{i}.com",
                "notes": f"notes {i}",
                "category": "test",
                "tags": "test,sprint3",
            }
        )

        assert isinstance(entry, dict)
        assert "id" in entry
        assert entry["title"] == f"Entry {i}"
        assert entry["username"] == f"user{i}@example.com"
        assert entry["password"] == f"StrongPass{i}!A1"

        created_entries.append(entry)

    all_entries = manager.get_all_entries()

    assert len(all_entries) == 100
    assert manager.count_entries() == 100

    for entry in created_entries[:10]:
        updated = manager.update_entry(
            entry["id"],
            {
                "title": "Updated",
                "username": "updated@example.com",
                "password": "UpdatedPass123!",
                "url": "https://updated.com",
                "notes": "updated notes",
                "category": "updated",
                "tags": "updated,sprint3",
            },
        )

        assert isinstance(updated, dict)
        assert updated["id"] == entry["id"]
        assert updated["title"] == "Updated"
        assert updated["username"] == "updated@example.com"
        assert updated["password"] == "UpdatedPass123!"
        assert updated["tags"] == "updated,sprint3"

    for entry in created_entries[:20]:
        manager.delete_entry(entry["id"], soft_delete=True)

    remaining = manager.get_all_entries()

    assert len(remaining) == 80
    assert manager.count_entries() == 80
    assert manager.count_deleted_entries() == 20

    with manager._connection() as conn:
        deleted_rows = conn.execute(
            """
            SELECT original_entry_id, deleted_at, expires_at
            FROM deleted_entries
            """
        ).fetchall()

    assert len(deleted_rows) == 20

    for row in deleted_rows:
        assert row["original_entry_id"] is not None
        assert row["deleted_at"] is not None
        assert row["expires_at"] is not None

    events = manager.get_published_events()

    created_events = [event for event in events if isinstance(event, EntryCreated)]
    updated_events = [event for event in events if isinstance(event, EntryUpdated)]
    deleted_events = [event for event in events if isinstance(event, EntryDeleted)]

    assert len(created_events) == 100
    assert len(updated_events) == 10
    assert len(deleted_events) == 20


def test_entry_manager_transaction_rolls_back_invalid_create(tmp_path):
    manager = make_manager(tmp_path)

    assert manager.count_entries() == 0

    with pytest.raises(EntryValidationError):
        manager.create_entry(
            {
                "title": "",
                "username": "bad@example.com",
                "password": "StrongPass123!",
                "url": "https://bad.com",
                "notes": "",
                "category": "",
                "tags": "",
            }
        )

    assert manager.count_entries() == 0


def test_database_indexes_and_search_index_metadata_exist(tmp_path):
    manager = make_manager(tmp_path)

    with manager._connection() as conn:
        index_rows = conn.execute(
            """
            PRAGMA index_list(vault_entries)
            """
        ).fetchall()

        index_names = {row["name"] for row in index_rows}

        metadata = conn.execute(
            """
            SELECT strategy
            FROM search_index_metadata
            WHERE id = 1
            """
        ).fetchone()

    assert "idx_vault_entries_created_at" in index_names
    assert "idx_vault_entries_updated_at" in index_names
    assert "idx_vault_entries_tags" in index_names

    assert metadata is not None
    assert metadata["strategy"] == "application_level_decrypted_runtime_index"


def test_concurrent_gui_like_operations_do_not_corrupt_data(tmp_path):
    manager = make_manager(tmp_path)

    total_entries = 50

    def create_one(i: int) -> int:
        entry = manager.create_entry(
            {
                "title": f"Concurrent {i}",
                "username": f"concurrent{i}@example.com",
                "password": f"ConcurrentPass{i}!A1",
                "url": f"https://concurrent{i}.com",
                "notes": f"concurrent notes {i}",
                "category": "concurrent",
                "tags": "thread,test",
            }
        )

        return int(entry["id"])

    created_ids = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(create_one, i) for i in range(total_entries)]

        for future in as_completed(futures):
            created_ids.append(future.result())

    assert len(created_ids) == total_entries
    assert len(set(created_ids)) == total_entries
    assert manager.count_entries() == total_entries

    def read_one(entry_id: int) -> dict:
        return manager.get_entry(entry_id)

    read_entries = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(read_one, entry_id) for entry_id in created_ids]

        for future in as_completed(futures):
            read_entries.append(future.result())

    assert len(read_entries) == total_entries

    for entry in read_entries:
        assert entry["title"].startswith("Concurrent")
        assert entry["username"].startswith("concurrent")
        assert entry["password"].startswith("ConcurrentPass")
        assert entry["category"] == "concurrent"
        assert entry["tags"] == "thread,test"


def test_password_generator_10000_passwords_no_duplicates_and_strength():
    generator = PasswordGenerator()

    passwords = set()

    for _ in range(10_000):
        password = generator.generate(
            length=16,
            use_lowercase=True,
            use_uppercase=True,
            use_digits=True,
            use_special=True,
            exclude_similar=True,
        )

        assert password not in passwords
        passwords.add(password)

        assert len(password) == 16

        assert any(ch.islower() for ch in password)
        assert any(ch.isupper() for ch in password)
        assert any(ch.isdigit() for ch in password)
        assert any(ch in PasswordGenerator.SPECIAL_CHARS for ch in password)

        for ch in "lI10O":
            assert ch not in password

        strength = generator.analyze_strength(password)

        assert int(strength["score"]) >= 3

    recent = generator.get_recent_passwords()

    assert len(recent) == 20
    assert len(set(recent)) == 20