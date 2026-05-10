from __future__ import annotations

from src.core.crypto.auth_service import AuthService
from src.core.crypto.placeholder import AES256Placeholder
from src.database.key_store_repo import KeyStoreRepository
from src.database.repo import VaultRepository, VaultEntryInput


def test_password_rotation_with_10_entries(tmp_db):
    key_store = KeyStoreRepository(tmp_db)
    auth_service = AuthService(key_store)

    setup = auth_service.setup_master_password("StrongPassA123!")
    assert setup.success is True

    login_a = auth_service.login("StrongPassA123!")
    assert login_a.success is True

    crypto_a = AES256Placeholder(auth_service)
    repo_a = VaultRepository(tmp_db, crypto_a)

    for i in range(10):
        repo_a.add_entry(
            VaultEntryInput(
                title=f"Запись {i}",
                username=f"user{i}",
                password=f"password{i}",
                url=f"https://example{i}.com",
                notes=f"notes{i}",
                tags="test",
            )
        )

    changed = auth_service.change_master_password(
        "StrongPassA123!",
        "StrongPassB123!",
    )
    assert changed.success is True

    auth_service.logout()

    login_b = auth_service.login("StrongPassB123!")
    assert login_b.success is True

    crypto_b = AES256Placeholder(auth_service)

    rows = tmp_db.connect().execute(
        "SELECT username, encrypted_password, notes FROM vault_entries"
    ).fetchall()

    assert len(rows) == 10

    for i, row in enumerate(rows):
        assert crypto_b.decrypt(row["username"]).decode("utf-8") == f"user{i}"
        assert crypto_b.decrypt(row["encrypted_password"]).decode("utf-8") == f"password{i}"
        assert crypto_b.decrypt(row["notes"]).decode("utf-8") == f"notes{i}"