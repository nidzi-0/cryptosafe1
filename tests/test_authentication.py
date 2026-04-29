from __future__ import annotations

from src.core.crypto.auth_service import AuthService
from src.database.key_store_repo import KeyStoreRepository


def test_auth_service_setup_and_login(tmp_db):
    key_store = KeyStoreRepository(tmp_db)
    service = AuthService(key_store)

    assert service.is_configured() is False

    setup = service.setup_master_password("StrongPass123!")
    assert setup.success is True

    assert service.is_configured() is True

    login = service.login("StrongPass123!")
    assert login.success is True

    key = service.get_encryption_key()
    assert isinstance(key, bytes)
    assert len(key) == 32
    assert service.is_logged_in() is True


def test_auth_service_rejects_wrong_password(tmp_db):
    key_store = KeyStoreRepository(tmp_db)
    service = AuthService(key_store)

    service.setup_master_password("StrongPass123!")

    login = service.login("WrongPass123!")
    assert login.success is False
    assert service.failed_attempts() == 1


def test_auth_service_rejects_weak_master_password(tmp_db):
    key_store = KeyStoreRepository(tmp_db)
    service = AuthService(key_store)

    setup = service.setup_master_password("password123")

    assert setup.success is False
    assert len(setup.errors) > 0


def test_change_master_password(tmp_db):
    key_store = KeyStoreRepository(tmp_db)
    service = AuthService(key_store)

    setup = service.setup_master_password("StrongPass123!")
    assert setup.success is True

    changed = service.change_master_password("StrongPass123!", "NewStrongPass123!")
    assert changed.success is True

    service.logout()

    old_login = service.login("StrongPass123!")
    assert old_login.success is False

    new_login = service.login("NewStrongPass123!")
    assert new_login.success is True
    assert service.get_encryption_key() is not None