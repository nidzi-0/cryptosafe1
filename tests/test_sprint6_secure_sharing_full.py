import json
from datetime import datetime, timedelta

import pytest

from src.core.import_export.key_exchange import KeyExchangeService
from src.core.import_export.sharing_service import SharingService, SharingServiceError


class FakeVault:
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
        self.saved_entries = []

    def get_entry(self, entry_id):
        return self.entries.get(str(entry_id))

    def execute(self, query, params):
        self.shared_records.append(
            {
                "query": query,
                "params": params,
            }
        )

    def upsert_entry(self, entry):
        self.saved_entries.append(entry)


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


def test_share_entry_with_password_encrypts_and_decrypts():
    vault = FakeVault()
    audit = FakeAuditLogger()
    service = SharingService(vault, audit_logger=audit)

    result = service.share_entry_with_password(
        entry_id="1",
        recipient="alice@example.com",
        password="share-password",
        permissions={"read": True, "edit": False, "include_password": True},
        expires_in=7,
    )

    package = result["package"]

    assert package["cryptosafe_shared_package"] is True
    assert package["encryption"]["method"] == "password"
    assert "data" in package
    assert "entry" not in package

    decrypted = service.decrypt_shared_package_with_password(
        package=package,
        password="share-password",
    )

    assert decrypted["cryptosafe_shared_entry"] is True
    assert decrypted["entry"]["title"] == "GitHub"
    assert decrypted["entry"]["password"] == "secret123"
    assert decrypted["permissions"]["read"] is True
    assert decrypted["permissions"]["edit"] is False
    assert len(vault.shared_records) == 1
    assert audit.events[0]["event_type"] == "share_created"


def test_share_entry_with_wrong_password_fails():
    vault = FakeVault()
    service = SharingService(vault)

    result = service.share_entry_with_password(
        entry_id="1",
        recipient="alice@example.com",
        password="correct-password",
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    with pytest.raises(SharingServiceError):
        service.decrypt_shared_package_with_password(
            package=result["package"],
            password="wrong-password",
        )


def test_share_entry_with_rsa_public_key_encrypts_and_decrypts():
    vault = FakeVault()
    service = SharingService(vault)
    key_service = KeyExchangeService()

    private_key, public_key = key_service.generate_rsa_keypair()

    result = service.share_entry_with_public_key(
        entry_id="1",
        recipient="alice@example.com",
        public_key=public_key,
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    package = result["package"]

    assert package["cryptosafe_shared_package"] is True
    assert package["encryption"]["method"] == "rsa"
    assert "encrypted_key" in package["encryption"]

    decrypted = service.decrypt_shared_package_with_private_key(
        package=package,
        private_key=private_key,
    )

    assert decrypted["entry"]["title"] == "GitHub"
    assert decrypted["entry"]["username"] == "user@example.com"


def test_share_entry_with_ecc_public_key_encrypts_and_decrypts():
    vault = FakeVault()
    service = SharingService(vault)
    key_service = KeyExchangeService()

    private_key, public_key = key_service.generate_ecc_keypair()

    result = service.share_entry_with_public_key(
        entry_id="1",
        recipient="alice@example.com",
        public_key=public_key,
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    package = result["package"]

    assert package["cryptosafe_shared_package"] is True
    assert package["encryption"]["method"] == "ecc"
    assert "ephemeral_public_key" in package["encryption"]

    decrypted = service.decrypt_shared_package_with_private_key(
        package=package,
        private_key=private_key,
    )

    assert decrypted["entry"]["title"] == "GitHub"
    assert decrypted["entry"]["url"] == "https://github.com"


def test_share_entry_supports_excluding_password():
    vault = FakeVault()
    service = SharingService(vault)

    result = service.share_entry(
        entry_id="1",
        recipient="alice@example.com",
        permissions={"read": True, "edit": False, "include_password": False},
        expires_in=7,
    )

    package = result["package"]

    assert package["cryptosafe_shared_entry"] is True
    assert package["entry"]["title"] == "GitHub"
    assert "password" not in package["entry"]


def test_share_expiration_must_be_between_1_and_30_days():
    vault = FakeVault()
    service = SharingService(vault)

    with pytest.raises(SharingServiceError):
        service.share_entry_with_password(
            entry_id="1",
            recipient="alice@example.com",
            password="share-password",
            permissions={"read": True},
            expires_in=0,
        )

    with pytest.raises(SharingServiceError):
        service.share_entry_with_password(
            entry_id="1",
            recipient="alice@example.com",
            password="share-password",
            permissions={"read": True},
            expires_in=31,
        )


def test_import_shared_entry_temporarily_without_saving():
    vault = FakeVault()
    service = SharingService(vault)

    result = service.share_entry_with_password(
        entry_id="1",
        recipient="alice@example.com",
        password="share-password",
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    imported = service.import_shared_entry(
        package=result["package"],
        password="share-password",
        save_to_vault=False,
    )

    assert imported["status"] == "temporary"
    assert imported["entry"]["title"] == "GitHub"
    assert len(vault.saved_entries) == 0


def test_import_shared_entry_and_save_to_vault():
    vault = FakeVault()
    service = SharingService(vault)

    result = service.share_entry_with_password(
        entry_id="1",
        recipient="alice@example.com",
        password="share-password",
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    imported = service.import_shared_entry(
        package=result["package"],
        password="share-password",
        save_to_vault=True,
    )

    assert imported["status"] == "saved"
    assert imported["entry"]["title"] == "GitHub"
    assert len(vault.saved_entries) == 1
    assert vault.saved_entries[0]["title"] == "GitHub"


def test_tampered_shared_package_is_rejected():
    vault = FakeVault()
    service = SharingService(vault)

    result = service.share_entry_with_password(
        entry_id="1",
        recipient="alice@example.com",
        password="share-password",
        permissions={"read": True, "edit": False},
        expires_in=7,
    )

    package = result["package"]
    package["integrity"]["ciphertext_hash"] = "0" * 64

    with pytest.raises(SharingServiceError):
        service.decrypt_shared_package_with_password(
            package=package,
            password="share-password",
        )


def test_expired_shared_entry_is_rejected():
    vault = FakeVault()
    service = SharingService(vault)

    result = service.share_entry(
        entry_id="1",
        recipient="alice@example.com",
        permissions={"read": True, "edit": False},
        expires_in=1,
    )

    package = result["package"]
    package["expires_at"] = (datetime.utcnow() - timedelta(days=1)).isoformat()

    package["integrity"]["package_hash"] = service._package_checksum_without_integrity(package)

    with pytest.raises(SharingServiceError):
        service.import_shared_entry(
            package=package,
            save_to_vault=False,
        )