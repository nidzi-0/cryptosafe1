from __future__ import annotations

from src.core.crypto.keychain import KeychainStorage


def test_keychain_storage_fallback(tmp_path):
    storage = KeychainStorage(service_name="CryptoSafeManagerTest")
    storage.fallback_path = tmp_path / "fallback.json"

    storage.store_secret("test_secret", "value123")

    assert storage.load_secret("test_secret") == "value123"

    storage.delete_secret("test_secret")

    assert storage.load_secret("test_secret") is None