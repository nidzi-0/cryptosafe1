from __future__ import annotations

import time

from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    KeyDerivationManager,
    PasswordPolicy,
)
from src.core.crypto.key_storage import KeyCache
from src.core.crypto.placeholder import AES256Placeholder


class DummyKeyManager:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def get_encryption_key(self) -> bytes:
        return self.key


def test_placeholder_encrypt_decrypt_roundtrip():
    key_manager = DummyKeyManager(b"test_key_1234567890123456789012")
    crypto = AES256Placeholder(key_manager)

    plaintext = b"secret data"

    ciphertext = crypto.encrypt(plaintext)
    restored = crypto.decrypt(ciphertext)

    assert ciphertext != plaintext
    assert restored == plaintext


def test_argon2_params_are_valid():
    manager = KeyDerivationManager()

    auth_hash = manager.create_auth_hash("StrongPass123!")

    assert isinstance(auth_hash, str)
    assert "$argon2id$" in auth_hash
    assert manager.verify_password("StrongPass123!", auth_hash) is True


def test_argon2_different_params_produce_valid_hashes():
    variants = [
        Argon2Params(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16),
        Argon2Params(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16),
        Argon2Params(time_cost=4, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16),
    ]

    password = "StrongPass123!"

    for params in variants:
        manager = KeyDerivationManager(argon2_params=params)
        auth_hash = manager.create_auth_hash(password)

        assert "$argon2id$" in auth_hash
        assert manager.verify_password(password, auth_hash) is True


def test_invalid_argon2_params_rejected():
    try:
        KeyDerivationManager(
            argon2_params=Argon2Params(time_cost=1),
            pbkdf2_params=PBKDF2Params(),
        )
    except ValueError as exc:
        assert "time_cost" in str(exc)
    else:
        raise AssertionError("Ожидалась ошибка параметров Argon2")


def test_pbkdf2_key_consistency_100_times():
    manager = KeyDerivationManager()

    password = "StrongPassword123!"
    salt = b"1234567890abcdef"

    first_key = manager.derive_encryption_key(password, salt)

    for _ in range(100):
        new_key = manager.derive_encryption_key(password, salt)
        assert new_key == first_key

    assert len(first_key) == 32


def test_verify_password_success_and_failure():
    manager = KeyDerivationManager()
    auth_hash = manager.create_auth_hash("StrongPass123!")

    assert manager.verify_password("StrongPass123!", auth_hash) is True
    assert manager.verify_password("WrongPass123!", auth_hash) is False


def test_constant_time_password_verification():
    manager = KeyDerivationManager()

    password = "StrongPassword123!"
    wrong_password = "WrongPassword123!"

    stored_hash = manager.create_auth_hash(password)

    start_ok = time.perf_counter()
    for _ in range(20):
        manager.verify_password(password, stored_hash)
    ok_time = time.perf_counter() - start_ok

    start_bad = time.perf_counter()
    for _ in range(20):
        manager.verify_password(wrong_password, stored_hash)
    bad_time = time.perf_counter() - start_bad

    diff = abs(ok_time - bad_time)

    assert ok_time > 0
    assert bad_time > 0
    assert diff < 1.0


def test_password_policy_accepts_strong_password():
    policy = PasswordPolicy()

    result = policy.validate("StrongPass123!")

    assert result.valid is True
    assert result.errors == []


def test_password_policy_rejects_weak_password():
    policy = PasswordPolicy()

    result = policy.validate("password123")

    assert result.valid is False
    assert len(result.errors) > 0


def test_memory_wipe_after_clear():
    cache = KeyCache()

    key = b"A" * 32

    cache.store_key(key)

    internal_buffer = cache._cached_key.key

    cache.clear()

    assert internal_buffer != bytearray(b"A" * 32)
    assert all(b == 0 for b in internal_buffer)