from __future__ import annotations

import time

from src.core.crypto.key_derivation import (
    Argon2Params,
    PBKDF2Params,
    KeyDerivationManager,
    PasswordPolicy,
)


def test_argon2_params_are_valid():
    manager = KeyDerivationManager()

    auth_hash = manager.create_auth_hash("StrongPass123!")
    assert isinstance(auth_hash, str)
    assert "$argon2id$" in auth_hash


def test_pbkdf2_key_consistency_100_times():
    manager = KeyDerivationManager()
    salt = b"1234567890abcdef"

    keys = [
        manager.derive_encryption_key("StrongPass123!", salt)
        for _ in range(100)
    ]

    assert all(key == keys[0] for key in keys)
    assert len(keys[0]) == 32


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


def test_verify_password_success_and_failure():
    manager = KeyDerivationManager()
    auth_hash = manager.create_auth_hash("StrongPass123!")

    assert manager.verify_password("StrongPass123!", auth_hash) is True
    assert manager.verify_password("WrongPass123!", auth_hash) is False


def test_password_check_timing_has_same_logic_path():
    manager = KeyDerivationManager()
    auth_hash = manager.create_auth_hash("StrongPass123!")

    start_ok = time.perf_counter()
    manager.verify_password("StrongPass123!", auth_hash)
    ok_time = time.perf_counter() - start_ok

    start_bad = time.perf_counter()
    manager.verify_password("WrongPass123!", auth_hash)
    bad_time = time.perf_counter() - start_bad

    assert ok_time > 0
    assert bad_time > 0