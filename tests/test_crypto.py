from __future__ import annotations
from src.core.crypto.placeholder import AES256Placeholder


def test_placeholder_encrypt_decrypt_roundtrip():
    crypto = AES256Placeholder()
    key = b"key"
    data = b"secret"
    ct = crypto.encrypt(data, key)
    pt = crypto.decrypt(ct, key)
    assert pt == data