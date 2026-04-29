from __future__ import annotations

import time

from src.core.crypto.key_storage import KeyCache, wipe_bytearray


def test_key_cache_store_and_get_key():
    cache = KeyCache(ttl_seconds=3600)
    key = b"a" * 32

    cache.store_key(key)

    assert cache.is_unlocked() is True
    assert cache.get_key() == key


def test_key_cache_clear_wipes_key():
    cache = KeyCache(ttl_seconds=3600)
    key = b"b" * 32

    cache.store_key(key)
    cache.clear()

    assert cache.is_unlocked() is False
    assert cache.get_key() is None


def test_key_cache_expires():
    cache = KeyCache(ttl_seconds=1)
    key = b"c" * 32

    cache.store_key(key)
    time.sleep(1.1)

    assert cache.get_key() is None
    assert cache.is_unlocked() is False


def test_key_cache_focus_lost_clears_key():
    cache = KeyCache(ttl_seconds=3600, clear_on_focus_lost=True)
    key = b"d" * 32

    cache.store_key(key)
    cache.on_focus_lost()

    assert cache.get_key() is None


def test_wipe_bytearray_sets_zeroes():
    buf = bytearray(b"secret-key")
    wipe_bytearray(buf)

    assert all(b == 0 for b in buf)