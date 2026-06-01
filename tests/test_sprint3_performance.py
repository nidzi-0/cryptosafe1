from __future__ import annotations

import os
import time
import tracemalloc

import pytest

from src.core.crypto.key_manager import CachedKeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.entry_manager import EntryManager


TOTAL_ENTRIES = 1000

MAX_LOAD_SECONDS = 2.0
MAX_SEARCH_SECONDS = 0.2
MAX_MEMORY_MB = 50.0


def make_manager(tmp_path) -> EntryManager:
    db_path = tmp_path / "performance_vault.db"

    key_manager = CachedKeyManager(b"K" * 32)
    encryption_service = AESGCMEncryptionService(key_manager)

    return EntryManager(
        db_path=db_path,
        encryption_service=encryption_service,
    )


def populate_entries(manager: EntryManager, count: int = TOTAL_ENTRIES) -> None:
    for i in range(count):
        manager.create_entry(
            {
                "title": f"Performance Entry {i}",
                "username": f"user{i}@example.com",
                "password": f"StrongPassword{i}!A1",
                "url": f"https://service{i}.example.com",
                "notes": f"performance test notes {i}",
                "category": "performance" if i % 2 == 0 else "common",
                "tags": f"perf,test,entry{i}",
            }
        )


@pytest.mark.performance
def test_perf_load_1000_entries_under_2_seconds(tmp_path):
    manager = make_manager(tmp_path)
    populate_entries(manager, TOTAL_ENTRIES)

    start = time.perf_counter()
    entries = manager.get_all_entries()
    elapsed = time.perf_counter() - start

    assert len(entries) == TOTAL_ENTRIES
    assert elapsed < MAX_LOAD_SECONDS, (
        f"Загрузка {TOTAL_ENTRIES} записей заняла {elapsed:.3f} сек., "
        f"лимит {MAX_LOAD_SECONDS:.3f} сек."
    )


@pytest.mark.performance
def test_perf_search_1000_entries_under_200_ms(tmp_path):
    manager = make_manager(tmp_path)
    populate_entries(manager, TOTAL_ENTRIES)

    manager.rebuild_search_index()

    start = time.perf_counter()
    result_ids = manager.search_in_index("entry999")
    elapsed = time.perf_counter() - start

    assert result_ids
    assert elapsed < MAX_SEARCH_SECONDS, (
        f"Поиск среди {TOTAL_ENTRIES} записей занял {elapsed:.3f} сек., "
        f"лимит {MAX_SEARCH_SECONDS:.3f} сек."
    )


@pytest.mark.performance
def test_perf_memory_under_50_mb_for_1000_entries(tmp_path):
    manager = make_manager(tmp_path)
    populate_entries(manager, TOTAL_ENTRIES)

    tracemalloc.start()

    entries = manager.get_all_entries()
    manager.rebuild_search_index()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024

    assert len(entries) == TOTAL_ENTRIES
    assert peak_mb < MAX_MEMORY_MB, (
        f"Пиковое использование памяти: {peak_mb:.2f} МБ, "
        f"лимит {MAX_MEMORY_MB:.2f} МБ."
    )


@pytest.mark.performance
def test_perf_database_file_size_reasonable_for_1000_entries(tmp_path):
    db_path = tmp_path / "performance_vault.db"

    key_manager = CachedKeyManager(b"K" * 32)
    encryption_service = AESGCMEncryptionService(key_manager)

    manager = EntryManager(
        db_path=db_path,
        encryption_service=encryption_service,
    )

    populate_entries(manager, TOTAL_ENTRIES)

    size_mb = os.path.getsize(db_path) / 1024 / 1024

    assert size_mb < 20.0, (
        f"Размер базы после {TOTAL_ENTRIES} записей: {size_mb:.2f} МБ."
    )