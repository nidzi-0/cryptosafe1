from __future__ import annotations


def test_schema_tables_exist(tmp_db):
    conn = tmp_db.connect()
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "vault_entries" in tables
    assert "audit_log" in tables
    assert "settings" in tables
    assert "key_store" in tables


def test_user_version_set(tmp_db):
    conn = tmp_db.connect()
    v = int(conn.execute("PRAGMA user_version").fetchone()[0])
    assert v >= 1