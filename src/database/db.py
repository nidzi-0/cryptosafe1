from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .schema import SCHEMA_SQL


class Database:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self._local = threading.local()

    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path.as_posix(), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def init_schema(self) -> None:
        conn = self.connect()
        conn.executescript(SCHEMA_SQL)

        version = int(conn.execute("PRAGMA user_version;").fetchone()[0])

        if version < 1:
            conn.execute("PRAGMA user_version = 1;")
            version = 1

        if version < 2:
            self._migrate_to_v2(conn)
            conn.execute("PRAGMA user_version = 2;")

        conn.commit()

    def _migrate_to_v2(self, conn: sqlite3.Connection) -> None:
        columns = conn.execute("PRAGMA table_info(key_store);").fetchall()
        names = {row["name"] for row in columns}

        required = {"id", "key_type", "key_data", "version", "created_at"}

        if required.issubset(names):
            return

        conn.execute("ALTER TABLE key_store RENAME TO key_store_old;")

        conn.execute(
            """
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL UNIQUE,
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            """
        )

        old_columns = conn.execute("PRAGMA table_info(key_store_old);").fetchall()
        old_names = {row["name"] for row in old_columns}

        if {"key_type", "salt"}.issubset(old_names):
            rows = conn.execute("SELECT key_type, salt FROM key_store_old WHERE salt IS NOT NULL;").fetchall()
            for row in rows:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO key_store(key_type, key_data, version, created_at)
                    VALUES(?, ?, 1, datetime('now'))
                    """,
                    (row["key_type"], row["salt"]),
                )

        if {"key_type", "hash"}.issubset(old_names):
            rows = conn.execute("SELECT key_type, hash FROM key_store_old WHERE hash IS NOT NULL;").fetchall()
            for row in rows:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO key_store(key_type, key_data, version, created_at)
                    VALUES(?, ?, 1, datetime('now'))
                    """,
                    (row["key_type"], row["hash"]),
                )

        conn.execute("DROP TABLE key_store_old;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keystore_type ON key_store(key_type);")

    def backup_stub(self) -> None:
        raise NotImplementedError("Заглушка Sprint 1")

    def restore_stub(self) -> None:
        raise NotImplementedError("Заглушка Sprint 1")