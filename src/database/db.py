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

        version = int(conn.execute("PRAGMA user_version;").fetchone()[0])

        if version == 0:
            conn.executescript(SCHEMA_SQL)
            conn.execute("PRAGMA user_version = 1;")
            version = 1

        if version < 2:
            self._migrate_v1_to_v2(conn)
            conn.execute("PRAGMA user_version = 2;")

        conn.commit()

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL UNIQUE,
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_keystore_type
            ON key_store(key_type);
            """
        )

        columns = conn.execute("PRAGMA table_info(key_store);").fetchall()
        column_names = {row["name"] for row in columns}

        if "key_data" not in column_names:
            conn.execute("ALTER TABLE key_store ADD COLUMN key_data BLOB;")

        if "version" not in column_names:
            conn.execute("ALTER TABLE key_store ADD COLUMN version INTEGER NOT NULL DEFAULT 1;")

        if "created_at" not in column_names:
            conn.execute("ALTER TABLE key_store ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP;")

    def backup_stub(self) -> None:
        raise NotImplementedError("Заглушка Sprint 1")

    def restore_stub(self) -> None:
        raise NotImplementedError("Заглушка Sprint 1")