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

        ver = int(conn.execute("PRAGMA user_version;").fetchone()[0])
        if ver == 0:
            conn.execute("PRAGMA user_version = 1;")

        conn.commit()

    def backup_stub(self) -> None:
        raise NotImplementedError("Sprint 1 placeholder")

    def restore_stub(self) -> None:
        raise NotImplementedError("Sprint 1 placeholder")