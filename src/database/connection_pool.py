from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from queue import Empty, Queue
from threading import Lock
from typing import Iterator


class SQLiteConnectionPoolError(Exception):
    """Базовая ошибка пула SQLite-соединений."""


class SQLiteConnectionPool:
    def __init__(
        self,
        db_path: str | Path,
        pool_size: int = 5,
        timeout: float = 30.0,
    ):
        self.db_path = Path(db_path)
        self.pool_size = pool_size
        self.timeout = timeout

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._pool: Queue[sqlite3.Connection] = Queue(maxsize=pool_size)
        self._created_connections = 0
        self._lock = Lock()
        self._closed = False

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            check_same_thread=False,
        )

        conn.row_factory = sqlite3.Row

        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")

        return conn

    def acquire(self) -> sqlite3.Connection:
        if self._closed:
            raise SQLiteConnectionPoolError("Пул соединений уже закрыт.")

        try:
            return self._pool.get_nowait()
        except Empty:
            pass

        with self._lock:
            if self._created_connections < self.pool_size:
                conn = self._create_connection()
                self._created_connections += 1
                return conn

        try:
            return self._pool.get(timeout=self.timeout)
        except Empty as exc:
            raise SQLiteConnectionPoolError(
                "Не удалось получить соединение из пула."
            ) from exc

    def release(self, conn: sqlite3.Connection) -> None:
        if self._closed:
            try:
                conn.close()
            except Exception:
                pass
            return

        try:
            self._pool.put_nowait(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.acquire()

        try:
            yield conn
        finally:
            self.release(conn)

    def close_all(self) -> None:
        self._closed = True

        while True:
            try:
                conn = self._pool.get_nowait()
            except Empty:
                break

            try:
                conn.close()
            except Exception:
                pass