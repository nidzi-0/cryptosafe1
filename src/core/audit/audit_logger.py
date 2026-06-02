from __future__ import annotations

import hashlib
import json
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.audit.log_signer import AuditLogSigner


class AuditLoggerError(Exception):
    """Базовая ошибка audit logger."""


class AuditSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    severity: str
    source: str
    details: dict[str, Any]
    user_id: str = "local_user"
    entry_id: int | str | None = None


class AuditLogger:

    ZERO_HASH = "0" * 64

    SENSITIVE_KEYS = {
        "password",
        "pass",
        "secret",
        "token",
        "key",
        "private_key",
        "master_key",
        "encryption_key",
        "clipboard",
        "plaintext",
    }

    def __init__(
        self,
        db_path: str | Path,
        signer: AuditLogSigner,
        user_id: str = "local_user",
    ):
        self.db_path = Path(db_path)
        self.signer = signer
        self.user_id = user_id
        self._lock = threading.RLock()

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row

        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.execute("PRAGMA cache_size=-20000")

        self._ensure_tables_exist()
        self._ensure_public_key_stored()
        self._ensure_genesis_entry()

    def _connect(self) -> sqlite3.Connection:
        return self._conn

    def _table_columns(self, conn: sqlite3.Connection, table_name: str) -> set[str]:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row["name"] for row in rows}

    def _table_exists(self, conn: sqlite3.Connection, table_name: str) -> bool:
        row = conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = ?
            """,
            (table_name,),
        ).fetchone()

        return row is not None

    def _ensure_tables_exist(self) -> None:
        with self._lock:
            with self._conn:
                if self._table_exists(self._conn, "audit_log"):
                    columns = self._table_columns(self._conn, "audit_log")

                    if "sequence_number" not in columns:
                        legacy_name = (
                            f"audit_log_legacy_{int(datetime.now().timestamp())}"
                        )
                        self._conn.execute(
                            f"""
                            ALTER TABLE audit_log
                            RENAME TO {legacy_name}
                            """
                        )

                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_log (
                        sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        entry_id TEXT,
                        previous_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL,
                        entry_data BLOB NOT NULL,
                        signature TEXT NOT NULL,
                        signing_algorithm TEXT NOT NULL
                    )
                    """
                )

                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_public_keys (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        algorithm TEXT NOT NULL,
                        public_key TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )

                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                    ON audit_log(timestamp)
                    """
                )

                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
                    ON audit_log(event_type)
                    """
                )

                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_log_sequence_number
                    ON audit_log(sequence_number)
                    """
                )

                self._conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_log_severity
                    ON audit_log(severity)
                    """
                )

    def _ensure_public_key_stored(self) -> None:
        key_info = self.signer.get_key_info()

        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO audit_public_keys (
                        id,
                        algorithm,
                        public_key,
                        created_at
                    )
                    VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        algorithm = excluded.algorithm,
                        public_key = excluded.public_key
                    """,
                    (
                        key_info.algorithm,
                        key_info.public_key_hex,
                        self._now(),
                    ),
                )

    def _ensure_genesis_entry(self) -> None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM audit_log
                """
            ).fetchone()

        if int(row["count"]) == 0:
            self.log_event(
                event_type="SYSTEM_GENESIS",
                severity=AuditSeverity.INFO.value,
                source="audit_logger",
                details={"message": "Audit log initialized"},
                user_id="system",
            )

    def _now(self) -> str:
        """
        COMP-2:
        timestamp ISO 8601 with UTC timezone.
        """
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _get_previous_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            """
            SELECT entry_hash
            FROM audit_log
            ORDER BY sequence_number DESC
            LIMIT 1
            """
        ).fetchone()

        if row is None:
            return self.ZERO_HASH

        return str(row["entry_hash"])

    def _sanitize_details(self, value: Any) -> Any:
        """
        LOG-3:
        чувствительные данные не попадают в audit log.
        """
        if isinstance(value, dict):
            result = {}

            for key, item in value.items():
                normalized_key = str(key).lower()

                if any(sensitive in normalized_key for sensitive in self.SENSITIVE_KEYS):
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self._sanitize_details(item)

            return result

        if isinstance(value, list):
            return [self._sanitize_details(item) for item in value]

        if isinstance(value, tuple):
            return [self._sanitize_details(item) for item in value]

        return value

    def _canonical_json(self, data: dict[str, Any]) -> str:
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def log_event(
        self,
        event_type: str,
        severity: str = AuditSeverity.INFO.value,
        source: str = "system",
        details: dict[str, Any] | None = None,
        user_id: str | None = None,
        entry_id: int | str | None = None,
    ) -> int:
        with self._lock:
            details = details or {}

            with self._conn:
                previous_hash = self._get_previous_hash(self._conn)

                entry = {
                    "timestamp": self._now(),
                    "event_type": str(event_type),
                    "severity": str(severity),
                    "user_id": str(user_id or self.user_id),
                    "source": str(source),
                    "details": self._sanitize_details(details),
                    "entry_id": None if entry_id is None else str(entry_id),
                    "previous_hash": previous_hash,
                }

                entry_json = self._canonical_json(entry)
                entry_bytes = entry_json.encode("utf-8")
                entry_hash = hashlib.sha256(entry_bytes).hexdigest()
                signature = self.signer.sign(entry_bytes).hex()
                key_info = self.signer.get_key_info()

                cursor = self._conn.execute(
                    """
                    INSERT INTO audit_log (
                        timestamp,
                        event_type,
                        severity,
                        user_id,
                        source,
                        entry_id,
                        previous_hash,
                        entry_hash,
                        entry_data,
                        signature,
                        signing_algorithm
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["timestamp"],
                        entry["event_type"],
                        entry["severity"],
                        entry["user_id"],
                        entry["source"],
                        entry["entry_id"],
                        previous_hash,
                        entry_hash,
                        entry_bytes,
                        signature,
                        key_info.algorithm,
                    ),
                )

                return int(cursor.lastrowid)

    def handle_event(self, event: object) -> None:
        event_type = event.__class__.__name__
        details = {}

        if hasattr(event, "__dataclass_fields__"):
            details = {
                field: getattr(event, field)
                for field in event.__dataclass_fields__
            }
        elif hasattr(event, "__dict__"):
            details = dict(event.__dict__)
        else:
            details = {"repr": repr(event)}

        severity = AuditSeverity.INFO.value

        if "Failed" in event_type or "Error" in event_type:
            severity = AuditSeverity.WARN.value

        if "Security" in event_type or "Tamper" in event_type:
            severity = AuditSeverity.CRITICAL.value

        entry_id = details.get("entry_id") or details.get("source_entry_id")

        self.log_event(
            event_type=event_type,
            severity=severity,
            source="event_system",
            details=details,
            entry_id=entry_id,
        )

    def query_logs(
        self,
        event_type: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT *
            FROM audit_log
            WHERE 1 = 1
        """
        params: list[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if search:
            query += " AND entry_data LIKE ?"
            params.append(f"%{search}%")

        query += """
            ORDER BY sequence_number DESC
            LIMIT ?
            OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def count_logs(self) -> int:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM audit_log
                """
            ).fetchone()

        return int(row["count"])

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        data_raw = row["entry_data"]

        if isinstance(data_raw, bytes):
            data_text = data_raw.decode("utf-8")
        else:
            data_text = str(data_raw)

        try:
            entry_data = json.loads(data_text)
        except Exception:
            entry_data = {"raw": data_text}

        return {
            "sequence_number": row["sequence_number"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "severity": row["severity"],
            "user_id": row["user_id"],
            "source": row["source"],
            "entry_id": row["entry_id"],
            "previous_hash": row["previous_hash"],
            "entry_hash": row["entry_hash"],
            "entry_data": entry_data,
            "signature": row["signature"],
            "signing_algorithm": row["signing_algorithm"],
        }

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


class AuditLoggerAsync(AuditLogger):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._async_queue: queue.Queue = queue.Queue()
        self._async_stop_event = threading.Event()
        self._async_thread = threading.Thread(
            target=self._process_queue,
            name="AuditLoggerAsync",
            daemon=True,
        )
        self._async_thread.start()

    def log_event_async(self, *args, **kwargs) -> None:
        self._async_queue.put((args, kwargs))

    def _process_queue(self) -> None:
        while not self._async_stop_event.is_set():
            try:
                args, kwargs = self._async_queue.get(timeout=0.1)

                try:
                    self.log_event(*args, **kwargs)
                finally:
                    self._async_queue.task_done()

            except queue.Empty:
                continue
            except Exception:
                time.sleep(0.1)

    def flush_async(self, timeout: float | None = None) -> None:
        self._async_queue.join()

    def close_async(self) -> None:
        self.flush_async()
        self._async_stop_event.set()
        self._async_thread.join(timeout=2)
        self.close()