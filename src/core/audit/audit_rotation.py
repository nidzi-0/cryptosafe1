from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


class AuditRotationError(Exception):
    """Ошибка политики ротации audit log."""


@dataclass
class AuditRotationPolicy:
    max_entries: int = 10_000
    max_age_days: int = 365
    archive_enabled: bool = True


class AuditLogRotator:
    def __init__(
        self,
        db_path: str | Path,
        policy: AuditRotationPolicy | None = None,
        audit_logger=None,
    ):
        self.db_path = Path(db_path)
        self.policy = policy or AuditRotationPolicy()
        self.audit_logger = audit_logger
        self._ensure_archive_table()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_archive_table(self) -> None:
        with self._connect() as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_log_archive (
                        archive_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        archived_at TEXT NOT NULL,
                        archive_reason TEXT NOT NULL,
                        original_sequence_number INTEGER NOT NULL,
                        original_row_json TEXT NOT NULL
                    )
                    """
                )

                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_log_archive_original_sequence
                    ON audit_log_archive(original_sequence_number)
                    """
                )

    def rotate_if_needed(self) -> dict:
        archived_by_count = self._rotate_by_count()
        archived_by_age = self._rotate_by_age()

        result = {
            "archived_by_count": archived_by_count,
            "archived_by_age": archived_by_age,
            "total_archived": archived_by_count + archived_by_age,
        }

        if result["total_archived"] > 0 and self.audit_logger is not None:
            try:
                self.audit_logger.log_event(
                    event_type="AUDIT_LOG_ROTATED",
                    severity="INFO",
                    source="audit_rotator",
                    details=result,
                )
            except Exception:
                pass

        return result

    def _rotate_by_count(self) -> int:
        if self.policy.max_entries <= 0:
            return 0

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence_number
                FROM audit_log
                ORDER BY sequence_number ASC
                """
            ).fetchall()

        overflow = len(rows) - self.policy.max_entries

        if overflow <= 0:
            return 0

        candidates = [
            int(row["sequence_number"])
            for row in rows
            if int(row["sequence_number"]) > 1
        ][:overflow]

        return self._archive_sequences(
            candidates,
            reason="max_entries_exceeded",
        )

    def _rotate_by_age(self) -> int:
        if self.policy.max_age_days <= 0:
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.policy.max_age_days)
        cutoff_text = cutoff.isoformat(timespec="seconds")

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sequence_number
                FROM audit_log
                WHERE timestamp < ?
                  AND sequence_number > 1
                ORDER BY sequence_number ASC
                """,
                (cutoff_text,),
            ).fetchall()

        candidates = [
            int(row["sequence_number"])
            for row in rows
        ]

        return self._archive_sequences(
            candidates,
            reason="max_age_exceeded",
        )

    def _archive_sequences(self, sequence_numbers: list[int], reason: str) -> int:
        if not sequence_numbers:
            return 0

        archived = 0

        with self._connect() as conn:
            with conn:
                for sequence_number in sequence_numbers:
                    row = conn.execute(
                        """
                        SELECT *
                        FROM audit_log
                        WHERE sequence_number = ?
                        """,
                        (sequence_number,),
                    ).fetchone()

                    if row is None:
                        continue

                    row_dict = {
                        key: row[key]
                        for key in row.keys()
                    }

                    entry_data = row_dict.get("entry_data")

                    if isinstance(entry_data, bytes):
                        try:
                            row_dict["entry_data"] = entry_data.decode("utf-8")
                        except UnicodeDecodeError:
                            row_dict["entry_data"] = entry_data.hex()

                    if self.policy.archive_enabled:
                        conn.execute(
                            """
                            INSERT INTO audit_log_archive (
                                archived_at,
                                archive_reason,
                                original_sequence_number,
                                original_row_json
                            )
                            VALUES (?, ?, ?, ?)
                            """,
                            (
                                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                reason,
                                sequence_number,
                                json.dumps(row_dict, ensure_ascii=False, sort_keys=True),
                            ),
                        )

                    conn.execute(
                        """
                        DELETE FROM audit_log
                        WHERE sequence_number = ?
                        """,
                        (sequence_number,),
                    )

                    archived += 1

        return archived