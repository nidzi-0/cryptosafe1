from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EntryManagerError(Exception):
    """Базовая ошибка менеджера записей."""


class EntryNotFoundError(EntryManagerError):
    """Ошибка, если запись не найдена."""


class EntryValidationError(EntryManagerError):
    """Ошибка проверки данных записи."""


class EntryManager:
    REQUIRED_FIELDS = ("title", "password")

    ENCRYPTED_FIELDS = (
        "title",
        "username",
        "password",
        "url",
        "notes",
        "category",
        "tags",
    )

    def __init__(self, db_path: str | Path, encryption_service):
        self.db_path = Path(db_path)
        self.encryption_service = encryption_service

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_table_exists()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _ensure_table_exists(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    title_encrypted BLOB NOT NULL,
                    username_encrypted BLOB,
                    password_encrypted BLOB NOT NULL,
                    url_encrypted BLOB,
                    notes_encrypted BLOB,
                    category_encrypted BLOB,
                    tags_encrypted BLOB,

                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deleted_at TEXT
                )
                """
            )
            conn.commit()

    def _encrypt_text(self, value: Any) -> bytes:
        if value is None:
            value = ""

        text = str(value)

        encrypted = self.encryption_service.encrypt(text)

        if isinstance(encrypted, str):
            return encrypted.encode("utf-8")

        return encrypted

    def _decrypt_text(self, value: bytes | None) -> str:
        if value is None:
            return ""

        decrypted = self.encryption_service.decrypt(value)

        if isinstance(decrypted, bytes):
            return decrypted.decode("utf-8")

        return str(decrypted)

    def _validate_entry_data(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise EntryValidationError("Данные записи должны быть словарём.")

        title = str(data.get("title", "")).strip()
        password = str(data.get("password", ""))

        if not title:
            raise EntryValidationError("Название записи не может быть пустым.")

        if not password:
            raise EntryValidationError("Пароль не может быть пустым.")

    def _row_to_entry(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "title": self._decrypt_text(row["title_encrypted"]),
            "username": self._decrypt_text(row["username_encrypted"]),
            "password": self._decrypt_text(row["password_encrypted"]),
            "url": self._decrypt_text(row["url_encrypted"]),
            "notes": self._decrypt_text(row["notes_encrypted"]),
            "category": self._decrypt_text(row["category_encrypted"]),
            "tags": self._decrypt_text(row["tags_encrypted"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "deleted_at": row["deleted_at"],
        }

    def create_entry(self, data: dict[str, Any]) -> int:
        self._validate_entry_data(data)

        now = self._now()

        encrypted = {
            field: self._encrypt_text(data.get(field, ""))
            for field in self.ENCRYPTED_FIELDS
        }

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vault_entries (
                    title_encrypted,
                    username_encrypted,
                    password_encrypted,
                    url_encrypted,
                    notes_encrypted,
                    category_encrypted,
                    tags_encrypted,
                    created_at,
                    updated_at,
                    deleted_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    encrypted["title"],
                    encrypted["username"],
                    encrypted["password"],
                    encrypted["url"],
                    encrypted["notes"],
                    encrypted["category"],
                    encrypted["tags"],
                    now,
                    now,
                ),
            )
            conn.commit()

            entry_id = int(cursor.lastrowid)

        self._write_audit_log("create_entry", f"Создана запись id={entry_id}")

        return entry_id

    def get_entry(self, entry_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM vault_entries
                WHERE id = ?
                  AND deleted_at IS NULL
                """,
                (entry_id,),
            ).fetchone()

        if row is None:
            raise EntryNotFoundError(f"Запись с id={entry_id} не найдена.")

        return self._row_to_entry(row)

    def get_all_entries(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM vault_entries
                WHERE deleted_at IS NULL
                ORDER BY updated_at DESC, id DESC
                """
            ).fetchall()

        return [self._row_to_entry(row) for row in rows]

    def update_entry(self, entry_id: int, data: dict[str, Any]) -> None:
        self._validate_entry_data(data)

        self.get_entry(entry_id)

        now = self._now()

        encrypted = {
            field: self._encrypt_text(data.get(field, ""))
            for field in self.ENCRYPTED_FIELDS
        }

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET
                    title_encrypted = ?,
                    username_encrypted = ?,
                    password_encrypted = ?,
                    url_encrypted = ?,
                    notes_encrypted = ?,
                    category_encrypted = ?,
                    tags_encrypted = ?,
                    updated_at = ?
                WHERE id = ?
                  AND deleted_at IS NULL
                """,
                (
                    encrypted["title"],
                    encrypted["username"],
                    encrypted["password"],
                    encrypted["url"],
                    encrypted["notes"],
                    encrypted["category"],
                    encrypted["tags"],
                    now,
                    entry_id,
                ),
            )
            conn.commit()

        self._write_audit_log("update_entry", f"Обновлена запись id={entry_id}")

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        self.get_entry(entry_id)

        now = self._now()

        with self._connect() as conn:
            if soft_delete:
                conn.execute(
                    """
                    UPDATE vault_entries
                    SET deleted_at = ?,
                        updated_at = ?
                    WHERE id = ?
                      AND deleted_at IS NULL
                    """,
                    (
                        now,
                        now,
                        entry_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    DELETE FROM vault_entries
                    WHERE id = ?
                    """,
                    (entry_id,),
                )

            conn.commit()

        self._write_audit_log("delete_entry", f"Удалена запись id={entry_id}")

    def search_entries(self, query: str) -> list[dict[str, Any]]:
        query = query.strip().lower()

        if not query:
            return self.get_all_entries()

        result = []

        for entry in self.get_all_entries():
            text = " ".join(
                [
                    str(entry.get("title", "")),
                    str(entry.get("username", "")),
                    str(entry.get("url", "")),
                    str(entry.get("notes", "")),
                    str(entry.get("category", "")),
                    str(entry.get("tags", "")),
                ]
            ).lower()

            if query in text:
                result.append(entry)

        return result

    def count_entries(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM vault_entries
                WHERE deleted_at IS NULL
                """
            ).fetchone()

        return int(row["count"])

    def _write_audit_log(self, action: str, details: str = "") -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        details TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )

                conn.execute(
                    """
                    INSERT INTO audit_log (
                        action,
                        details,
                        created_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        action,
                        details,
                        self._now(),
                    ),
                )

                conn.commit()
        except Exception:
            pass