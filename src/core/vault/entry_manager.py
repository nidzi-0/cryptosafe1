from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from src.database.connection_pool import SQLiteConnectionPool


Entry = dict[str, Any]


class EntryManagerError(Exception):
    """Базовая ошибка менеджера записей."""


class EntryNotFoundError(EntryManagerError):
    """Ошибка, если запись не найдена."""


class EntryValidationError(EntryManagerError):
    """Ошибка проверки данных записи."""


class EventPublisherError(EntryManagerError):
    """Ошибка публикации события."""


@dataclass(frozen=True)
class EntryCreated:
    entry: Entry
    created_at: str


@dataclass(frozen=True)
class EntryUpdated:
    entry: Entry
    updated_at: str


@dataclass(frozen=True)
class EntryDeleted:
    entry_id: int
    deleted_at: str
    expires_at: str | None
    soft_delete: bool


@dataclass(frozen=True)
class ClipboardCopyRequested:
    entry_id: int
    field_name: str
    requested_at: str


Event = EntryCreated | EntryUpdated | EntryDeleted | ClipboardCopyRequested
EventHandler = Callable[[Event], None]


class EventPublisher:
    def __init__(self):
        self._subscribers: list[EventHandler] = []
        self._history: list[Event] = []

    def subscribe(self, handler: EventHandler) -> None:
        self._subscribers.append(handler)

    def publish(self, event: Event) -> None:
        self._history.append(event)

        for handler in self._subscribers:
            handler(event)

    def get_history(self) -> list[Event]:
        return list(self._history)


class EntryManager:
    REQUIRED_FIELDS = ("title", "password")

    ENTRY_FIELDS = (
        "title",
        "username",
        "password",
        "url",
        "notes",
        "category",
        "tags",

        # FUTURE-1
        "totp_secret",
        "shared_metadata",
    )

    SEARCHABLE_FIELDS = (
        "title",
        "username",
        "url",
        "notes",
        "category",
        "tags",
    )

    DEFAULT_DELETED_RETENTION_DAYS = 30

    def __init__(
        self,
        db_path: str | Path,
        encryption_service,
        event_publisher: EventPublisher | None = None,
        deleted_retention_days: int = DEFAULT_DELETED_RETENTION_DAYS,
        connection_pool: SQLiteConnectionPool | None = None,
    ):
        self.db_path = Path(db_path)
        self.encryption_service = encryption_service
        self.event_publisher = event_publisher or EventPublisher()
        self.deleted_retention_days = deleted_retention_days

        self.connection_pool = connection_pool or SQLiteConnectionPool(
            db_path=self.db_path,
            pool_size=5,
        )

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._search_index: dict[int, str] = {}

        self._ensure_tables_exist()
        self.rebuild_search_index()

    def subscribe(self, handler: EventHandler) -> None:
        self.event_publisher.subscribe(handler)

    def get_published_events(self) -> list[Event]:
        return self.event_publisher.get_history()

    def _connection(self):
        return self.connection_pool.connection()

    def close(self) -> None:
        self.connection_pool.close_all()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _expires_at(self) -> str:
        expires = datetime.now(timezone.utc) + timedelta(days=self.deleted_retention_days)
        return expires.isoformat(timespec="seconds")

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

    def _get_columns(self, conn: sqlite3.Connection, table_name: str) -> set[str]:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row["name"] for row in rows}

    def _ensure_tables_exist(self) -> None:
        with self._connection() as conn:
            with conn:
                if self._table_exists(conn, "vault_entries"):
                    columns = self._get_columns(conn, "vault_entries")

                    if "encrypted_data" not in columns:
                        legacy_name = (
                            f"vault_entries_legacy_{int(datetime.now().timestamp())}"
                        )

                        conn.execute(
                            f"""
                            ALTER TABLE vault_entries
                            RENAME TO {legacy_name}
                            """
                        )
                    else:
                        if "tags" not in columns:
                            conn.execute(
                                """
                                ALTER TABLE vault_entries
                                ADD COLUMN tags TEXT NOT NULL DEFAULT ''
                                """
                            )

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vault_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        encrypted_data BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        tags TEXT NOT NULL DEFAULT '',
                        deleted_at TEXT
                    )
                    """
                )

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS deleted_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_entry_id INTEGER NOT NULL,
                        encrypted_data BLOB NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        deleted_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        tags TEXT NOT NULL DEFAULT ''
                    )
                    """
                )

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
                    CREATE TABLE IF NOT EXISTS search_index_metadata (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        strategy TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )

                conn.execute(
                    """
                    INSERT INTO search_index_metadata (
                        id,
                        strategy,
                        updated_at
                    )
                    VALUES (1, 'application_level_decrypted_runtime_index', ?)
                    ON CONFLICT(id) DO UPDATE SET
                        strategy = excluded.strategy,
                        updated_at = excluded.updated_at
                    """,
                    (self._now(),),
                )

                self._create_indexes(conn)

    def _create_indexes(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at
            ON vault_entries(created_at)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at
            ON vault_entries(updated_at)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vault_entries_tags
            ON vault_entries(tags)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vault_entries_deleted_at
            ON vault_entries(deleted_at)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_deleted_entries_original_entry_id
            ON deleted_entries(original_entry_id)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_deleted_entries_expires_at
            ON deleted_entries(expires_at)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
            ON audit_log(created_at)
            """
        )

    def _validate_entry_data(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise EntryValidationError("Данные записи должны быть словарём.")

        title = str(data.get("title", "")).strip()
        password = str(data.get("password", ""))

        if not title:
            raise EntryValidationError("Название записи не может быть пустым.")

        if not password:
            raise EntryValidationError("Пароль не может быть пустым.")

    def _normalize_entry_data(self, data: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}

        for field in self.ENTRY_FIELDS:
            value = data.get(field, "")

            if field == "shared_metadata":
                if value is None or value == "":
                    value = {}
                elif not isinstance(value, dict):
                    value = {
                        "raw": str(value),
                    }

                normalized[field] = value
                continue

            if value is None:
                value = ""

            normalized[field] = str(value)

        if data.get("created_at"):
            normalized["created_at"] = str(data["created_at"])

        return normalized

    def _row_to_entry(self, row: sqlite3.Row) -> Entry:
        package = self.encryption_service.decrypt_entry(row["encrypted_data"])

        return {
            "id": row["id"],
            "version": package.get("version", 1),
            "title": package.get("title", ""),
            "username": package.get("username", ""),
            "password": package.get("password", ""),
            "url": package.get("url", ""),
            "notes": package.get("notes", ""),
            "category": package.get("category", ""),
            "tags": package.get("tags", row["tags"]),
            "totp_secret": package.get("totp_secret", ""),
            "shared_metadata": package.get("shared_metadata", {}),
            "created_at": package.get("created_at", row["created_at"]),
            "updated_at": row["updated_at"],
            "deleted_at": row["deleted_at"],
        }

    def _entry_to_search_text(self, entry: Entry) -> str:
        return " ".join(
            str(entry.get(field, ""))
            for field in self.SEARCHABLE_FIELDS
        ).lower()

    def rebuild_search_index(self) -> None:
        self._search_index.clear()

        try:
            entries = self.get_all_entries()
        except Exception:
            entries = []

        for entry in entries:
            entry_id = int(entry["id"])
            self._search_index[entry_id] = self._entry_to_search_text(entry)

        self._write_audit_log(
            action="search_index_rebuilt",
            details=f"Перестроен поисковый индекс, записей: {len(self._search_index)}",
        )

    def get_search_index_snapshot(self) -> dict[int, str]:
        return dict(self._search_index)

    def _update_search_index_for_entry(self, entry: Entry) -> None:
        entry_id = int(entry["id"])
        self._search_index[entry_id] = self._entry_to_search_text(entry)

        self._write_audit_log(
            action="search_index_updated",
            details="Обновлена запись поискового индекса",
        )

    def _remove_from_search_index(self, entry_id: int) -> None:
        self._search_index.pop(int(entry_id), None)

        self._write_audit_log(
            action="search_index_removed",
            details="Запись удалена из поискового индекса",
        )

    def search_in_index(self, query: str) -> list[int]:
        query = str(query or "").lower().strip()

        if not query:
            return list(self._search_index.keys())

        result = []

        for entry_id, text in self._search_index.items():
            if query in text:
                result.append(entry_id)

        return result

    def _publish_event(self, event: Event) -> None:
        try:
            self.event_publisher.publish(event)
        except Exception as exc:
            raise EventPublisherError(f"Не удалось опубликовать событие: {exc}") from exc

    def _write_audit_log(self, action: str, details: str = "") -> None:
        try:
            with self._connection() as conn:
                with conn:
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
        except Exception:
            pass

    def create_entry(self, data_dict: dict[str, Any]) -> Entry:
        self._validate_entry_data(data_dict)

        now = self._now()

        normalized = self._normalize_entry_data(data_dict)
        normalized["created_at"] = now

        tags = normalized.get("tags", "")
        encrypted_data = self.encryption_service.encrypt_entry(normalized)

        with self._connection() as conn:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO vault_entries (
                        encrypted_data,
                        created_at,
                        updated_at,
                        tags,
                        deleted_at
                    )
                    VALUES (?, ?, ?, ?, NULL)
                    """,
                    (
                        encrypted_data,
                        now,
                        now,
                        tags,
                    ),
                )

                entry_id = int(cursor.lastrowid)

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
                        "create_entry",
                        "Создана запись",
                        now,
                    ),
                )

        entry = self.get_entry(entry_id)

        self._update_search_index_for_entry(entry)

        self._publish_event(
            EntryCreated(
                entry=entry,
                created_at=now,
            )
        )

        return entry

    def get_entry(self, entry_id: int) -> Entry:
        with self._connection() as conn:
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
            raise EntryNotFoundError("Запись не найдена или уже была удалена.")

        return self._row_to_entry(row)

    def get_all_entries(self) -> list[Entry]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM vault_entries
                WHERE deleted_at IS NULL
                ORDER BY updated_at DESC, id DESC
                """
            ).fetchall()

        return [self._row_to_entry(row) for row in rows]

    def update_entry(self, entry_id: int, data_dict: dict[str, Any]) -> Entry:
        self._validate_entry_data(data_dict)

        current = self.get_entry(entry_id)

        normalized = self._normalize_entry_data(data_dict)
        normalized["created_at"] = current.get("created_at") or self._now()

        tags = normalized.get("tags", "")
        encrypted_data = self.encryption_service.encrypt_entry(normalized)

        now = self._now()

        with self._connection() as conn:
            with conn:
                cursor = conn.execute(
                    """
                    UPDATE vault_entries
                    SET
                        encrypted_data = ?,
                        updated_at = ?,
                        tags = ?
                    WHERE id = ?
                      AND deleted_at IS NULL
                    """,
                    (
                        encrypted_data,
                        now,
                        tags,
                        entry_id,
                    ),
                )

                if cursor.rowcount == 0:
                    raise EntryNotFoundError("Запись не найдена или уже была удалена.")

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
                        "update_entry",
                        "Обновлена запись",
                        now,
                    ),
                )

        entry = self.get_entry(entry_id)

        self._update_search_index_for_entry(entry)

        self._publish_event(
            EntryUpdated(
                entry=entry,
                updated_at=now,
            )
        )

        return entry

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        now = self._now()
        expires_at = self._expires_at() if soft_delete else None

        with self._connection() as conn:
            with conn:
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
                    raise EntryNotFoundError("Запись не найдена или уже была удалена.")

                if soft_delete:
                    conn.execute(
                        """
                        INSERT INTO deleted_entries (
                            original_entry_id,
                            encrypted_data,
                            created_at,
                            updated_at,
                            deleted_at,
                            expires_at,
                            tags
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            row["id"],
                            row["encrypted_data"],
                            row["created_at"],
                            row["updated_at"],
                            now,
                            expires_at,
                            row["tags"],
                        ),
                    )

                conn.execute(
                    """
                    DELETE FROM vault_entries
                    WHERE id = ?
                    """,
                    (entry_id,),
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
                        "delete_entry",
                        (
                            f"Мягко удалена запись; expires_at={expires_at}"
                            if soft_delete
                            else "Физически удалена запись"
                        ),
                        now,
                    ),
                )

        self._remove_from_search_index(entry_id)

        self._publish_event(
            EntryDeleted(
                entry_id=entry_id,
                deleted_at=now,
                expires_at=expires_at,
                soft_delete=soft_delete,
            )
        )

    def request_clipboard_copy(self, entry_id: int, field_name: str = "password") -> None:
        allowed_fields = {"password", "username", "totp_secret"}

        if field_name not in allowed_fields:
            raise EntryValidationError("Недопустимое поле для копирования.")

        self.get_entry(entry_id)

        event_time = self._now()

        self._publish_event(
            ClipboardCopyRequested(
                entry_id=entry_id,
                field_name=field_name,
                requested_at=event_time,
            )
        )

        self._write_audit_log(
            action="clipboard_copy_requested",
            details=f"Запрошено копирование поля {field_name}",
        )

    def search_entries(self, query: str) -> list[Entry]:
        entry_ids = self.search_in_index(query)

        result = []

        for entry_id in entry_ids:
            try:
                result.append(self.get_entry(entry_id))
            except EntryNotFoundError:
                continue

        return result

    def count_entries(self) -> int:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM vault_entries
                """
            ).fetchone()

        return int(row["count"])

    def count_deleted_entries(self) -> int:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM deleted_entries
                """
            ).fetchone()

        return int(row["count"])