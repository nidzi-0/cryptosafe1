from __future__ import annotations

from datetime import datetime, timezone, timedelta


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EntryManager:
    def __init__(self, db, encryption_service, event_bus=None) -> None:
        self.db = db
        self.encryption_service = encryption_service
        self.event_bus = event_bus
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self.db.connect()

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deleted_entries (
                id INTEGER PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                deleted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                tags TEXT
            )
            """
        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault_entries(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags)")

        conn.commit()

    def create_entry(self, data_dict: dict) -> dict:
        self._validate(data_dict)

        conn = self.db.connect()
        now = utc_now()

        payload = dict(data_dict)
        payload["created_at"] = now
        payload["version"] = 1

        encrypted = self.encryption_service.encrypt_entry(payload)
        tags = data_dict.get("tags", "")

        try:
            conn.execute("BEGIN")

            cur = conn.execute(
                """
                INSERT INTO vault_entries(encrypted_data, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?)
                """,
                (encrypted, now, now, tags),
            )

            entry_id = int(cur.lastrowid)

            conn.commit()

        except Exception:
            conn.rollback()
            raise ValueError("Не удалось создать запись")

        self._publish("EntryCreated", entry_id)

        return self.get_entry(entry_id)

    def get_entry(self, entry_id: int) -> dict:
        conn = self.db.connect()

        row = conn.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            WHERE id = ?
            """,
            (entry_id,),
        ).fetchone()

        if row is None:
            raise ValueError("Запись недоступна")

        data = self.encryption_service.decrypt_entry(row["encrypted_data"])
        data["id"] = row["id"]
        data["created_at"] = row["created_at"]
        data["updated_at"] = row["updated_at"]
        data["tags"] = row["tags"]

        return data

    def get_all_entries(self) -> list[dict]:
        conn = self.db.connect()

        rows = conn.execute(
            """
            SELECT id
            FROM vault_entries
            ORDER BY updated_at DESC
            """
        ).fetchall()

        return [self.get_entry(row["id"]) for row in rows]

    def update_entry(self, entry_id: int, data_dict: dict) -> dict:
        self._validate(data_dict)

        conn = self.db.connect()
        now = utc_now()

        current = self.get_entry(entry_id)

        payload = dict(data_dict)
        payload["created_at"] = current.get("created_at")
        payload["version"] = 1

        encrypted = self.encryption_service.encrypt_entry(payload)
        tags = data_dict.get("tags", "")

        try:
            conn.execute("BEGIN")

            cur = conn.execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?, updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (encrypted, now, tags, entry_id),
            )

            if cur.rowcount == 0:
                raise ValueError("Запись недоступна")

            conn.commit()

        except Exception:
            conn.rollback()
            raise ValueError("Не удалось обновить запись")

        self._publish("EntryUpdated", entry_id)

        return self.get_entry(entry_id)

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        conn = self.db.connect()

        row = conn.execute(
            """
            SELECT id, encrypted_data, tags
            FROM vault_entries
            WHERE id = ?
            """,
            (entry_id,),
        ).fetchone()

        if row is None:
            raise ValueError("Запись недоступна")

        try:
            conn.execute("BEGIN")

            if soft_delete:
                deleted_at = utc_now()
                expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

                conn.execute(
                    """
                    INSERT INTO deleted_entries(id, encrypted_data, deleted_at, expires_at, tags)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (row["id"], row["encrypted_data"], deleted_at, expires_at, row["tags"]),
                )

            conn.execute(
                """
                DELETE FROM vault_entries
                WHERE id = ?
                """,
                (entry_id,),
            )

            conn.commit()

        except Exception:
            conn.rollback()
            raise ValueError("Не удалось удалить запись")

        self._publish("EntryDeleted", entry_id)

    def _validate(self, data: dict) -> None:
        if not data.get("title"):
            raise ValueError("Заголовок обязателен")

        if not data.get("password"):
            raise ValueError("Пароль обязателен")

    def _publish(self, event_name: str, entry_id: int) -> None:
        if self.event_bus is None:
            return

        try:
            self.event_bus.publish(event_name, {"entry_id": entry_id})
        except TypeError:
            pass