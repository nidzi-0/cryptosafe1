import sqlite3
from pathlib import Path
from typing import Union


class ImportExportSchemaError(Exception):
    pass


class ImportExportSchema:
    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            with sqlite3.connect(self.db_path) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                self._create_shared_entries(connection)
                self._create_import_export_history(connection)
                self._create_contacts(connection)
                connection.commit()

        except Exception as exc:
            raise ImportExportSchemaError(f"Failed to initialize import/export schema: {exc}") from exc

    def _create_shared_entries(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS shared_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shared_id TEXT NOT NULL UNIQUE,
                original_entry_id TEXT NOT NULL,
                encryption_method TEXT NOT NULL,
                recipient_info TEXT NOT NULL,
                permissions TEXT NOT NULL,
                shared_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                package_checksum TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_shared_entries_shared_id
            ON shared_entries(shared_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_shared_entries_original_entry_id
            ON shared_entries(original_entry_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_shared_entries_expires_at
            ON shared_entries(expires_at)
            """
        )

    def _create_import_export_history(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS import_export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                file_format TEXT NOT NULL,
                encryption_used TEXT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                file_size INTEGER NOT NULL DEFAULT 0,
                checksum TEXT,
                verification_status TEXT NOT NULL DEFAULT 'unknown',
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_import_export_history_operation_type
            ON import_export_history(operation_type)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_import_export_history_created_at
            ON import_export_history(created_at)
            """
        )

    def _create_contacts(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_name TEXT NOT NULL,
                identifier TEXT NOT NULL UNIQUE,
                public_key TEXT,
                key_type TEXT,
                key_fingerprint TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                last_used_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_contacts_identifier
            ON contacts(identifier)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_contacts_key_fingerprint
            ON contacts(key_fingerprint)
            """
        )