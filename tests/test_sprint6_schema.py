import sqlite3

from src.core.import_export.import_export_schema import ImportExportSchema


def table_exists(db_path, table_name):
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = ?
            """,
            (table_name,),
        )
        return cursor.fetchone() is not None


def column_names(db_path, table_name):
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(f"PRAGMA table_info({table_name})")
        return [row[1] for row in cursor.fetchall()]


def test_import_export_schema_creates_required_tables(tmp_path):
    db_path = tmp_path / "cryptosafe_test.db"

    schema = ImportExportSchema(db_path)
    schema.initialize()

    assert table_exists(db_path, "shared_entries")
    assert table_exists(db_path, "import_export_history")
    assert table_exists(db_path, "contacts")


def test_shared_entries_columns_exist(tmp_path):
    db_path = tmp_path / "cryptosafe_test.db"

    schema = ImportExportSchema(db_path)
    schema.initialize()

    columns = column_names(db_path, "shared_entries")

    assert "shared_id" in columns
    assert "original_entry_id" in columns
    assert "encryption_method" in columns
    assert "recipient_info" in columns
    assert "permissions" in columns
    assert "shared_at" in columns
    assert "expires_at" in columns


def test_import_export_history_columns_exist(tmp_path):
    db_path = tmp_path / "cryptosafe_test.db"

    schema = ImportExportSchema(db_path)
    schema.initialize()

    columns = column_names(db_path, "import_export_history")

    assert "operation_type" in columns
    assert "file_format" in columns
    assert "encryption_used" in columns
    assert "entry_count" in columns
    assert "file_size" in columns
    assert "checksum" in columns
    assert "verification_status" in columns


def test_contacts_columns_exist(tmp_path):
    db_path = tmp_path / "cryptosafe_test.db"

    schema = ImportExportSchema(db_path)
    schema.initialize()

    columns = column_names(db_path, "contacts")

    assert "contact_name" in columns
    assert "identifier" in columns
    assert "public_key" in columns
    assert "key_type" in columns
    assert "key_fingerprint" in columns
    assert "last_used_at" in columns


def test_schema_initialize_is_idempotent(tmp_path):
    db_path = tmp_path / "cryptosafe_test.db"

    schema = ImportExportSchema(db_path)
    schema.initialize()
    schema.initialize()

    assert table_exists(db_path, "shared_entries")
    assert table_exists(db_path, "import_export_history")
    assert table_exists(db_path, "contacts")