from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw


class AuthServiceError(Exception):
    """Базовая ошибка сервиса аутентификации."""


class MasterPasswordAlreadyExistsError(AuthServiceError):
    """Ошибка, если мастер-пароль уже создан."""


class MasterPasswordNotFoundError(AuthServiceError):
    """Ошибка, если мастер-пароль ещё не создан."""


class InvalidMasterPasswordError(AuthServiceError):
    """Ошибка неверного мастер-пароля."""


@dataclass
class AuthResult:
    success: bool
    message: str = ""
    master_key: bytes | None = None


class AuthService:
    SALT_SIZE = 16
    KEY_SIZE = 32
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536
    ARGON2_PARALLELISM = 2

    def __init__(self, db_path_or_key_store: str | Path | Any):
        self._cached_key: bytes | None = None
        self.key_store = None
        self.db_path: Path | None = None

        if hasattr(db_path_or_key_store, "set_key_data") and hasattr(
            db_path_or_key_store, "get_key_data"
        ):
            self.key_store = db_path_or_key_store
            self.db = db_path_or_key_store.db
        else:
            self.db_path = Path(db_path_or_key_store)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._ensure_tables()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _connect(self) -> sqlite3.Connection:
        if self.key_store is not None:
            return self.db.connect()

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_store (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    kdf_name TEXT NOT NULL,
                    time_cost INTEGER NOT NULL,
                    memory_cost INTEGER NOT NULL,
                    parallelism INTEGER NOT NULL,
                    key_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
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

            conn.commit()

    def _derive_key(
        self,
        password: str,
        salt: bytes,
        time_cost: int | None = None,
        memory_cost: int | None = None,
        parallelism: int | None = None,
        key_size: int | None = None,
    ) -> bytes:
        if not isinstance(password, str):
            raise AuthServiceError("Мастер-пароль должен быть строкой.")

        if not password:
            raise AuthServiceError("Мастер-пароль не может быть пустым.")

        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost or self.ARGON2_TIME_COST,
            memory_cost=memory_cost or self.ARGON2_MEMORY_COST,
            parallelism=parallelism or self.ARGON2_PARALLELISM,
            hash_len=key_size or self.KEY_SIZE,
            type=Type.ID,
        )

    def _password_hash(self, key: bytes) -> bytes:
        return hashlib.sha256(key).digest()

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        if isinstance(a, memoryview):
            a = a.tobytes()
        if isinstance(b, memoryview):
            b = b.tobytes()
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            return False
        return hmac.compare_digest(a, b)

    def has_master_password(self) -> bool:
        if self.key_store is not None:
            return self.key_store.exists("auth_hash")

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM auth_store
                WHERE id = 1
                """
            ).fetchone()
            return int(row["count"]) > 0

    def master_password_exists(self) -> bool:
        return self.has_master_password()

    def is_master_password_set(self) -> bool:
        return self.has_master_password()

    def has_master_key(self) -> bool:
        return self.has_master_password()

    def create_master_password(self, password: str) -> bytes:
        if self.has_master_password():
            raise MasterPasswordAlreadyExistsError("Мастер-пароль уже создан.")

        salt = os.urandom(self.SALT_SIZE)
        master_key = self._derive_key(password, salt)
        password_hash = self._password_hash(master_key)
        now = self._now()

        if self.key_store is not None:
            params = {
                "salt": salt.hex(),
                "kdf_name": "argon2id",
                "time_cost": self.ARGON2_TIME_COST,
                "memory_cost": self.ARGON2_MEMORY_COST,
                "parallelism": self.ARGON2_PARALLELISM,
                "key_size": self.KEY_SIZE,
                "created_at": now,
                "updated_at": now,
            }
            self.key_store.set_key_data("auth_hash", password_hash)
            self.key_store.set_json_params("auth_params", params)
            self.key_store.set_key_data("encryption_key", master_key)
            self._cached_key = master_key
            self.write_audit_log("create_master_password", "Создан мастер-пароль")
            return master_key

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_store (
                    id, salt, password_hash, kdf_name,
                    time_cost, memory_cost, parallelism,
                    key_size, created_at, updated_at
                )
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    salt,
                    password_hash,
                    "argon2id",
                    self.ARGON2_TIME_COST,
                    self.ARGON2_MEMORY_COST,
                    self.ARGON2_PARALLELISM,
                    self.KEY_SIZE,
                    now,
                    now,
                ),
            )
            conn.commit()

        self._cached_key = master_key
        self.write_audit_log("create_master_password", "Создан мастер-пароль")
        return master_key

    def setup_master_password(self, password: str) -> AuthResult:
        try:
            key = self.create_master_password(password)
            return AuthResult(True, "Мастер-пароль создан", key)
        except Exception as exc:
            return AuthResult(False, str(exc), None)

    def unlock_with_password(self, password: str) -> bytes:
        if self.key_store is not None:
            expected_hash = self.key_store.get_key_data("auth_hash")
            params = self.key_store.get_json_params("auth_params")

            if expected_hash is None or params is None:
                raise MasterPasswordNotFoundError("Мастер-пароль ещё не создан.")

            salt = bytes.fromhex(params["salt"])
            master_key = self._derive_key(
                password=password,
                salt=salt,
                time_cost=int(params.get("time_cost", self.ARGON2_TIME_COST)),
                memory_cost=int(params.get("memory_cost", self.ARGON2_MEMORY_COST)),
                parallelism=int(params.get("parallelism", self.ARGON2_PARALLELISM)),
                key_size=int(params.get("key_size", self.KEY_SIZE)),
            )

            actual_hash = self._password_hash(master_key)

            if not self._constant_time_compare(actual_hash, expected_hash):
                self.write_audit_log("failed_login", "Неверный мастер-пароль")
                raise InvalidMasterPasswordError("Неверный мастер-пароль.")

            self._cached_key = master_key
            self.write_audit_log("successful_login", "Успешный вход")
            return master_key

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM auth_store
                WHERE id = 1
                """
            ).fetchone()

        if row is None:
            raise MasterPasswordNotFoundError("Мастер-пароль ещё не создан.")

        master_key = self._derive_key(
            password=password,
            salt=row["salt"],
            time_cost=int(row["time_cost"]),
            memory_cost=int(row["memory_cost"]),
            parallelism=int(row["parallelism"]),
            key_size=int(row["key_size"]),
        )

        actual_hash = self._password_hash(master_key)

        if not self._constant_time_compare(actual_hash, row["password_hash"]):
            self.write_audit_log("failed_login", "Неверный мастер-пароль")
            raise InvalidMasterPasswordError("Неверный мастер-пароль.")

        self._cached_key = master_key
        self.write_audit_log("successful_login", "Успешный вход")
        return master_key

    def login(self, password: str) -> AuthResult:
        try:
            key = self.unlock_with_password(password)
            return AuthResult(True, "Успешный вход", key)
        except Exception as exc:
            return AuthResult(False, str(exc), None)

    def logout(self) -> None:
        if self._cached_key is not None:
            self._cached_key = b"\x00" * len(self._cached_key)
        self._cached_key = None
        self.write_audit_log("logout", "Выход из хранилища")

    def get_encryption_key(self) -> bytes:
        if self._cached_key is not None:
            return self._cached_key

        if self.key_store is not None:
            key = self.key_store.get_key_data("encryption_key")
            if key is not None:
                return key

        raise MasterPasswordNotFoundError("Ключ шифрования не загружен.")

    def get_key(self) -> bytes:
        return self.get_encryption_key()

    def change_master_password(self, old_password: str, new_password: str):
        old_key = self.unlock_with_password(old_password)

        if not new_password:
            raise AuthServiceError("Новый мастер-пароль не может быть пустым.")

        salt = os.urandom(self.SALT_SIZE)
        new_master_key = self._derive_key(new_password, salt)
        new_hash = self._password_hash(new_master_key)
        now = self._now()
        self._reencrypt_legacy_vault_entries(old_key, new_master_key)

        if self.key_store is not None:
            params = {
                "salt": salt.hex(),
                "kdf_name": "argon2id",
                "time_cost": self.ARGON2_TIME_COST,
                "memory_cost": self.ARGON2_MEMORY_COST,
                "parallelism": self.ARGON2_PARALLELISM,
                "key_size": self.KEY_SIZE,
                "updated_at": now,
            }

            self.key_store.set_key_data("auth_hash", new_hash)
            self.key_store.set_json_params("auth_params", params)
            self.key_store.set_key_data("encryption_key", new_master_key)
            self._cached_key = new_master_key
            self.write_audit_log("change_master_password", "Мастер-пароль изменён")
            return AuthResult(True, "Мастер-пароль изменён", new_master_key)

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE auth_store
                SET salt = ?,
                    password_hash = ?,
                    kdf_name = ?,
                    time_cost = ?,
                    memory_cost = ?,
                    parallelism = ?,
                    key_size = ?,
                    updated_at = ?
                WHERE id = 1
                """,
                (
                    salt,
                    new_hash,
                    "argon2id",
                    self.ARGON2_TIME_COST,
                    self.ARGON2_MEMORY_COST,
                    self.ARGON2_PARALLELISM,
                    self.KEY_SIZE,
                    now,
                ),
            )
            conn.commit()

        self._cached_key = new_master_key
        self.write_audit_log("change_master_password", "Мастер-пароль изменён")
        return new_master_key

    def _xor_with_key(self, data: bytes | None, key: bytes) -> bytes | None:
        if data is None:
            return None

        return bytes(
            byte ^ key[index % len(key)]
            for index, byte in enumerate(data)
        )

    def _reencrypt_legacy_vault_entries(self, old_key: bytes, new_key: bytes) -> None:
        try:
            conn = self._connect()

            rows = conn.execute(
            ).fetchall()

            for row in rows:
                username_plain = self._xor_with_key(row["username"], old_key)
                password_plain = self._xor_with_key(row["encrypted_password"], old_key)
                notes_plain = self._xor_with_key(row["notes"], old_key)

                username_new = self._xor_with_key(username_plain, new_key)
                password_new = self._xor_with_key(password_plain, new_key)
                notes_new = self._xor_with_key(notes_plain, new_key)

                conn.execute(
                    """
                    UPDATE vault_entries
                    SET username = ?,
                        encrypted_password = ?,
                        notes = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        username_new,
                        password_new,
                        notes_new,
                        self._now(),
                        row["id"],
                    ),
                )

            conn.commit()
        except sqlite3.OperationalError:
            return

    def write_audit_log(self, action: str, details: str = "") -> None:
        try:
            conn = self._connect()

            columns = conn.execute("PRAGMA table_info(audit_log)").fetchall()
            column_names = {row["name"] for row in columns}

            if "created_at" in column_names:
                conn.execute(
                    """
                    INSERT INTO audit_log (action, details, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (action, details, self._now()),
                )
            elif "timestamp" in column_names:
                conn.execute(
                    """
                    INSERT INTO audit_log (action, details, timestamp)
                    VALUES (?, ?, ?)
                    """,
                    (action, details, self._now()),
                )

            conn.commit()
        except Exception:
            pass