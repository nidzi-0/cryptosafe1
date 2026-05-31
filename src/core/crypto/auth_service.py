from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw


class AuthServiceError(Exception):
    """Базовая ошибка сервиса аутентификации."""


class MasterPasswordAlreadyExistsError(AuthServiceError):
    """Ошибка, если мастер-пароль уже создан."""


class MasterPasswordNotFoundError(AuthServiceError):
    """Ошибка, если мастер-пароль ещё не создан."""


class InvalidMasterPasswordError(AuthServiceError):
    """Ошибка неверного мастер-пароля."""


class AuthService:
    """
    Сервис мастер-пароля.

    Отвечает за:
    - первичную регистрацию мастер-пароля;
    - проверку существования мастер-пароля;
    - вход по мастер-паролю;
    - смену мастер-пароля;
    - получение ключа шифрования для AES-GCM.
    """

    SALT_SIZE = 16
    KEY_SIZE = 32

    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536
    ARGON2_PARALLELISM = 2

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _ensure_tables(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS key_store (
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

    def has_master_password(self) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM key_store
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

    def create_master_password(self, password: str) -> bytes:
        if self.has_master_password():
            raise MasterPasswordAlreadyExistsError("Мастер-пароль уже создан.")

        salt = os.urandom(self.SALT_SIZE)
        master_key = self._derive_key(password, salt)
        password_hash = self._password_hash(master_key)

        now = self._now()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO key_store (
                    id,
                    salt,
                    password_hash,
                    kdf_name,
                    time_cost,
                    memory_cost,
                    parallelism,
                    key_size,
                    created_at,
                    updated_at
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

        self.write_audit_log("create_master_password", "Создан мастер-пароль")

        return master_key

    def unlock_with_password(self, password: str) -> bytes:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM key_store
                WHERE id = 1
                """
            ).fetchone()

        if row is None:
            raise MasterPasswordNotFoundError("Мастер-пароль ещё не создан.")

        salt = row["salt"]
        expected_hash = row["password_hash"]

        master_key = self._derive_key(
            password=password,
            salt=salt,
            time_cost=int(row["time_cost"]),
            memory_cost=int(row["memory_cost"]),
            parallelism=int(row["parallelism"]),
            key_size=int(row["key_size"]),
        )

        actual_hash = self._password_hash(master_key)

        if not self._constant_time_compare(actual_hash, expected_hash):
            self.write_audit_log("failed_login", "Неверный мастер-пароль")
            raise InvalidMasterPasswordError("Неверный мастер-пароль.")

        self.write_audit_log("successful_login", "Успешный вход")

        return master_key

    def change_master_password(self, old_password: str, new_password: str) -> bytes:
        self.unlock_with_password(old_password)

        if not new_password:
            raise AuthServiceError("Новый мастер-пароль не может быть пустым.")

        salt = os.urandom(self.SALT_SIZE)
        new_master_key = self._derive_key(new_password, salt)
        new_hash = self._password_hash(new_master_key)

        now = self._now()

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE key_store
                SET
                    salt = ?,
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

        self.write_audit_log("change_master_password", "Мастер-пароль изменён")

        return new_master_key

    def write_audit_log(self, action: str, details: str = "") -> None:
        try:
            with self._connect() as conn:
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

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        if isinstance(a, memoryview):
            a = a.tobytes()

        if isinstance(b, memoryview):
            b = b.tobytes()

        return hashlib.sha256(a).digest() == hashlib.sha256(b).digest()