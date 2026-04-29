from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .db import Database


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class KeyStoreRecord:
    key_type: str
    key_data: bytes
    version: int


class KeyStoreRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def set_key_data(self, key_type: str, key_data: bytes, version: int = 1) -> None:
        if not key_type:
            raise ValueError("Тип ключа не может быть пустым")

        if not isinstance(key_data, (bytes, bytearray)):
            raise ValueError("Данные ключа должны быть байтами")

        conn = self.db.connect()
        conn.execute(
            """
            INSERT INTO key_store(key_type, key_data, version, created_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(key_type) DO UPDATE SET
                key_data = excluded.key_data,
                version = excluded.version,
                created_at = excluded.created_at
            """,
            (key_type, bytes(key_data), version, utc_now_iso()),
        )
        conn.commit()

    def get_key_data(self, key_type: str) -> bytes | None:
        conn = self.db.connect()
        row = conn.execute(
            "SELECT key_data FROM key_store WHERE key_type = ?",
            (key_type,),
        ).fetchone()

        if row is None:
            return None

        return bytes(row["key_data"])

    def get_record(self, key_type: str) -> KeyStoreRecord | None:
        conn = self.db.connect()
        row = conn.execute(
            "SELECT key_type, key_data, version FROM key_store WHERE key_type = ?",
            (key_type,),
        ).fetchone()

        if row is None:
            return None

        return KeyStoreRecord(
            key_type=row["key_type"],
            key_data=bytes(row["key_data"]),
            version=int(row["version"]),
        )

    def set_json_params(self, key_type: str, params: dict, version: int = 1) -> None:
        raw = json.dumps(params, ensure_ascii=False).encode("utf-8")
        self.set_key_data(key_type, raw, version)

    def get_json_params(self, key_type: str) -> dict | None:
        raw = self.get_key_data(key_type)

        if raw is None:
            return None

        return json.loads(raw.decode("utf-8"))

    def exists(self, key_type: str) -> bool:
        return self.get_key_data(key_type) is not None