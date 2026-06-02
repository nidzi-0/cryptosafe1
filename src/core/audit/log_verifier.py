from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.audit.log_signer import AuditLogSigner


@dataclass
class VerificationResult:
    total_entries: int
    valid_entries: int
    invalid_entries: list[dict[str, Any]]
    chain_breaks: list[dict[str, Any]]
    verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": self.total_entries,
            "valid_entries": self.valid_entries,
            "invalid_entries": self.invalid_entries,
            "chain_breaks": self.chain_breaks,
            "verified": self.verified,
        }


class AuditLogVerifier:

    ZERO_HASH = "0" * 64

    def __init__(
        self,
        db_path: str | Path,
        signer: AuditLogSigner,
    ):
        self.db_path = Path(db_path)
        self.signer = signer

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def verify_integrity(
        self,
        start_sequence: int | None = None,
        end_sequence: int | None = None,
        limit_recent: int | None = None,
    ) -> VerificationResult:
        query = """
            SELECT *
            FROM audit_log
            WHERE 1 = 1
        """
        params: list[Any] = []

        if start_sequence is not None:
            query += " AND sequence_number >= ?"
            params.append(start_sequence)

        if end_sequence is not None:
            query += " AND sequence_number <= ?"
            params.append(end_sequence)

        query += " ORDER BY sequence_number ASC"

        if limit_recent is not None:
            query = f"""
                SELECT *
                FROM (
                    {query}
                )
                ORDER BY sequence_number DESC
                LIMIT ?
            """
            params.append(limit_recent)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        if limit_recent is not None:
            rows = list(reversed(rows))

        invalid_entries = []
        chain_breaks = []
        valid_entries = 0
        previous_hash = None

        for row in rows:
            sequence_number = int(row["sequence_number"])
            entry_data = row["entry_data"]
            signature_hex = row["signature"]
            stored_hash = row["entry_hash"]
            stored_previous_hash = row["previous_hash"]

            if isinstance(entry_data, str):
                entry_bytes = entry_data.encode("utf-8")
            else:
                entry_bytes = bytes(entry_data)

            computed_hash = hashlib.sha256(entry_bytes).hexdigest()

            if computed_hash != stored_hash:
                invalid_entries.append(
                    {
                        "sequence_number": sequence_number,
                        "reason": "Hash mismatch",
                        "expected": stored_hash,
                        "actual": computed_hash,
                    }
                )
                continue

            try:
                signature = bytes.fromhex(signature_hex)
            except ValueError:
                invalid_entries.append(
                    {
                        "sequence_number": sequence_number,
                        "reason": "Invalid signature encoding",
                    }
                )
                continue

            if not self.signer.verify(entry_bytes, signature):
                invalid_entries.append(
                    {
                        "sequence_number": sequence_number,
                        "reason": "Invalid signature",
                    }
                )
                continue

            if previous_hash is not None and stored_previous_hash != previous_hash:
                chain_breaks.append(
                    {
                        "sequence_number": sequence_number,
                        "expected_previous_hash": previous_hash,
                        "actual_previous_hash": stored_previous_hash,
                    }
                )
                continue

            previous_hash = stored_hash
            valid_entries += 1

        verified = not invalid_entries and not chain_breaks

        return VerificationResult(
            total_entries=len(rows),
            valid_entries=valid_entries,
            invalid_entries=invalid_entries,
            chain_breaks=chain_breaks,
            verified=verified,
        )

    def verify_startup(self) -> VerificationResult:
        return self.verify_integrity()

    def verify_recent(self, limit: int = 1000) -> VerificationResult:
        return self.verify_integrity(limit_recent=limit)

    def export_report(self, output_path: str | Path) -> Path:
        result = self.verify_integrity()
        output_path = Path(output_path)

        output_path.write_text(
            json.dumps(
                result.to_dict(),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return output_path