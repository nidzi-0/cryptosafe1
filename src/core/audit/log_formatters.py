from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path


class AuditExportError(Exception):
    """Ошибка экспорта audit log."""


class AuditLogExporter:


    def __init__(
        self,
        audit_logger,
        signer,
        export_policy=None,
    ):
        self.audit_logger = audit_logger
        self.signer = signer
        self.export_policy = export_policy

    def _validate_export_policy(self, password: str | None = None) -> None:
        if self.export_policy is None:
            return

        self.export_policy.validate_export_allowed(password)

    def _log_export_operation(
        self,
        export_type: str,
        limit: int,
    ) -> None:
        try:
            self.audit_logger.log_event(
                event_type="AUDIT_LOG_EXPORTED",
                severity="INFO",
                source="audit_exporter",
                details={
                    "export_type": export_type,
                    "limit": limit,
                    "path": "[REDACTED]",
                },
            )
        except Exception:
            pass

    def export_signed_json(
        self,
        output_path: str | Path,
        limit: int = 10_000,
        password: str | None = None,
    ) -> Path:
        self._validate_export_policy(password)

        output_path = Path(output_path)
        logs = self.audit_logger.query_logs(limit=limit)

        payload = {
            "metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "exporter": "CryptoSafe Manager",
                "format": "signed_json",
                "total_entries": len(logs),
                "public_key": self.signer.get_public_key_hex(),
                "algorithm": self.signer.algorithm,
            },
            "entries": logs,
        }

        output_path.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        self._log_export_operation("signed_json", limit)

        return output_path

    def export_csv(
        self,
        output_path: str | Path,
        limit: int = 10_000,
        password: str | None = None,
    ) -> Path:
        self._validate_export_policy(password)

        output_path = Path(output_path)
        logs = self.audit_logger.query_logs(limit=limit)

        with output_path.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "sequence_number",
                    "timestamp",
                    "event_type",
                    "severity",
                    "user_id",
                    "source",
                    "entry_id",
                    "entry_hash",
                    "previous_hash",
                    "signature",
                    "signing_algorithm",
                ],
            )

            writer.writeheader()

            for row in logs:
                writer.writerow(
                    {
                        "sequence_number": row["sequence_number"],
                        "timestamp": row["timestamp"],
                        "event_type": row["event_type"],
                        "severity": row["severity"],
                        "user_id": row["user_id"],
                        "source": row["source"],
                        "entry_id": row["entry_id"],
                        "entry_hash": row["entry_hash"],
                        "previous_hash": row["previous_hash"],
                        "signature": row["signature"],
                        "signing_algorithm": row["signing_algorithm"],
                    }
                )

        self._log_export_operation("csv", limit)

        return output_path

    def export_pdf(
        self,
        output_path: str | Path,
        limit: int = 500,
        password: str | None = None,
    ) -> Path:
        self._validate_export_policy(password)

        output_path = Path(output_path)
        logs = self.audit_logger.query_logs(limit=limit)

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas

            c = canvas.Canvas(str(output_path), pagesize=A4)
            width, height = A4

            y = height - 50
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "CryptoSafe Manager Audit Log Report")
            y -= 30

            c.setFont("Helvetica", 9)
            c.drawString(
                50,
                y,
                f"Generated at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
            )
            y -= 25

            for row in logs:
                if y < 80:
                    c.showPage()
                    c.setFont("Helvetica", 9)
                    y = height - 50

                line = (
                    f"#{row['sequence_number']} | "
                    f"{row['timestamp']} | "
                    f"{row['severity']} | "
                    f"{row['event_type']} | "
                    f"{row['source']}"
                )

                c.drawString(50, y, line[:120])
                y -= 14

            c.save()

            self._log_export_operation("pdf", limit)

            return output_path

        except Exception:
            lines = [
                "CryptoSafe Manager Audit Log Report",
                f"Generated at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
                "",
            ]

            for row in logs:
                lines.append(
                    f"#{row['sequence_number']} | "
                    f"{row['timestamp']} | "
                    f"{row['severity']} | "
                    f"{row['event_type']} | "
                    f"{row['source']}"
                )

            output_path.write_text("\n".join(lines), encoding="utf-8")

            self._log_export_operation("pdf_fallback", limit)

            return output_path