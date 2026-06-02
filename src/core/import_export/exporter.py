import base64
import csv
import gzip
import hashlib
import io
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class VaultExportError(Exception):
    pass


@dataclass(frozen=True)
class ExportOptions:
    format: str = "encrypted_json"
    include_notes: bool = True
    encryption_bits: int = 256
    compress: bool = False
    plaintext_allowed: bool = False
    require_master_confirmation: bool = False


class VaultExporter:
    EXPORT_VERSION = "1.0"
    SOURCE_APP = "CryptoSafe Manager"
    PBKDF2_ITERATIONS = 100_000
    SALT_SIZE = 16
    NONCE_SIZE = 12

    SUPPORTED_FORMATS = {
        "encrypted_json",
        "csv",
        "bitwarden_json",
    }

    def __init__(
        self,
        entry_manager: Any,
        audit_logger: Optional[Any] = None,
        master_password_verifier: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.master_password_verifier = master_password_verifier

    def export_to_file(
        self,
        output_path: Union[str, Path],
        password: str,
        entry_ids: Optional[Sequence[Union[str, int]]] = None,
        options: Optional[ExportOptions] = None,
        master_password: Optional[str] = None,
    ) -> Path:
        options = options or ExportOptions()
        output_path = Path(output_path)
        temp_name = None

        if options.require_master_confirmation:
            self._verify_master_password(master_password)

        package = self.export_vault(
            password=password,
            entry_ids=entry_ids,
            options=options,
            master_password=master_password,
        )

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                dir=str(output_path.parent),
                suffix=".tmp",
            ) as tmp:
                temp_name = tmp.name
                json.dump(package, tmp, ensure_ascii=False, indent=2)

            os.replace(temp_name, output_path)

            self._audit(
                "export_file_created",
                {
                    "path": str(output_path),
                    "format": options.format,
                    "entry_count": package.get("metadata", {}).get("entry_count"),
                },
            )

            return output_path

        except Exception as exc:
            self._safe_remove_temp(temp_name)
            raise VaultExportError(f"Failed to export vault to file: {exc}") from exc

    def export_vault(
        self,
        password: str,
        entry_ids: Optional[Sequence[Union[str, int]]] = None,
        options: Optional[ExportOptions] = None,
        master_password: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not password or not isinstance(password, str):
            raise VaultExportError("Export password is required.")

        options = options or ExportOptions()
        self._validate_options(options)

        if options.require_master_confirmation:
            self._verify_master_password(master_password)

        entries = self._get_entries_for_export(entry_ids)
        filtered_entries = [self._filter_entry_fields(entry, options) for entry in entries]

        if options.format == "csv":
            payload_text = self._entries_to_csv(filtered_entries)

            if options.plaintext_allowed:
                self._audit(
                    "plaintext_csv_export_created",
                    {
                        "entry_count": len(filtered_entries),
                    },
                )

                return {
                    "version": self.EXPORT_VERSION,
                    "cryptosafe_export": True,
                    "format": "csv",
                    "plaintext": True,
                    "timestamp": self._utc_now(),
                    "data": payload_text,
                    "metadata": self._metadata(len(filtered_entries), options),
                }

            payload = {
                "format": "csv",
                "csv": payload_text,
            }

        elif options.format == "bitwarden_json":
            payload = self._entries_to_bitwarden_json(filtered_entries)

        else:
            payload = {
                "format": "native",
                "entries": filtered_entries,
            }

        package = self._encrypt_payload(
            payload=payload,
            password=password,
            options=options,
            entry_count=len(filtered_entries),
        )

        self._audit(
            "vault_exported",
            {
                "format": options.format,
                "entry_count": len(filtered_entries),
                "encrypted": True,
            },
        )

        return package

    def _verify_master_password(self, master_password: Optional[str]) -> None:
        if not master_password:
            raise VaultExportError("Master password confirmation is required.")

        if self.master_password_verifier is None:
            raise VaultExportError("Master password verifier is not configured.")

        try:
            is_valid = self.master_password_verifier(master_password)
        except Exception as exc:
            raise VaultExportError("Master password verification failed.") from exc

        if not is_valid:
            raise VaultExportError("Master password verification failed.")

    def _get_entries_for_export(
        self,
        entry_ids: Optional[Sequence[Union[str, int]]],
    ) -> List[Dict[str, Any]]:
        try:
            if entry_ids is None:
                raw_entries = self.entry_manager.list_entries()
                return [self._normalize_entry(entry) for entry in raw_entries]

            entries = []

            for entry_id in entry_ids:
                entry = self.entry_manager.get_entry(entry_id)

                if entry is None:
                    raise VaultExportError(f"Entry not found: {entry_id}")

                entries.append(self._normalize_entry(entry))

            return entries

        except VaultExportError:
            raise
        except Exception as exc:
            raise VaultExportError(f"Failed to retrieve entries for export: {exc}") from exc

    def _normalize_entry(self, entry: Any) -> Dict[str, Any]:
        if isinstance(entry, dict):
            data = dict(entry)
        elif hasattr(entry, "__dict__"):
            data = dict(entry.__dict__)
        else:
            raise VaultExportError(f"Unsupported entry type: {type(entry)!r}")

        normalized = {
            "id": data.get("id") or data.get("entry_id"),
            "title": data.get("title") or data.get("name") or "",
            "username": data.get("username") or "",
            "password": data.get("password") or "",
            "url": data.get("url") or data.get("website") or "",
            "notes": data.get("notes") or "",
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
        }

        if not normalized["title"]:
            normalized["title"] = "Untitled"

        return normalized

    def _filter_entry_fields(
        self,
        entry: Dict[str, Any],
        options: ExportOptions,
    ) -> Dict[str, Any]:
        result = dict(entry)

        if not options.include_notes:
            result.pop("notes", None)

        return result

    def _encrypt_payload(
        self,
        payload: Dict[str, Any],
        password: str,
        options: ExportOptions,
        entry_count: int,
    ) -> Dict[str, Any]:
        try:
            salt = os.urandom(self.SALT_SIZE)
            nonce = os.urandom(self.NONCE_SIZE)
            key = self._derive_export_key(
                password=password,
                salt=salt,
                encryption_bits=options.encryption_bits,
            )

            plaintext = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")

            if options.compress:
                plaintext = gzip.compress(plaintext)

            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            plaintext_hash = hashlib.sha256(plaintext).hexdigest()
            ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()

            return {
                "version": self.EXPORT_VERSION,
                "cryptosafe_export": True,
                "timestamp": self._utc_now(),
                "metadata": self._metadata(entry_count, options),
                "encryption": {
                    "algorithm": f"AES-{options.encryption_bits}-GCM",
                    "key_derivation": "PBKDF2-HMAC-SHA256",
                    "iterations": self.PBKDF2_ITERATIONS,
                    "salt": self._b64e(salt),
                    "nonce": self._b64e(nonce),
                    "compressed": options.compress,
                },
                "data": self._b64e(ciphertext),
                "integrity": {
                    "hash_algorithm": "SHA256",
                    "plaintext_hash": plaintext_hash,
                    "ciphertext_hash": ciphertext_hash,
                },
            }

        except Exception as exc:
            raise VaultExportError(f"Failed to encrypt export payload: {exc}") from exc

    def _derive_export_key(
        self,
        password: str,
        salt: bytes,
        encryption_bits: int,
    ) -> bytes:
        if encryption_bits not in (128, 256):
            raise VaultExportError("Encryption strength must be 128 or 256 bits.")

        length = encryption_bits // 8

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )

        return kdf.derive(password.encode("utf-8"))

    def _entries_to_csv(self, entries: Iterable[Dict[str, Any]]) -> str:
        output = io.StringIO()
        fieldnames = ["title", "username", "password", "url", "notes"]

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )

        writer.writeheader()

        for entry in entries:
            writer.writerow(
                {
                    "title": entry.get("title", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "url": entry.get("url", ""),
                    "notes": entry.get("notes", ""),
                }
            )

        return output.getvalue()

    def _entries_to_bitwarden_json(
        self,
        entries: Iterable[Dict[str, Any]],
    ) -> Dict[str, Any]:
        items = []

        for entry in entries:
            uris = []

            if entry.get("url"):
                uris.append(
                    {
                        "uri": entry.get("url", ""),
                    }
                )

            items.append(
                {
                    "type": 1,
                    "name": entry.get("title", "Untitled"),
                    "notes": entry.get("notes", ""),
                    "login": {
                        "username": entry.get("username", ""),
                        "password": entry.get("password", ""),
                        "uris": uris,
                    },
                }
            )

        return {
            "format": "bitwarden_json",
            "encrypted": False,
            "items": items,
        }

    def _metadata(self, entry_count: int, options: ExportOptions) -> Dict[str, Any]:
        return {
            "source_application": self.SOURCE_APP,
            "export_version": self.EXPORT_VERSION,
            "exported_at": self._utc_now(),
            "entry_count": entry_count,
            "format": options.format,
            "include_notes": options.include_notes,
            "encryption_bits": options.encryption_bits,
            "compressed": options.compress,
            "master_confirmation_required": options.require_master_confirmation,
        }

    def _validate_options(self, options: ExportOptions) -> None:
        if options.format not in self.SUPPORTED_FORMATS:
            raise VaultExportError(
                f"Unsupported export format: {options.format}. "
                f"Supported: {sorted(self.SUPPORTED_FORMATS)}"
            )

        if options.encryption_bits not in (128, 256):
            raise VaultExportError("encryption_bits must be 128 or 256.")

    def _audit(self, event_type: str, details: Dict[str, Any]) -> None:
        if self.audit_logger is None:
            return

        try:
            if hasattr(self.audit_logger, "log_event"):
                self.audit_logger.log_event(event_type, details)
            elif hasattr(self.audit_logger, "log"):
                self.audit_logger.log(event_type, details)
        except Exception:
            pass

    @staticmethod
    def _b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _safe_remove_temp(temp_name: Optional[str]) -> None:
        if not temp_name:
            return

        try:
            path = Path(temp_name)
            if path.exists():
                path.unlink()
        except Exception:
            pass
