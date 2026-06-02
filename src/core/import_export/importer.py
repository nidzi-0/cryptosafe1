import base64
import csv
import gzip
import hashlib
import io
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class VaultImportError(Exception):
    pass


class VaultImporter:
    MAX_FILE_SIZE = 10 * 1024 * 1024
    DEFAULT_TIMEOUT_SECONDS = 30
    REQUIRED_FIELDS = ["title", "username", "password", "url", "notes"]

    def __init__(
        self,
        entry_manager: Any,
        audit_logger: Optional[Any] = None,
        max_file_size: int = MAX_FILE_SIZE,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.max_file_size = max_file_size
        self.timeout_seconds = timeout_seconds

    def import_file(
        self,
        file_path: Union[str, Path],
        password: Optional[str] = None,
        mode: str = "merge",
        dry_run: bool = False,
        import_format: Optional[str] = None,
        duplicate_handling: str = "update",
    ) -> Dict[str, Any]:
        return self._run_with_timeout(
            self._import_file_internal,
            file_path,
            password,
            mode,
            dry_run,
            import_format,
            duplicate_handling,
        )

    def import_package(
        self,
        package: Dict[str, Any],
        password: Optional[str],
        mode: str = "merge",
        dry_run: bool = False,
        duplicate_handling: str = "update",
    ) -> Dict[str, Any]:
        return self._run_with_timeout(
            self._import_package_internal,
            package,
            password,
            mode,
            dry_run,
            duplicate_handling,
        )

    def import_raw(
        self,
        raw_data: str,
        import_format: str,
        mode: str = "merge",
        dry_run: bool = False,
        duplicate_handling: str = "update",
    ) -> Dict[str, Any]:
        return self._run_with_timeout(
            self._import_raw_internal,
            raw_data,
            import_format,
            mode,
            dry_run,
            duplicate_handling,
        )

    def _import_file_internal(
        self,
        file_path: Union[str, Path],
        password: Optional[str],
        mode: str,
        dry_run: bool,
        import_format: Optional[str],
        duplicate_handling: str,
    ) -> Dict[str, Any]:
        file_path = Path(file_path)

        if not file_path.exists():
            raise VaultImportError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size

        if file_size > self.max_file_size:
            raise VaultImportError("File size exceeds maximum allowed 10 MB")

        try:
            raw_data = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raw_data = file_path.read_text(encoding="utf-8-sig")
        except Exception as exc:
            raise VaultImportError(f"Failed to read import file: {exc}") from exc

        detected_format = import_format or self._detect_format(raw_data, file_path)

        if detected_format == "encrypted_json":
            try:
                package = json.loads(raw_data)
            except Exception as exc:
                raise VaultImportError(f"Failed to parse encrypted JSON package: {exc}") from exc

            return self._import_package_internal(
                package=package,
                password=password,
                mode=mode,
                dry_run=dry_run,
                duplicate_handling=duplicate_handling,
            )

        return self._import_raw_internal(
            raw_data=raw_data,
            import_format=detected_format,
            mode=mode,
            dry_run=dry_run,
            duplicate_handling=duplicate_handling,
        )

    def _import_package_internal(
        self,
        package: Dict[str, Any],
        password: Optional[str],
        mode: str,
        dry_run: bool,
        duplicate_handling: str,
    ) -> Dict[str, Any]:
        if not password:
            raise VaultImportError("Password is required for encrypted import")

        self._validate_mode(mode)
        self._validate_duplicate_handling(duplicate_handling)

        payload = self._sandbox_execute(self._decrypt_package, package, password)
        entries = self._entries_from_payload(payload)
        entries = self._validate_and_prepare_entries(entries)

        return self._apply_import(
            entries=entries,
            mode=mode,
            dry_run=dry_run,
            duplicate_handling=duplicate_handling,
            source_format=payload.get("format", "encrypted_json"),
        )

    def _import_raw_internal(
        self,
        raw_data: str,
        import_format: str,
        mode: str,
        dry_run: bool,
        duplicate_handling: str,
    ) -> Dict[str, Any]:
        self._validate_mode(mode)
        self._validate_duplicate_handling(duplicate_handling)

        if import_format == "csv":
            entries = self._parse_csv(raw_data)
        elif import_format == "lastpass_csv":
            entries = self._parse_lastpass_csv(raw_data)
        elif import_format == "bitwarden_json":
            entries = self._parse_bitwarden_json(raw_data)
        else:
            raise VaultImportError(f"Unsupported import format: {import_format}")

        entries = self._validate_and_prepare_entries(entries)

        return self._apply_import(
            entries=entries,
            mode=mode,
            dry_run=dry_run,
            duplicate_handling=duplicate_handling,
            source_format=import_format,
        )

    def _decrypt_package(self, package: Dict[str, Any], password: str) -> Dict[str, Any]:
        self._validate_package_before_decryption(package)

        enc_info = package["encryption"]

        try:
            salt = base64.b64decode(enc_info["salt"])
            nonce = base64.b64decode(enc_info["nonce"])
            ciphertext = base64.b64decode(package["data"])
        except Exception as exc:
            raise VaultImportError(f"Invalid base64 data: {exc}") from exc

        if len(salt) < 8:
            raise VaultImportError("Invalid encryption salt")

        if len(nonce) != 12:
            raise VaultImportError("Invalid AES-GCM nonce")

        key_length = self._get_key_length(enc_info)

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                iterations=int(enc_info.get("iterations", 100_000)),
            )
            key = kdf.derive(password.encode("utf-8"))
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise VaultImportError("Failed to decrypt package") from exc

        self._verify_integrity(package, plaintext)

        if enc_info.get("compressed", False):
            try:
                plaintext = gzip.decompress(plaintext)
            except Exception as exc:
                raise VaultImportError("Failed to decompress package") from exc

        try:
            return json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise VaultImportError(f"Failed to parse decrypted payload: {exc}") from exc

    def _validate_package_before_decryption(self, package: Dict[str, Any]) -> None:
        if not isinstance(package, dict):
            raise VaultImportError("Package must be a dictionary")

        if package.get("cryptosafe_export") is not True:
            raise VaultImportError("Not a CryptoSafe export package")

        if "encryption" not in package:
            raise VaultImportError("Package does not contain encryption section")

        if "data" not in package:
            raise VaultImportError("Package does not contain encrypted data")

        if "integrity" not in package:
            raise VaultImportError("Package does not contain integrity section")

        enc_info = package["encryption"]

        if not isinstance(enc_info, dict):
            raise VaultImportError("Encryption section must be a dictionary")

        algorithm = enc_info.get("algorithm")

        if algorithm not in {"AES-128-GCM", "AES-256-GCM"}:
            raise VaultImportError(f"Unsupported encryption algorithm: {algorithm}")

        if "salt" not in enc_info:
            raise VaultImportError("Encryption salt is missing")

        if "nonce" not in enc_info:
            raise VaultImportError("Encryption nonce is missing")

        if "iterations" not in enc_info:
            raise VaultImportError("KDF iterations are missing")

    def _verify_integrity(self, package: Dict[str, Any], plaintext: bytes) -> None:
        expected_hash = package.get("integrity", {}).get("plaintext_hash")

        if not expected_hash:
            raise VaultImportError("Missing plaintext hash")

        actual_hash = hashlib.sha256(plaintext).hexdigest()

        if expected_hash != actual_hash:
            raise VaultImportError("Integrity check failed")

    def _get_key_length(self, enc_info: Dict[str, Any]) -> int:
        algorithm = enc_info.get("algorithm", "AES-256-GCM")

        if algorithm == "AES-128-GCM":
            return 16

        if algorithm == "AES-256-GCM":
            return 32

        raise VaultImportError(f"Unsupported encryption algorithm: {algorithm}")

    def _entries_from_payload(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        payload_format = payload.get("format")

        if payload_format == "native":
            return payload.get("entries", [])

        if payload_format == "csv":
            return self._parse_csv(payload.get("csv", ""))

        if payload_format == "bitwarden_json":
            return self._parse_bitwarden_items(payload.get("items", []))

        if "entries" in payload:
            return payload.get("entries", [])

        raise VaultImportError(f"Unsupported decrypted payload format: {payload_format}")

    def _parse_csv(self, raw_data: str) -> List[Dict[str, Any]]:
        dialect = self._detect_csv_dialect(raw_data)
        reader = csv.DictReader(io.StringIO(raw_data), dialect=dialect)
        entries = []

        for row in reader:
            entries.append(
                {
                    "title": row.get("title") or row.get("name") or row.get("Name") or "Untitled",
                    "username": row.get("username") or row.get("login") or row.get("email") or "",
                    "password": row.get("password") or row.get("pass") or "",
                    "url": row.get("url") or row.get("uri") or row.get("website") or "",
                    "notes": row.get("notes") or row.get("note") or row.get("extra") or "",
                }
            )

        return entries

    def _parse_lastpass_csv(self, raw_data: str) -> List[Dict[str, Any]]:
        dialect = self._detect_csv_dialect(raw_data)
        reader = csv.DictReader(io.StringIO(raw_data), dialect=dialect)
        entries = []

        for row in reader:
            entries.append(
                {
                    "title": row.get("name") or row.get("title") or "Untitled",
                    "username": row.get("username") or "",
                    "password": row.get("password") or "",
                    "url": row.get("url") or "",
                    "notes": row.get("extra") or row.get("notes") or "",
                }
            )

        return entries

    def _parse_bitwarden_json(self, raw_data: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(raw_data)
        except Exception as exc:
            raise VaultImportError(f"Failed to parse Bitwarden JSON: {exc}") from exc

        return self._parse_bitwarden_items(data.get("items", []))

    def _parse_bitwarden_items(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        entries = []

        for item in items:
            login = item.get("login", {})
            uris = login.get("uris", [])

            url = ""

            if uris and isinstance(uris, list):
                first_uri = uris[0]
                if isinstance(first_uri, dict):
                    url = first_uri.get("uri", "")

            entries.append(
                {
                    "title": item.get("name", "Untitled"),
                    "username": login.get("username", ""),
                    "password": login.get("password", ""),
                    "url": url,
                    "notes": item.get("notes", ""),
                }
            )

        return entries

    def _detect_csv_dialect(self, raw_data: str):
        sample = raw_data[:4096]

        try:
            return csv.Sniffer().sniff(sample, delimiters=",;\t")
        except Exception:
            return csv.excel

    def _detect_format(self, raw_data: str, file_path: Optional[Path] = None) -> str:
        stripped = raw_data.lstrip()

        if stripped.startswith("{"):
            try:
                data = json.loads(raw_data)
            except Exception:
                raise VaultImportError("JSON format detection failed")

            if data.get("cryptosafe_export") is True:
                return "encrypted_json"

            if "items" in data:
                return "bitwarden_json"

            raise VaultImportError("Unknown JSON import format")

        header = raw_data.splitlines()[0].lower() if raw_data.splitlines() else ""

        if "url" in header and "username" in header and "password" in header and "extra" in header:
            return "lastpass_csv"

        if file_path and file_path.suffix.lower() == ".csv":
            return "csv"

        if "," in header or ";" in header or "\t" in header:
            return "csv"

        raise VaultImportError("Could not detect import format")

    def _validate_and_prepare_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not isinstance(entries, list):
            raise VaultImportError("Imported entries must be a list")

        prepared = []

        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise VaultImportError(f"Entry #{index + 1} must be a dictionary")

            normalized = self._normalize_entry(entry)
            self._validate_entry(normalized, index)
            sanitized = self._sanitize_entry(normalized)
            self._scan_for_malicious_patterns(sanitized)
            prepared.append(sanitized)

        return prepared

    def _normalize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {
            "id": entry.get("id") or entry.get("entry_id"),
            "title": str(entry.get("title") or entry.get("name") or "Untitled"),
            "username": str(entry.get("username") or ""),
            "password": str(entry.get("password") or ""),
            "url": str(entry.get("url") or entry.get("website") or ""),
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
        }

        if "notes" in entry:
            normalized["notes"] = str(entry.get("notes") or "")

        return normalized

    def _validate_entry(self, entry: Dict[str, Any], index: int) -> None:
        required_fields = ["title", "username", "password", "url"]

        for field in required_fields:
            if field not in entry:
                raise VaultImportError(f"Entry #{index + 1} missing field: {field}")

            if not isinstance(entry[field], str):
                raise VaultImportError(f"Entry #{index + 1} field must be string: {field}")

        if "notes" in entry and not isinstance(entry["notes"], str):
            raise VaultImportError(f"Entry #{index + 1} field must be string: notes")

        if len(entry["title"]) > 255:
            raise VaultImportError(f"Entry #{index + 1} title is too long")

        if len(entry["username"]) > 512:
            raise VaultImportError(f"Entry #{index + 1} username is too long")

        if len(entry["password"]) > 4096:
            raise VaultImportError(f"Entry #{index + 1} password is too long")

        if len(entry["url"]) > 2048:
            raise VaultImportError(f"Entry #{index + 1} url is too long")

        if "notes" in entry and len(entry["notes"]) > 10000:
            raise VaultImportError(f"Entry #{index + 1} notes are too long")

    def _sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}

        for key, value in entry.items():
            if isinstance(value, str):
                cleaned = value.replace("\x00", "")
                cleaned = cleaned.replace("<script", "&lt;script")
                cleaned = cleaned.replace("</script>", "&lt;/script&gt;")
                cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")
                sanitized[key] = cleaned
            else:
                sanitized[key] = value

        return sanitized

    def _scan_for_malicious_patterns(self, entry: Dict[str, Any]) -> None:
        patterns = [
            r"javascript:",
            r"vbscript:",
            r"data:text/html",
            r"<\s*iframe",
            r"<\s*object",
            r"<\s*embed",
            r"\.exe\s*$",
            r"\.bat\s*$",
            r"\.cmd\s*$",
            r"\.ps1\s*$",
        ]

        text = " ".join(str(value).lower() for value in entry.values())

        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                raise VaultImportError("Malicious content detected in imported data")

    def _apply_import(
        self,
        entries: List[Dict[str, Any]],
        mode: str,
        dry_run: bool,
        duplicate_handling: str,
        source_format: str,
    ) -> Dict[str, Any]:
        existing_keys = self._get_existing_keys()
        imported = 0
        skipped = 0
        duplicates = 0
        preview_entries = []

        if dry_run:
            for entry in entries:
                duplicate = self._entry_key(entry) in existing_keys
                preview_entries.append(
                    {
                        "entry": entry,
                        "duplicate": duplicate,
                    }
                )

            return {
                "status": "dry_run",
                "entry_count": len(entries),
                "entries": entries,
                "preview": preview_entries,
                "duplicates": sum(1 for item in preview_entries if item["duplicate"]),
                "source_format": source_format,
            }

        if mode == "replace":
            if hasattr(self.entry_manager, "clear_all"):
                self.entry_manager.clear_all()
            else:
                raise VaultImportError("EntryManager does not support clear_all")

            existing_keys = set()

        for entry in entries:
            entry_key = self._entry_key(entry)
            is_duplicate = entry_key in existing_keys

            if is_duplicate:
                duplicates += 1

                if duplicate_handling == "skip":
                    skipped += 1
                    continue

                if duplicate_handling == "error":
                    raise VaultImportError(f"Duplicate entry detected: {entry.get('title')}")

            self._save_entry(entry)
            existing_keys.add(entry_key)
            imported += 1

        self._audit(
            "vault_imported",
            {
                "count": imported,
                "skipped": skipped,
                "duplicates": duplicates,
                "mode": mode,
                "source_format": source_format,
            },
        )

        return {
            "status": "success",
            "imported": imported,
            "skipped": skipped,
            "duplicates": duplicates,
            "mode": mode,
            "source_format": source_format,
        }

    def _get_existing_keys(self) -> set:
        keys = set()

        if not hasattr(self.entry_manager, "list_entries"):
            return keys

        try:
            entries = self.entry_manager.list_entries()
        except Exception:
            return keys

        for entry in entries:
            if isinstance(entry, dict):
                normalized = self._normalize_entry(entry)
            elif hasattr(entry, "__dict__"):
                normalized = self._normalize_entry(dict(entry.__dict__))
            else:
                continue

            keys.add(self._entry_key(normalized))

        return keys

    def _entry_key(self, entry: Dict[str, Any]) -> Tuple[str, str, str]:
        return (
            entry.get("title", "").strip().lower(),
            entry.get("username", "").strip().lower(),
            entry.get("url", "").strip().lower(),
        )

    def _save_entry(self, entry: Dict[str, Any]) -> None:
        if hasattr(self.entry_manager, "upsert_entry"):
            self.entry_manager.upsert_entry(entry)
            return

        if hasattr(self.entry_manager, "create_entry"):
            self.entry_manager.create_entry(
                title=entry.get("title", ""),
                username=entry.get("username", ""),
                password=entry.get("password", ""),
                url=entry.get("url", ""),
                notes=entry.get("notes", ""),
            )
            return

        raise VaultImportError("EntryManager does not support upsert_entry or create_entry")

    def _validate_mode(self, mode: str) -> None:
        if mode not in {"merge", "replace"}:
            raise VaultImportError("Import mode must be merge or replace")

    def _validate_duplicate_handling(self, duplicate_handling: str) -> None:
        if duplicate_handling not in {"update", "skip", "error"}:
            raise VaultImportError("Duplicate handling must be update, skip or error")

    def _sandbox_execute(self, func, *args, **kwargs):
        start_time = time.monotonic()

        try:
            result = func(*args, **kwargs)
        except VaultImportError:
            raise
        except Exception as exc:
            raise VaultImportError(f"Sandboxed import operation failed: {exc}") from exc

        elapsed = time.monotonic() - start_time

        if elapsed > self.timeout_seconds:
            raise VaultImportError("Timeout after 30 seconds of processing")

        return result

    def _run_with_timeout(self, func, *args, **kwargs):
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)

            try:
                return future.result(timeout=self.timeout_seconds)
            except TimeoutError as exc:
                raise VaultImportError("Timeout after 30 seconds of processing") from exc

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