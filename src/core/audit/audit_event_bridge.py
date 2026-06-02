from __future__ import annotations

from dataclasses import is_dataclass, asdict
from typing import Any

from src.core.audit.audit_logger import AuditLogger, AuditSeverity


class AuditEventBridgeError(Exception):
    """Ошибка event bridge для audit logging."""


class AuditEventBridge:
    EVENT_TYPE_MAP = {
        "EntryCreated": "VAULT_ENTRY_CREATED",
        "EntryUpdated": "VAULT_ENTRY_UPDATED",
        "EntryDeleted": "VAULT_ENTRY_DELETED",
        "ClipboardCopyRequested": "CLIPBOARD_COPY_REQUESTED",

        "ClipboardCopied": "CLIPBOARD_COPIED",
        "ClipboardCleared": "CLIPBOARD_CLEARED",
        "ClipboardWarning": "CLIPBOARD_WARNING",
        "ClipboardSecurityAlert": "CLIPBOARD_SECURITY_ALERT",
        "ClipboardAccessDetected": "CLIPBOARD_ACCESS_DETECTED",
        "EphemeralClipboardTransfer": "CLIPBOARD_EPHEMERAL_TRANSFER",
        "ClipboardStateChanged": "CLIPBOARD_STATE_CHANGED",

        "SystemStartup": "SYSTEM_STARTUP",
        "SystemShutdown": "SYSTEM_SHUTDOWN",
        "VaultLocked": "SYSTEM_VAULT_LOCKED",
        "VaultUnlocked": "SYSTEM_VAULT_UNLOCKED",
        "ConfigurationChanged": "CONFIGURATION_CHANGED",
    }

    SOURCE_MAP = {
        "EntryCreated": "vault",
        "EntryUpdated": "vault",
        "EntryDeleted": "vault",
        "ClipboardCopyRequested": "vault",
        "ClipboardCopied": "clipboard",
        "ClipboardCleared": "clipboard",
        "ClipboardWarning": "clipboard",
        "ClipboardSecurityAlert": "clipboard_security",
        "ClipboardAccessDetected": "clipboard_security",
        "EphemeralClipboardTransfer": "clipboard",
        "ClipboardStateChanged": "clipboard",
        "SystemStartup": "system",
        "SystemShutdown": "system",
        "VaultLocked": "system",
        "VaultUnlocked": "system",
        "ConfigurationChanged": "settings",
    }

    SEVERITY_MAP = {
        "ClipboardWarning": AuditSeverity.WARN.value,
        "ClipboardSecurityAlert": AuditSeverity.CRITICAL.value,
        "ClipboardAccessDetected": AuditSeverity.CRITICAL.value,
        "EntryDeleted": AuditSeverity.WARN.value,
        "SystemShutdown": AuditSeverity.INFO.value,
    }

    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger

    def handle_event(self, event: object) -> None:
        event_class_name = event.__class__.__name__

        event_type = self.EVENT_TYPE_MAP.get(event_class_name, event_class_name.upper())
        source = self.SOURCE_MAP.get(event_class_name, "event_system")
        severity = self.SEVERITY_MAP.get(event_class_name, AuditSeverity.INFO.value)

        details = self._event_to_dict(event)
        entry_id = self._extract_entry_id(details)

        self.audit_logger.log_event(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details,
            entry_id=entry_id,
        )

    def log_system_event(
        self,
        event_type: str,
        details: dict[str, Any] | None = None,
        severity: str = AuditSeverity.INFO.value,
        source: str = "system",
    ) -> None:
        self.audit_logger.log_event(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details or {},
        )

    def _event_to_dict(self, event: object) -> dict[str, Any]:
        if is_dataclass(event):
            return asdict(event)

        if hasattr(event, "__dict__"):
            return dict(event.__dict__)

        return {
            "repr": repr(event),
        }

    def _extract_entry_id(self, details: dict[str, Any]) -> int | str | None:
        for key in ("entry_id", "source_entry_id", "original_entry_id"):
            value = details.get(key)

            if value is not None:
                return value

        entry = details.get("entry")

        if isinstance(entry, dict):
            return entry.get("id")

        return None