from __future__ import annotations

import atexit
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    create_platform_clipboard_adapter,
)
from src.core.clipboard.secure_memory import SecureMemoryBuffer


class ClipboardServiceError(Exception):
    """Базовая ошибка сервиса буфера обмена."""


class ClipboardSecurityLevel(str, Enum):
    BASIC = "basic"
    ADVANCED = "advanced"
    PARANOID = "paranoid"


class ClipboardDataType(str, Enum):
    TEXT = "text"
    PASSWORD = "password"
    USERNAME = "username"
    NOTES = "notes"
    TOTP = "totp"
    ENCRYPTED_BLOB = "encrypted_blob"


@dataclass
class ClipboardSettings:

    auto_clear_seconds: int | None = 30
    notifications_enabled: bool = True
    warning_before_clear_seconds: int = 5
    security_level: ClipboardSecurityLevel = ClipboardSecurityLevel.BASIC
    block_on_suspicious_activity: bool = False
    allowed_applications: list[str] | None = None

    def validate(self) -> None:
        if self.auto_clear_seconds is not None:
            if self.auto_clear_seconds < 5 or self.auto_clear_seconds > 300:
                raise ClipboardServiceError(
                    "Таймер auto-clear должен быть от 5 до 300 секунд или None."
                )

        if self.warning_before_clear_seconds < 0:
            raise ClipboardServiceError(
                "warning_before_clear_seconds не может быть отрицательным."
            )

        if self.allowed_applications is None:
            self.allowed_applications = []


@dataclass(frozen=True)
class ClipboardCopied:
    data_type: str
    source_entry_id: int | str | None
    timeout_seconds: int | None
    copied_at: str


@dataclass(frozen=True)
class ClipboardCleared:
    reason: str
    cleared_at: str


@dataclass(frozen=True)
class ClipboardWarning:
    message: str
    remaining_seconds: int
    created_at: str


@dataclass(frozen=True)
class ClipboardSecurityAlert:
    message: str
    detected_at: str


@dataclass(frozen=True)
class ClipboardAccessDetected:


    reason: str
    detected_at: str


@dataclass(frozen=True)
class EphemeralClipboardTransfer:


    data_type: str
    source_entry_id: int | str | None
    created_at: str


@dataclass(frozen=True)
class ClipboardStateChanged:
    active: bool
    data_type: str | None
    source_entry_id: int | str | None
    remaining_seconds: float


@dataclass
class SecureClipboardItem:

    data_type: str
    source_entry_id: int | str | None
    copied_at_monotonic: float
    copied_at: str
    mask_buffer: SecureMemoryBuffer
    obfuscated_buffer: SecureMemoryBuffer
    data_length: int

    @classmethod
    def create(
        cls,
        data: str,
        data_type: str,
        source_entry_id: int | str | None,
    ) -> "SecureClipboardItem":
        data_bytes = str(data).encode("utf-8")
        mask = secrets.token_bytes(32)

        obfuscated = bytes(
            byte ^ mask[index % len(mask)]
            for index, byte in enumerate(data_bytes)
        )

        return cls(
            data_type=data_type,
            source_entry_id=source_entry_id,
            copied_at_monotonic=time.monotonic(),
            copied_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            mask_buffer=SecureMemoryBuffer(mask),
            obfuscated_buffer=SecureMemoryBuffer(obfuscated),
            data_length=len(data_bytes),
        )

    def reveal(self) -> str:
        mask = self.mask_buffer.read()
        obfuscated = self.obfuscated_buffer.read()

        if not mask or not obfuscated:
            return ""

        data = bytes(
            byte ^ mask[index % len(mask)]
            for index, byte in enumerate(obfuscated[: self.data_length])
        )

        return data.decode("utf-8")

    def masked_preview(self) -> str:
        value = self.reveal()

        if not value:
            return ""

        if len(value) <= 3:
            return "•" * len(value)

        return value[:3] + "•" * min(8, max(3, len(value) - 3))

    def secure_wipe(self) -> None:
        self.mask_buffer.close()
        self.obfuscated_buffer.close()


@dataclass
class ClipboardStatus:
    active: bool
    data_type: str | None = None
    source_entry_id: int | str | None = None
    remaining_seconds: float = 0.0
    preview: str = ""
    ephemeral: bool = False


Observer = Callable[[object], None]


class ClipboardService:

    SENSITIVE_DATA_TYPES = {
        ClipboardDataType.PASSWORD.value,
        ClipboardDataType.TOTP.value,
        ClipboardDataType.ENCRYPTED_BLOB.value,
        "password",
        "totp",
        "encrypted_blob",
    }

    def __init__(
        self,
        platform_adapter: ClipboardAdapter | None = None,
        settings: ClipboardSettings | None = None,
        event_publisher=None,
        audit_logger=None,
    ):
        self.platform_adapter = platform_adapter or create_platform_clipboard_adapter()
        self.settings = settings or ClipboardSettings()
        self.settings.validate()

        self.event_publisher = event_publisher
        self.audit_logger = audit_logger

        self._lock = threading.RLock()
        self._current_item: SecureClipboardItem | None = None
        self._clear_timer: threading.Timer | None = None
        self._warning_timer: threading.Timer | None = None
        self._observers: list[Observer] = []

        self._blocked = False
        self._last_system_clipboard_value = ""
        self._ephemeral_mode = False
        self._suspicious_events_count = 0

        self.register_crash_recovery()

    def subscribe(self, observer: Observer) -> None:
        with self._lock:
            self._observers.append(observer)

    def unsubscribe(self, observer: Observer) -> None:
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def _notify(self, event: object) -> None:
        for observer in list(self._observers):
            try:
                observer(event)
            except Exception:
                pass

        if self.event_publisher is not None:
            try:
                if hasattr(self.event_publisher, "publish"):
                    self.event_publisher.publish(event)
            except Exception:
                pass

    def copy_to_clipboard(
        self,
        data: str,
        data_type: str = ClipboardDataType.PASSWORD.value,
        source_entry_id: int | str | None = None,
        vault_unlocked: bool = True,
        never_copy: bool = False,
        ephemeral: bool = False,
    ) -> ClipboardStatus:
        with self._lock:
            if not vault_unlocked:
                raise ClipboardServiceError("Хранилище заблокировано.")

            if never_copy:
                raise ClipboardServiceError(
                    "Для этой записи запрещено копирование в буфер обмена."
                )

            if self._blocked:
                raise ClipboardServiceError(
                    "Копирование заблокировано из-за подозрительной активности."
                )

            sanitized = self._sanitize_input(data)

            if not sanitized:
                raise ClipboardServiceError("Нельзя скопировать пустое значение.")

            effective_ephemeral = self._should_use_ephemeral_mode(
                data_type=data_type,
                requested_ephemeral=ephemeral,
            )

            self.clear_clipboard(reason="replaced")

            item = SecureClipboardItem.create(
                data=sanitized,
                data_type=data_type,
                source_entry_id=source_entry_id,
            )

            if effective_ephemeral:
                self._ephemeral_mode = True
                self._current_item = item
                self._last_system_clipboard_value = ""
            else:
                self._ephemeral_mode = False

                success = self.platform_adapter.copy_to_clipboard(sanitized)

                if not success:
                    item.secure_wipe()
                    raise ClipboardServiceError(
                        "Не удалось скопировать данные в буфер обмена."
                    )

                self._current_item = item
                self._last_system_clipboard_value = sanitized

            self._start_timers()

            copied_event = ClipboardCopied(
                data_type=data_type,
                source_entry_id=source_entry_id,
                timeout_seconds=self.settings.auto_clear_seconds,
                copied_at=item.copied_at,
            )

            self._notify(copied_event)

            if effective_ephemeral:
                self._notify(
                    EphemeralClipboardTransfer(
                        data_type=data_type,
                        source_entry_id=source_entry_id,
                        created_at=item.copied_at,
                    )
                )

            self._audit("clipboard_copied", data_type, source_entry_id)
            self._notify_state_changed()

            return self.get_status()

    def clear_clipboard(self, reason: str = "manual") -> ClipboardStatus:
        with self._lock:
            self._cancel_timers()

            had_content = self._current_item is not None

            if not self._ephemeral_mode:
                self.platform_adapter.clear_clipboard()

            if self._current_item is not None:
                self._current_item.secure_wipe()
                self._current_item = None

            self._last_system_clipboard_value = ""
            self._ephemeral_mode = False

            if had_content:
                event = ClipboardCleared(
                    reason=reason,
                    cleared_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                )

                self._notify(event)
                self._audit("clipboard_cleared", reason, None)

            self._notify_state_changed()

            return self.get_status()

    def clear_on_lock(self) -> ClipboardStatus:
        return self.clear_clipboard(reason="vault_locked")

    def close(self) -> None:
        self.clear_clipboard(reason="application_closed")

    def get_status(self) -> ClipboardStatus:
        with self._lock:
            if self._current_item is None:
                return ClipboardStatus(active=False)

            remaining = self._remaining_seconds_locked()

            return ClipboardStatus(
                active=True,
                data_type=self._current_item.data_type,
                source_entry_id=self._current_item.source_entry_id,
                remaining_seconds=remaining,
                preview=self._current_item.masked_preview(),
                ephemeral=self._ephemeral_mode,
            )

    def get_current_plaintext_for_testing(self) -> str:

        with self._lock:
            if self._current_item is None:
                return ""

            return self._current_item.reveal()

    def verify_system_clipboard_snapshot(self) -> bool:

        with self._lock:
            if self._current_item is None:
                return True

            if self._ephemeral_mode:
                return True

            try:
                current = self.platform_adapter.get_clipboard_content()
            except Exception:
                return True

            if current != self._last_system_clipboard_value:
                self.on_external_clipboard_change_detected(
                    "expected_content_mismatch"
                )
                return False

            return True

    def on_external_clipboard_change_detected(
        self,
        reason: str = "external_change",
    ) -> None:

        with self._lock:
            self._suspicious_events_count += 1

            access_event = ClipboardAccessDetected(
                reason=reason,
                detected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )

            alert = ClipboardSecurityAlert(
                message="Обнаружена подозрительная активность буфера обмена.",
                detected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )

            self._notify(access_event)
            self._notify(alert)

            self._audit("clipboard_access_detected", reason, None)
            self._audit("clipboard_security_alert", reason, None)

            if self.settings.block_on_suspicious_activity:
                self._blocked = True

            if self._current_item is not None:
                self.clear_clipboard(reason="suspicious_activity")

    def unblock_copying(self) -> None:
        with self._lock:
            self._blocked = False

    def get_suspicious_events_count(self) -> int:

        with self._lock:
            return self._suspicious_events_count

    def get_ephemeral_secret_for_internal_transfer(self) -> str:
        with self._lock:
            if self._current_item is None or not self._ephemeral_mode:
                return ""

            return self._current_item.reveal()

    def register_crash_recovery(self) -> None:
        atexit.register(self._crash_recovery_clear)

    def _crash_recovery_clear(self) -> None:
        try:
            self.clear_clipboard(reason="crash_recovery")
        except Exception:
            try:
                self.platform_adapter.clear_clipboard()
            except Exception:
                pass


    def _should_use_ephemeral_mode(
        self,
        data_type: str,
        requested_ephemeral: bool,
    ) -> bool:
        if requested_ephemeral:
            return True

        if self.settings.security_level == ClipboardSecurityLevel.PARANOID:
            normalized_type = str(data_type or "").lower().strip()

            if normalized_type in self.SENSITIVE_DATA_TYPES:
                return True

        return False

    def _sanitize_input(self, data: str) -> str:
        value = str(data or "")

        value = value.replace("\x00", "")
        value = value.replace("\r\n", "\n")

        return value.strip()

    def _start_timers(self) -> None:
        self._cancel_timers()

        timeout = self.settings.auto_clear_seconds

        if timeout is None:
            return

        self._clear_timer = threading.Timer(timeout, self._on_timeout)
        self._clear_timer.daemon = True
        self._clear_timer.start()

        warning_before = self.settings.warning_before_clear_seconds

        if warning_before > 0 and timeout > warning_before:
            self._warning_timer = threading.Timer(
                timeout - warning_before,
                self._on_warning,
            )
            self._warning_timer.daemon = True
            self._warning_timer.start()

    def _cancel_timers(self) -> None:
        if self._clear_timer is not None:
            self._clear_timer.cancel()
            self._clear_timer = None

        if self._warning_timer is not None:
            self._warning_timer.cancel()
            self._warning_timer = None

    def _on_timeout(self) -> None:
        self.clear_clipboard(reason="timeout")

    def _on_warning(self) -> None:
        with self._lock:
            if self._current_item is None:
                return

            event = ClipboardWarning(
                message="Буфер обмена будет очищен через несколько секунд.",
                remaining_seconds=self.settings.warning_before_clear_seconds,
                created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )

            self._notify(event)
            self._audit("clipboard_warning", "auto_clear_soon", None)

    def _remaining_seconds_locked(self) -> float:
        if self._current_item is None:
            return 0.0

        timeout = self.settings.auto_clear_seconds

        if timeout is None:
            return 0.0

        elapsed = time.monotonic() - self._current_item.copied_at_monotonic

        return max(0.0, timeout - elapsed)

    def _notify_state_changed(self) -> None:
        status = self.get_status()

        event = ClipboardStateChanged(
            active=status.active,
            data_type=status.data_type,
            source_entry_id=status.source_entry_id,
            remaining_seconds=status.remaining_seconds,
        )

        self._notify(event)

    def _audit(
        self,
        action: str,
        details: str,
        source_entry_id: int | str | None,
    ) -> None:
        if self.audit_logger is None:
            return

        try:
            if hasattr(self.audit_logger, "log"):
                self.audit_logger.log(
                    action=action,
                    details=details,
                    entry_id=source_entry_id,
                )
            elif callable(self.audit_logger):
                self.audit_logger(action, details, source_entry_id)
        except Exception:
            pass