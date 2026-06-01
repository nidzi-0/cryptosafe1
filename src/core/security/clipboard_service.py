from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


class ClipboardServiceError(Exception):
    """Базовая ошибка сервиса буфера обмена."""


class ClipboardIntegrationNotEnabledError(ClipboardServiceError):
    """Буфер обмена пока не включён. Заготовка для Sprint 4."""


@dataclass(frozen=True)
class ClipboardRequest:
    purpose: str
    requested_at: str


class ClipboardService:
    def __init__(self):
        self._last_request: ClipboardRequest | None = None

    def request_copy_secret(self, purpose: str = "copy_secret") -> ClipboardRequest:
        request = ClipboardRequest(
            purpose=purpose,
            requested_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        self._last_request = request

        raise ClipboardIntegrationNotEnabledError(
            "Копирование секретов в буфер обмена будет реализовано в Sprint 4."
        )

    def get_last_request(self) -> ClipboardRequest | None:
        return self._last_request

    def clear(self) -> None:
        self._last_request = None