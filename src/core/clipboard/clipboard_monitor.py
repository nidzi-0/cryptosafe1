from __future__ import annotations

import threading
import time

from src.core.clipboard.platform_adapter import ClipboardAdapter


class ClipboardMonitorError(Exception):
    """Ошибка мониторинга буфера обмена."""


class ClipboardMonitor:
    def __init__(
        self,
        platform_adapter: ClipboardAdapter,
        clipboard_service,
        poll_interval_seconds: float = 1.0,
    ):
        self.platform_adapter = platform_adapter
        self.clipboard_service = clipboard_service
        self.poll_interval_seconds = poll_interval_seconds

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_seen_content = ""
        self._running = False

    def start(self) -> bool:
        if self._running:
            return True

        try:
            self._last_seen_content = self.platform_adapter.get_clipboard_content()
        except Exception:
            self._last_seen_content = ""

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run,
            name="ClipboardMonitor",
            daemon=True,
        )

        self._running = True
        self._thread.start()

        return True

    def stop(self) -> None:
        self._stop_event.set()
        self._running = False

        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def is_running(self) -> bool:
        return self._running

    def check_once(self) -> None:
        try:
            current = self.platform_adapter.get_clipboard_content()
        except Exception:
            current = ""

        status = self.clipboard_service.get_status()

        if not status.active:
            self._last_seen_content = current
            return

        if status.ephemeral:
            return

        if current != self._last_seen_content:
            self._last_seen_content = current
            self.clipboard_service.on_external_clipboard_change_detected(
                "external_change"
            )
            return

        self.clipboard_service.verify_system_clipboard_snapshot()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.check_once()
            time.sleep(self.poll_interval_seconds)