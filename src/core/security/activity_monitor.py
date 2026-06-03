from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class ActivitySensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class AutoLockConfig:
    timeout_seconds: int = 300
    sensitivity: ActivitySensitivity = ActivitySensitivity.MEDIUM
    device_profile: str = "desktop"
    enabled: bool = True

    def validate(self) -> None:
        if not 60 <= self.timeout_seconds <= 8 * 60 * 60:
            raise ValueError("Auto-lock timeout must be between 1 minute and 8 hours")

        if self.device_profile not in {"desktop", "laptop"}:
            raise ValueError("device_profile must be desktop or laptop")


class ActivityMonitor:
    def __init__(
        self,
        lock_callback: Callable[[], None],
        config: AutoLockConfig | None = None,
        poll_interval_seconds: float = 1.0,
    ):
        self.config = config or AutoLockConfig()
        self.config.validate()

        self.lock_callback = lock_callback
        self.poll_interval_seconds = poll_interval_seconds
        self.last_activity = time.monotonic()
        self.last_focus_change = time.monotonic()
        self.last_lock_at: float | None = None
        self.locked = False

        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return

            self._running = True
            self._thread = threading.Thread(target=self._run, name="CryptoSafeActivityMonitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False

        if self._thread is not None:
            self._thread.join(timeout=2)

    def record_mouse_activity(self) -> None:
        self.record_activity("mouse")

    def record_keyboard_activity(self) -> None:
        self.record_activity("keyboard")

    def record_focus_change(self) -> None:
        with self._lock:
            self.last_focus_change = time.monotonic()
        self.record_activity("focus")

    def record_screen_lock(self) -> None:
        self.force_lock()

    def record_activity(self, source: str = "unknown") -> None:
        with self._lock:
            self.last_activity = time.monotonic()
            if self.locked:
                return

    def seconds_since_activity(self) -> float:
        with self._lock:
            return time.monotonic() - self.last_activity

    def should_lock(self) -> bool:
        if not self.config.enabled:
            return False

        return self.seconds_since_activity() >= self.config.timeout_seconds

    def force_lock(self) -> None:
        with self._lock:
            if self.locked:
                return
            self.locked = True
            self.last_lock_at = time.monotonic()

        self.lock_callback()

    def resume_after_unlock(self) -> None:
        with self._lock:
            self.locked = False
            self.last_activity = time.monotonic()

    def _run(self) -> None:
        while True:
            with self._lock:
                running = self._running

            if not running:
                return

            if self.should_lock():
                self.force_lock()

            time.sleep(self.poll_interval_seconds)