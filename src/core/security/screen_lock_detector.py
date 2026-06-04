from __future__ import annotations

import platform
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class ScreenLockState(str, Enum):
    UNKNOWN = "unknown"
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    SCREEN_SAVER = "screen_saver"


@dataclass
class ScreenLockEvent:
    state: ScreenLockState
    platform_name: str
    detected_by: str


class ScreenLockDetector:

    def __init__(
        self,
        on_lock_detected: Callable[[ScreenLockEvent], None],
        poll_interval_seconds: float = 2.0,
    ):
        self.on_lock_detected = on_lock_detected
        self.poll_interval_seconds = poll_interval_seconds
        self.platform_name = platform.system()
        self.last_state = ScreenLockState.UNKNOWN
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return

            self._running = True
            self._thread = threading.Thread(
                target=self._run,
                name="CryptoSafeScreenLockDetector",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False

        if self._thread is not None:
            self._thread.join(timeout=2)

    def inject_state_for_testing(self, state: ScreenLockState) -> None:
        self._handle_state_change(state, detected_by="test_injection")

    def poll_platform_state(self) -> ScreenLockState:
        return self.last_state

    def _handle_state_change(self, state: ScreenLockState, detected_by: str) -> None:
        with self._lock:
            previous = self.last_state
            self.last_state = state

        if state in {ScreenLockState.LOCKED, ScreenLockState.SCREEN_SAVER} and state != previous:
            self.on_lock_detected(
                ScreenLockEvent(
                    state=state,
                    platform_name=self.platform_name,
                    detected_by=detected_by,
                )
            )

    def _run(self) -> None:
        while True:
            with self._lock:
                running = self._running

            if not running:
                return

            state = self.poll_platform_state()
            self._handle_state_change(state, detected_by="polling")
            time.sleep(self.poll_interval_seconds)