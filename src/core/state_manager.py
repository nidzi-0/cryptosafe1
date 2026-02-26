from __future__ import annotations

import threading
import time
from dataclasses import dataclass


def wipe_bytearray(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


@dataclass
class SessionState:
    unlocked: bool = False
    last_activity_ts: float = 0.0


class StateManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.session = SessionState(unlocked=False, last_activity_ts=time.time())
        self.clipboard_preview: str | None = None
        self.clipboard_clear_at: float | None = None
        self.idle_timeout_sec: int = 0

    def set_unlocked(self, unlocked: bool) -> None:
        with self._lock:
            self.session.unlocked = unlocked
            self.session.last_activity_ts = time.time()

    def touch(self) -> None:
        with self._lock:
            self.session.last_activity_ts = time.time()

    def set_clipboard_timer(self, seconds: int) -> None:
        with self._lock:
            self.clipboard_clear_at = time.time() + seconds

    def clear_clipboard_state(self) -> None:
        with self._lock:
            self.clipboard_preview = None
            self.clipboard_clear_at = None