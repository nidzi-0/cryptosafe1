from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class AuditVerificationSchedule:

    interval_seconds: int = 24 * 60 * 60
    recent_limit: int = 1000


class AuditVerificationScheduler:
    def __init__(
        self,
        verifier,
        schedule: AuditVerificationSchedule | None = None,
        on_result=None,
    ):
        self.verifier = verifier
        self.schedule = schedule or AuditVerificationSchedule()
        self.on_result = on_result

        self._timer: threading.Timer | None = None
        self._running = False
        self.last_result = None

    def start(self) -> None:
        if self._running:
            return

        self._running = True
        self._schedule_next()

    def stop(self) -> None:
        self._running = False

        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def run_once(self):
        result = self.verifier.verify_recent(
            limit=self.schedule.recent_limit,
        )

        self.last_result = result

        if self.on_result is not None:
            try:
                self.on_result(result)
            except Exception:
                pass

        return result

    def _schedule_next(self):
        if not self._running:
            return

        self._timer = threading.Timer(
            self.schedule.interval_seconds,
            self._on_timer,
        )
        self._timer.daemon = True
        self._timer.start()

    def _on_timer(self):
        try:
            self.run_once()
        finally:
            self._schedule_next()