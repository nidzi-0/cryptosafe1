from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Callable


@dataclass
class MousePoint:
    x: int
    y: int
    timestamp: float


class ShakeDetector:

    def __init__(
        self,
        on_shake: Callable[[], None],
        window_seconds: float = 1.2,
        min_direction_changes: int = 4,
        min_distance_px: int = 40,
    ):
        self.on_shake = on_shake
        self.window_seconds = window_seconds
        self.min_direction_changes = min_direction_changes
        self.min_distance_px = min_distance_px
        self.points: deque[MousePoint] = deque(maxlen=30)
        self.last_trigger_at = 0.0
        self.cooldown_seconds = 2.0

    def record_position(self, x: int, y: int) -> bool:
        now = time.monotonic()
        self.points.append(MousePoint(x=x, y=y, timestamp=now))
        self._drop_old_points(now)

        if now - self.last_trigger_at < self.cooldown_seconds:
            return False

        if self._is_shake():
            self.last_trigger_at = now
            self.on_shake()
            return True

        return False

    def _drop_old_points(self, now: float) -> None:
        while self.points and now - self.points[0].timestamp > self.window_seconds:
            self.points.popleft()

    def _is_shake(self) -> bool:
        if len(self.points) < 6:
            return False

        direction_changes = 0
        last_direction = 0

        points = list(self.points)

        for previous, current in zip(points, points[1:]):
            dx = current.x - previous.x
            dy = current.y - previous.y

            if abs(dx) >= abs(dy):
                if abs(dx) < self.min_distance_px:
                    continue
                direction = 1 if dx > 0 else -1
            else:
                if abs(dy) < self.min_distance_px:
                    continue
                direction = 1 if dy > 0 else -1

            if last_direction != 0 and direction != last_direction:
                direction_changes += 1

            last_direction = direction

        return direction_changes >= self.min_direction_changes