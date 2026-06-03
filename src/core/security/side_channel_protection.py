from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence


class SideChannelProtectionError(Exception):
    """Базовая ошибка"""


@dataclass(frozen=True)
class TimingSample:
    label: str
    elapsed_ns: int


class ConstantTime:
    @staticmethod
    def bytes_equal(left: bytes | bytearray | memoryview, right: bytes | bytearray | memoryview) -> bool:
        if isinstance(left, memoryview):
            left = left.tobytes()
        if isinstance(right, memoryview):
            right = right.tobytes()

        if isinstance(left, bytearray):
            left = bytes(left)
        if isinstance(right, bytearray):
            right = bytes(right)

        if not isinstance(left, bytes) or not isinstance(right, bytes):
            return False

        return hmac.compare_digest(left, right)

    @staticmethod
    def string_equal(left: str, right: str) -> bool:
        if not isinstance(left, str) or not isinstance(right, str):
            return False

        left_bytes = left.encode("utf-8", errors="surrogatepass")
        right_bytes = right.encode("utf-8", errors="surrogatepass")
        return hmac.compare_digest(left_bytes, right_bytes)

    @staticmethod
    def fixed_time_contains(secret_candidate: str, values: Iterable[str]) -> bool:
        candidate = secret_candidate.encode("utf-8", errors="ignore")
        found = False

        for value in values:
            value_bytes = str(value).encode("utf-8", errors="ignore")
            if hmac.compare_digest(candidate, value_bytes):
                found = True

        return found

    @staticmethod
    def constant_time_select(condition: bool, value_if_true: bytes, value_if_false: bytes) -> bytes:
        if len(value_if_true) != len(value_if_false):
            raise ValueError("Values must have equal length")

        mask = 0xFF if condition else 0x00
        return bytes(
            (a & mask) | (b & (~mask & 0xFF))
            for a, b in zip(value_if_true, value_if_false)
        )


class TimingNoise:
    def __init__(self, enabled: bool = True, min_ms: int = 1, max_ms: int = 5):
        if min_ms < 0 or max_ms < min_ms:
            raise ValueError("Invalid timing noise range")

        self.enabled = enabled
        self.min_ms = min_ms
        self.max_ms = max_ms

    def sleep(self) -> None:
        if not self.enabled:
            return

        delay_ms = self.min_ms + secrets.randbelow(self.max_ms - self.min_ms + 1)
        time.sleep(delay_ms / 1000)


class SideChannelProtector:
    def __init__(self, timing_noise: TimingNoise | None = None):
        self.timing_noise = timing_noise or TimingNoise(enabled=False)

    def secure_compare_bytes(self, left: bytes, right: bytes) -> bool:
        result = ConstantTime.bytes_equal(left, right)
        self.timing_noise.sleep()
        return result

    def secure_compare_text(self, left: str, right: str) -> bool:
        result = ConstantTime.string_equal(left, right)
        self.timing_noise.sleep()
        return result

    def measure_operation(self, label: str, operation: Callable[[], object]) -> TimingSample:
        start = time.perf_counter_ns()
        operation()
        end = time.perf_counter_ns()
        return TimingSample(label=label, elapsed_ns=end - start)

    def timing_variance_ratio(self, samples: Sequence[TimingSample]) -> float:
        if not samples:
            return 0.0

        values = [sample.elapsed_ns for sample in samples]
        low = min(values)
        high = max(values)

        if low == 0:
            return 0.0

        return high / low