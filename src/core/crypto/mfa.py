from __future__ import annotations

from abc import ABC, abstractmethod


class MFAProvider(ABC):
    @abstractmethod
    def verify(self, code: str) -> bool:
        pass


class DummyMFAProvider(MFAProvider):
    def __init__(self, expected_code: str = "000000") -> None:
        self.expected_code = expected_code

    def verify(self, code: str) -> bool:
        return code == self.expected_code