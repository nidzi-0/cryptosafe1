from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Type
import threading
import queue


@dataclass(frozen=True)
class EntryAdded:
    entry_id: int
    title: str


@dataclass(frozen=True)
class EntryUpdated:
    entry_id: int


@dataclass(frozen=True)
class EntryDeleted:
    entry_id: int


@dataclass(frozen=True)
class UserLoggedIn:
    user: str = "local"


@dataclass(frozen=True)
class UserLoggedOut:
    user: str = "local"


@dataclass(frozen=True)
class ClipboardCopied:
    entry_id: int


@dataclass(frozen=True)
class ClipboardCleared:
    pass


Handler = Callable[[Any], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: Dict[Type[Any], List[Handler]] = {}
        self._lock = threading.Lock()
        self._q: "queue.Queue[Any]" = queue.Queue()
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def subscribe(self, event_type: Type[Any], handler: Handler) -> None:
        with self._lock:
            self._subs.setdefault(event_type, []).append(handler)

    def publish(self, event: Any) -> None:
        handlers = self._subs.get(type(event), [])
        for h in list(handlers):
            h(event)

    def publish_async(self, event: Any) -> None:
        self._q.put(event)

    def _run(self) -> None:
        while True:
            event = self._q.get()
            try:
                self.publish(event)
            finally:
                self._q.task_done()