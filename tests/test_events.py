from __future__ import annotations

from src.core.events import EventBus, EntryAdded


def test_event_bus_sync_publish():
    bus = EventBus()
    called = {"ok": False}

    def handler(e: EntryAdded):
        called["ok"] = True
        assert e.entry_id == 1

    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded(entry_id=1, title="X"))
    assert called["ok"] is True