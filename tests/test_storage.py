"""Unit tests for SQLite event storage."""

from pathlib import Path
from src.storage import EventStore


def test_event_store_lifecycle(tmp_path: Path):
    db_file = tmp_path / "test_events.db"
    store = EventStore(db_path=db_file)

    # 1. Save event
    eid = store.save_event(
        provider="stripe",
        headers={"Content-Type": "application/json", "Stripe-Signature": "t=123,v1=abc"},
        payload='{"type":"invoice.paid","amount":5000}',
        verified=True,
    )
    assert eid.startswith("evt_")

    # 2. Retrieve event
    fetched = store.get_event(eid)
    assert fetched is not None
    assert fetched["id"] == eid
    assert fetched["provider"] == "stripe"
    assert fetched["event_type"] == "invoice.paid"
    assert fetched["verified"] is True
    assert fetched["headers"]["Stripe-Signature"] == "t=123,v1=abc"

    # 3. List events
    events = store.list_events()
    assert len(events) == 1
    assert events[0]["id"] == eid

    # 4. Clear events
    store.clear()
    assert len(store.list_events()) == 0
