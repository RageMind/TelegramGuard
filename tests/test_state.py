from __future__ import annotations

from pathlib import Path

from telegram_guard.state import StateStore


def test_pending_action_is_single_use(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.sqlite3"))
    token = store.create_pending(
        42,
        "service.restart",
        {"unit": "nginx.service"},
        ttl_seconds=90,
    )

    first = store.consume_pending(token, 42)
    assert first == ("service.restart", {"unit": "nginx.service"})
    assert store.consume_pending(token, 42) is None


def test_pending_action_is_bound_to_admin(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.sqlite3"))
    token = store.create_pending(42, "firewall.revoke", {"ip": "203.0.113.42"})
    assert store.consume_pending(token, 99) is None
    assert store.consume_pending(token, 42) is not None


def test_audit_round_trip(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.sqlite3"))
    store.audit(42, "host.status", "ok", {"source": "test"})
    rows = store.recent_audit(10)
    assert rows[0]["actor_id"] == 42
    assert rows[0]["action"] == "host.status"
    assert rows[0]["details"] == {"source": "test"}


def test_audit_pagination_and_count(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.sqlite3"))
    for index in range(5):
        store.audit(42, f"action.{index}", "ok")

    assert store.audit_count() == 5
    first = store.audit_page(limit=2, offset=0)
    second = store.audit_page(limit=2, offset=2)

    assert [row["action"] for row in first] == ["action.4", "action.3"]
    assert [row["action"] for row in second] == ["action.2", "action.1"]
