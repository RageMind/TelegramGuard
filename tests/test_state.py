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
