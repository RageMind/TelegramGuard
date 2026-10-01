from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    actor_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pending_actions (
                    token TEXT PRIMARY KEY,
                    admin_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_audit_created_at
                ON audit(created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_pending_expiry
                ON pending_actions(expires_at);
                """
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def audit(
        self,
        actor_id: int,
        action: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        payload = json.dumps(details or {}, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit(created_at, actor_id, action, outcome, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(time.time()), actor_id, action, outcome, payload),
            )

    def recent_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 50))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT created_at, actor_id, action, outcome, details_json
                FROM audit
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "created_at": int(row["created_at"]),
                    "actor_id": int(row["actor_id"]),
                    "action": str(row["action"]),
                    "outcome": str(row["outcome"]),
                    "details": json.loads(str(row["details_json"])),
                }
            )
        return result

    def create_pending(
        self,
        admin_id: int,
        action: str,
        args: dict[str, Any],
        ttl_seconds: int = 90,
    ) -> str:
        token = secrets.token_urlsafe(18)
        now = int(time.time())
        expires_at = now + max(15, min(ttl_seconds, 300))
        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM pending_actions
                WHERE expires_at < ? OR consumed_at IS NOT NULL
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO pending_actions(
                    token, admin_id, action, args_json, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    token,
                    admin_id,
                    action,
                    json.dumps(args, ensure_ascii=False, sort_keys=True),
                    now,
                    expires_at,
                ),
            )
        return token

    def consume_pending(
        self, token: str, admin_id: int
    ) -> tuple[str, dict[str, Any]] | None:
        now = int(time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT action, args_json, expires_at, consumed_at
                FROM pending_actions
                WHERE token = ? AND admin_id = ?
                """,
                (token, admin_id),
            ).fetchone()
            if row is None:
                conn.rollback()
                return None
            if row["consumed_at"] is not None or int(row["expires_at"]) < now:
                conn.rollback()
                return None

            conn.execute(
                "UPDATE pending_actions SET consumed_at = ? WHERE token = ?",
                (now, token),
            )
            conn.commit()
            return str(row["action"]), json.loads(str(row["args_json"]))
