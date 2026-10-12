"""Expiring per-user/per-IP SSH PAM approval grants.

These grants never bypass OpenSSH password/public-key checks or nftables.
Only the bot process, after an authenticated Telegram admin callback, may
create them. Stored in the existing persistent bot SQLite database.
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from telegram_guard.security import parse_ip

MAX_TRUST_SECONDS = 7 * 86400
SSH_TRUST_CHOICES: dict[int, str] = {
    36000: "10 часов",
    72000: "20 часов",
    86400: "1 день",
    172800: "2 дня",
    259200: "3 дня",
    604800: "7 дней",
}


class SshTrustStore:
    def __init__(self, state_db: str) -> None:
        # Use the existing persistent database, already owned by the bot user.
        self.path = Path(state_db)
        if not self.path.is_file():
            raise RuntimeError("TelegramGuard state DB must exist before trust store")
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ssh_trusted_access (
                    id TEXT PRIMARY KEY,
                    ssh_user TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    service TEXT NOT NULL,
                    granted_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    granted_by INTEGER NOT NULL,
                    UNIQUE(ssh_user, remote_ip, service)
                );
                CREATE INDEX IF NOT EXISTS idx_ssh_trust_expires
                    ON ssh_trusted_access(expires_at);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _identity(ssh_user: str, remote_ip: str, service: str) -> tuple[str, str, str]:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", ssh_user):
            raise ValueError("invalid SSH user")
        if service != "sshd":
            raise ValueError("trusted approval is for sshd only")
        return ssh_user, str(parse_ip(remote_ip)), service

    def grant(
        self, ssh_user: str, remote_ip: str, service: str,
        ttl_seconds: int, admin_id: int,
    ) -> dict[str, int | str]:
        ssh_user, remote_ip, service = self._identity(ssh_user, remote_ip, service)
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= MAX_TRUST_SECONDS:
            raise ValueError("SSH trust must be between 1 minute and 7 days")
        if type(admin_id) is not int or admin_id <= 0:
            raise ValueError("invalid admin")
        now = int(time.time())
        until = now + ttl_seconds
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM ssh_trusted_access WHERE expires_at <= ?", (now,))
            conn.execute(
                """
                INSERT INTO ssh_trusted_access
                (id, ssh_user, remote_ip, service, granted_at, expires_at, granted_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ssh_user, remote_ip, service) DO UPDATE SET
                    granted_at=excluded.granted_at,
                    expires_at=excluded.expires_at,
                    granted_by=excluded.granted_by
                """,
                (secrets.token_urlsafe(12), ssh_user, remote_ip, service, now, until, admin_id),
            )
            conn.commit()
        return {
            "ssh_user": ssh_user, "remote_ip": remote_ip, "service": service,
            "expires_at": until, "ttl_seconds": ttl_seconds,
        }

    def remaining(self, ssh_user: str, remote_ip: str, service: str) -> int:
        try:
            ssh_user, remote_ip, service = self._identity(ssh_user, remote_ip, service)
        except ValueError:
            return 0
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT expires_at FROM ssh_trusted_access
                WHERE ssh_user=? AND remote_ip=? AND service=? AND expires_at > ?
                """,
                (ssh_user, remote_ip, service, now),
            ).fetchone()
        return max(0, int(row["expires_at"]) - now) if row is not None else 0

    def listing(self) -> list[dict[str, Any]]:
        now = int(time.time())
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, ssh_user, remote_ip, service, granted_at,
                       expires_at, granted_by
                FROM ssh_trusted_access WHERE expires_at > ?
                ORDER BY expires_at ASC LIMIT 50
                """,
                (now,),
            ).fetchall()
        return [
            {
                "id": str(row["id"]),
                "ssh_user": str(row["ssh_user"]),
                "remote_ip": str(row["remote_ip"]),
                "service": str(row["service"]),
                "granted_at": int(row["granted_at"]),
                "expires_at": int(row["expires_at"]),
                "granted_by": int(row["granted_by"]),
                "remaining_seconds": max(0, int(row["expires_at"]) - now),
            }
            for row in rows
        ]

    def revoke(self, identifier: str) -> dict[str, str] | None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,32}", identifier):
            raise ValueError("invalid trust id")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT ssh_user, remote_ip FROM ssh_trusted_access WHERE id=?",
                (identifier,),
            ).fetchone()
            if row is None:
                conn.rollback()
                return None
            conn.execute("DELETE FROM ssh_trusted_access WHERE id=?", (identifier,))
            conn.commit()
        return {"ssh_user": str(row["ssh_user"]), "remote_ip": str(row["remote_ip"])}
