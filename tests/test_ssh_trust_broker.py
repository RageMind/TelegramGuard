from __future__ import annotations

import asyncio
import json

import pytest

from telegram_guard.ssh_approval import SshApprovalBroker
from telegram_guard.ssh_trust import SshTrustStore
from telegram_guard.state import StateStore


@pytest.mark.asyncio
async def test_trusted_pam_request_automatically_approves_without_notification(
    tmp_path, monkeypatch,
):
    state = tmp_path / "state.db"
    StateStore(str(state))
    trusted = SshTrustStore(str(state))
    trusted.grant("root", "203.0.113.42", "sshd", 36000, 42)
    notified = []
    results = []

    async def notify(token, request):
        notified.append(token)

    async def result(token, request, decision):
        results.append(decision)

    broker = SshApprovalBroker(
        str(tmp_path / "approval.sock"), 2, notify, result,
        is_trusted=lambda req: trusted.remaining(
            req.user, req.remote_ip, req.service,
        ) > 0,
    )
    monkeypatch.setattr(broker, "_peer_is_root", lambda writer: True)
    await broker.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(broker.socket_path))
        writer.write((json.dumps({
            "version": 1, "user": "root", "remote_ip": "203.0.113.42",
            "service": "sshd", "tty": "ssh",
        }) + "\n").encode())
        await writer.drain()
        received = json.loads((await reader.readline()).decode())
        await writer.wait_closed()
        assert received == {"ok": True, "decision": "approve"}
        assert notified == []
        assert broker.pending == {}
        assert results == ["trusted"]
    finally:
        await broker.close()


@pytest.mark.asyncio
async def test_trust_does_not_bypass_other_ssh_user(tmp_path, monkeypatch):
    state = tmp_path / "state.db"
    StateStore(str(state))
    trusted = SshTrustStore(str(state))
    trusted.grant("root", "203.0.113.42", "sshd", 36000, 42)
    notified = []

    async def notify(token, request):
        notified.append(token)
        broker.decide(token, "deny")

    async def result(token, request, decision):
        return None

    broker = SshApprovalBroker(
        str(tmp_path / "approval.sock"), 2, notify, result,
        is_trusted=lambda req: trusted.remaining(
            req.user, req.remote_ip, req.service,
        ) > 0,
    )
    monkeypatch.setattr(broker, "_peer_is_root", lambda writer: True)
    await broker.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(broker.socket_path))
        writer.write((json.dumps({
            "version": 1, "user": "ubuntu", "remote_ip": "203.0.113.42",
            "service": "sshd", "tty": "ssh",
        }) + "\n").encode())
        await writer.drain()
        received = json.loads((await reader.readline()).decode())
        await writer.wait_closed()
        assert received == {"ok": False, "decision": "deny"}
        assert len(notified) == 1
    finally:
        await broker.close()
