from __future__ import annotations

import asyncio

import pytest

from telegram_guard.ssh_approval import SshApprovalBroker, parse_request


def test_parse_request() -> None:
    request = parse_request(
        {
            "version": 1,
            "user": "root",
            "remote_ip": "203.0.113.42",
            "service": "sshd",
            "tty": "ssh",
        }
    )
    assert request.user == "root"
    assert request.remote_ip == "203.0.113.42"
    assert request.service == "sshd"


def test_parse_request_rejects_control_characters() -> None:
    with pytest.raises(ValueError):
        parse_request(
            {
                "version": 1,
                "user": "root\nother",
                "remote_ip": "203.0.113.42",
                "service": "sshd",
                "tty": "ssh",
            }
        )


@pytest.mark.asyncio
async def test_broker_decision_resolves_future(tmp_path) -> None:
    async def on_request(token, request) -> None:
        return None

    async def on_result(token, request, decision) -> None:
        return None

    broker = SshApprovalBroker(
        str(tmp_path / "approval.sock"),
        30,
        on_request,
        on_result,
    )
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    broker.pending["token"] = type("Pending", (), {
        "future": future,
        "request": parse_request(
            {
                "version": 1,
                "user": "root",
                "remote_ip": "203.0.113.42",
                "service": "sshd",
                "tty": "ssh",
            }
        ),
    })()

    request = broker.decide("token", "approve")
    assert request is not None
    assert await future == "approve"
