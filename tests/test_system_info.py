from __future__ import annotations

from types import SimpleNamespace
import pytest

from telegram_guard.system_info import SystemController


def test_ssh_summary_classifies_authentication_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = object.__new__(SystemController)
    controller.config = SimpleNamespace(ssh_journal_unit="ssh.service")
    lines = [
        "sshd: Accepted publickey for user from 203.0.113.42",
        "sshd: Failed password for user from 203.0.113.43",
        "sshd: Invalid user guest from 203.0.113.44",
        "sshd: Connection closed by authenticating user user",
    ]
    monkeypatch.setattr(
        controller,
        "_journal_lines",
        lambda *args, **kwargs: lines,
    )

    summary = controller.ssh_summary(60)

    assert summary["events"] == 4
    assert summary["accepted"] == 1
    assert summary["failed"] == 1
    assert summary["invalid_user"] == 1
    assert summary["disconnected"] == 1
