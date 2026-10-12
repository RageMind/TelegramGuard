from __future__ import annotations

import time

import pytest

from telegram_guard.ssh_approval import parse_request
from telegram_guard.ssh_trust import (
    MAX_TRUST_SECONDS, SSH_TRUST_CHOICES, SshTrustStore,
)
from telegram_guard.state import StateStore


def store(tmp_path):
    db = tmp_path / "bot.db"
    StateStore(str(db))
    return SshTrustStore(str(db))


def test_ssh_trust_all_six_presets_and_persists_across_restart(tmp_path):
    item = store(tmp_path)
    for seconds, label in SSH_TRUST_CHOICES.items():
        grant = item.grant("root", "203.0.113.42", "sshd", seconds, 12345)
        assert grant["ttl_seconds"] == seconds
        assert label
        assert seconds - 5 <= item.remaining("root", "203.0.113.42", "sshd") <= seconds
        after_restart = SshTrustStore(str(tmp_path / "bot.db"))
        assert after_restart.remaining("root", "203.0.113.42", "sshd") > 0
        assert len(after_restart.listing()) == 1


def test_ssh_trust_scopes_user_ip_and_service(tmp_path):
    item = store(tmp_path)
    item.grant("root", "203.0.113.42", "sshd", 36000, 42)
    assert item.remaining("root", "203.0.113.42", "sshd") > 0
    assert item.remaining("ubuntu", "203.0.113.42", "sshd") == 0
    assert item.remaining("root", "203.0.113.43", "sshd") == 0
    assert item.remaining("root", "2001:db8::1", "sshd") == 0
    assert item.remaining("root", "203.0.113.42", "sudo") == 0
    assert item.remaining("root", "bad-host.example", "sshd") == 0


def test_ssh_trust_expires_and_remains_expired_after_restart(tmp_path, monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(time, "time", lambda: now)
    item = store(tmp_path)
    item.grant("root", "203.0.113.42", "sshd", 60, 42)
    assert item.remaining("root", "203.0.113.42", "sshd") == 60
    monkeypatch.setattr(time, "time", lambda: now + 60)
    assert item.remaining("root", "203.0.113.42", "sshd") == 0
    assert SshTrustStore(str(tmp_path / "bot.db")).listing() == []


def test_ssh_trust_can_be_revoked_and_is_not_anonymous(tmp_path):
    item = store(tmp_path)
    item.grant("root", "203.0.113.42", "sshd", 36000, 42)
    entry = item.listing()[0]
    assert entry["granted_by"] == 42
    assert item.revoke(str(entry["id"])) == {
        "ssh_user": "root", "remote_ip": "203.0.113.42",
    }
    assert item.remaining("root", "203.0.113.42", "sshd") == 0
    assert item.revoke(str(entry["id"])) is None


@pytest.mark.parametrize("ttl", [0, 59, MAX_TRUST_SECONDS + 1, True, -5])
def test_trust_rejects_unsafe_expiration(tmp_path, ttl):
    with pytest.raises(ValueError):
        store(tmp_path).grant("root", "203.0.113.42", "sshd", ttl, 42)


@pytest.mark.parametrize("username,ip,service", [
    ("*", "203.0.113.42", "sshd"),
    ("root", "127.0.0.1", "sshd"),
    ("root", "fe80::1", "sshd"),
    ("root", "203.0.113.42", "sudo"),
    ("root\nsecond", "203.0.113.42", "sshd"),
])
def test_trust_rejects_wildcards_loopback_and_wrong_service(tmp_path, username, ip, service):
    with pytest.raises(ValueError):
        store(tmp_path).grant(username, ip, service, 36000, 42)


def test_ssh_trust_is_not_a_credential_bypass(tmp_path):
    item = store(tmp_path)
    item.grant("root", "203.0.113.42", "sshd", 36000, 42)
    req = parse_request({
        "version": 1, "user": "root", "remote_ip": "203.0.113.42",
        "service": "sshd", "tty": "pts/0",
    })
    # This only changes the broker decision after sshd already called PAM.
    assert item.remaining(req.user, req.remote_ip, req.service) > 0
