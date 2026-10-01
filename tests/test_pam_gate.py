from __future__ import annotations

import pytest

from telegram_guard.pam_gate import _pam_request


def test_pam_request_uses_account_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAM_TYPE", "account")
    monkeypatch.setenv("PAM_SERVICE", "sshd")
    monkeypatch.setenv("PAM_USER", "root")
    monkeypatch.setenv("PAM_RHOST", "203.0.113.42")
    monkeypatch.setenv("PAM_TTY", "ssh")

    payload = _pam_request()
    assert payload["user"] == "root"
    assert payload["remote_ip"] == "203.0.113.42"


def test_pam_request_rejects_wrong_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAM_TYPE", "auth")
    monkeypatch.setenv("PAM_SERVICE", "sshd")
    monkeypatch.setenv("PAM_USER", "root")
    monkeypatch.setenv("PAM_RHOST", "203.0.113.42")

    with pytest.raises(ValueError):
        _pam_request()
