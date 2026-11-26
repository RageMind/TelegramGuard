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


@pytest.mark.parametrize("service", ["sshd", "xrdp-sesman"])
def test_supported_remote_account_services(monkeypatch, service):
    monkeypatch.setenv("PAM_TYPE", "account")
    monkeypatch.setenv("PAM_SERVICE", service)
    monkeypatch.setenv("PAM_USER", "desktop")
    monkeypatch.setenv("PAM_RHOST", "203.0.113.42")
    assert _pam_request()["service"] == service
    monkeypatch.setenv("PAM_SERVICE", "sudo")
    with pytest.raises(ValueError):
        _pam_request()


def test_legacy_xrdp_missing_host_requires_explicit_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAM_TYPE", "account")
    monkeypatch.setenv("PAM_SERVICE", "xrdp-sesman")
    monkeypatch.setenv("PAM_USER", "desktop")
    monkeypatch.delenv("PAM_RHOST", raising=False)
    assert _pam_request()["remote_ip"] == "unknown (XRDP)"
    monkeypatch.setenv("PAM_SERVICE", "sshd")
    with pytest.raises(ValueError, match="missing remote host"):
        _pam_request()
