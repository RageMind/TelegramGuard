from __future__ import annotations

from telegram_guard.bot import _ACTION_LABELS, _service_token


def test_service_callback_token_is_short_and_stable() -> None:
    unit = "example-very-long-managed-service-name.service"
    first = _service_token(unit)
    second = _service_token(unit)

    assert first == second
    assert len(first) == 12
    assert ":" not in first


def test_audit_labels_cover_sensitive_mutations() -> None:
    assert _ACTION_LABELS["firewall.allow"] == "Доступ выдан"
    assert _ACTION_LABELS["firewall.make_permanent"] == "Доступ сделан постоянным"
    assert _ACTION_LABELS["firewall.revoke"] == "Доступ отозван"
    assert _ACTION_LABELS["service.restart"] == "Сервис перезапущен"


def test_audit_labels_cover_ssh_approval_toggle() -> None:
    assert _ACTION_LABELS["ssh.approval.enable"] == "SSH 2FA включён"
    assert _ACTION_LABELS["ssh.approval.disable"] == "SSH 2FA отключён"
