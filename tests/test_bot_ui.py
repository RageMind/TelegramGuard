from __future__ import annotations

from telegram_guard.bot import _ACTION_LABELS, _approval_missing, _security_keyboard, _service_token


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


def test_security_keyboard_exposes_ssh_2fa_toggle() -> None:
    disabled = _security_keyboard(False)["inline_keyboard"]
    enabled = _security_keyboard(True)["inline_keyboard"]

    assert disabled[0][0] == {
        "text": "Включить Telegram 2FA",
        "callback_data": "ssh2fa:enable",
        "style": "success",
    }
    assert enabled[0][0] == {
        "text": "Отключить Telegram 2FA",
        "callback_data": "ssh2fa:disable",
        "style": "danger",
    }


def test_approval_missing_lists_failed_preflight_checks() -> None:
    missing = _approval_missing(
        {
            "pam_file_ok": True,
            "pam_writable": False,
            "backup_dir_ready": True,
            "broker_ready": False,
            "broker_active": True,
            "use_pam": False,
            "pam_exec": True,
        }
    )
    assert missing == ["запись PAM", "approval broker", "UsePAM"]
