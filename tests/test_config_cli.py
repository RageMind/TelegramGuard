from __future__ import annotations

from pathlib import Path

import pytest

from telegram_guard.config_cli import (
    _read_env,
    _render_env_update,
    export_non_secret_config,
    set_managed_services,
    validate_config,
)
from telegram_guard.security import ValidationError


def test_render_env_update_replaces_single_key() -> None:
    original = "A=1\nMANAGED_SERVICES=ssh.service\nB=2\n"
    updated = _render_env_update(
        original,
        "MANAGED_SERVICES",
        "ssh.service,nginx.service",
    )

    assert updated.count("MANAGED_SERVICES=") == 1
    assert "MANAGED_SERVICES=ssh.service,nginx.service" in updated


def test_set_managed_services_without_restart(tmp_path: Path) -> None:
    helper_env = tmp_path / "helper.env"
    helper_env.write_text(
        "FIREWALL_MODE=nft\nMANAGED_SERVICES=ssh.service\n",
        encoding="utf-8",
    )

    result = set_managed_services(
        helper_env,
        ["ssh.service", "nginx.service", "ssh.service"],
        restart=False,
    )

    assert result == ("ssh.service", "nginx.service")
    assert _read_env(helper_env)["MANAGED_SERVICES"] == (
        "ssh.service,nginx.service"
    )


def test_set_managed_services_rejects_unsafe_unit(tmp_path: Path) -> None:
    helper_env = tmp_path / "helper.env"
    helper_env.write_text("MANAGED_SERVICES=ssh.service\n", encoding="utf-8")

    with pytest.raises(ValidationError):
        set_managed_services(
            helper_env,
            ["../../etc/passwd"],
            restart=False,
        )


def test_export_excludes_identity_and_token(tmp_path: Path) -> None:
    helper_env = tmp_path / "helper.env"
    bot_env = tmp_path / "bot.env"
    helper_env.write_text(
        "SSH_PORT=22\nMANAGED_SERVICES=ssh.service\n",
        encoding="utf-8",
    )
    bot_env.write_text(
        "TELEGRAM_BOT_TOKEN=secret-token\n"
        "TELEGRAM_ADMIN_IDS=123456\n"
        "ALERT_INTERVAL_SECONDS=60\n",
        encoding="utf-8",
    )

    payload = export_non_secret_config(helper_env, bot_env)
    encoded = str(payload)

    assert payload["helper"]["SSH_PORT"] == "22"
    assert payload["bot"]["ALERT_INTERVAL_SECONDS"] == "60"
    assert "secret-token" not in encoded
    assert "123456" not in encoded


def test_validate_config_reports_invalid_values(tmp_path: Path) -> None:
    helper_env = tmp_path / "helper.env"
    bot_env = tmp_path / "bot.env"
    helper_env.write_text(
        "SSH_PORT=70000\nMANAGED_SERVICES=ssh.service\n",
        encoding="utf-8",
    )
    bot_env.write_text(
        "ALERT_INTERVAL_SECONDS=1\n"
        "SSH_FAILED_ALERT_THRESHOLD=0\n",
        encoding="utf-8",
    )

    errors = validate_config(helper_env, bot_env)

    assert any(error.startswith("SSH_PORT:") for error in errors)
    assert any(error.startswith("ALERT_INTERVAL_SECONDS:") for error in errors)
    assert any(
        error.startswith("SSH_FAILED_ALERT_THRESHOLD:")
        for error in errors
    )
