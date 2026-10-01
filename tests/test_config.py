from __future__ import annotations

import pytest

from telegram_guard.config import BotConfig, ConfigError, HelperConfig


def test_bot_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "TELEGRAM_BOT_TOKEN",
        "not-a-real-token:abcdefghijklmnopqrstuvwxyz",
    )
    monkeypatch.setenv("TELEGRAM_ADMIN_IDS", "111111111,222222222")
    config = BotConfig.from_env()
    assert config.admin_ids == (111111111, 222222222)
    assert config.helper_socket.endswith("helper.sock")
    assert config.alert_interval_seconds == 60
    assert config.ssh_failed_alert_threshold == 10


def test_bot_config_rejects_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "REPLACE_WITH_BOT_TOKEN")
    monkeypatch.setenv("TELEGRAM_ADMIN_IDS", "111111111")
    with pytest.raises(ConfigError):
        BotConfig.from_env()


def test_helper_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "FIREWALL_MODE",
        "MANAGED_SERVICES",
        "HELPER_ALLOWED_USER",
        "NFT_TABLE",
    ):
        monkeypatch.delenv(name, raising=False)
    config = HelperConfig.from_env()
    assert config.firewall_mode == "observe"
    assert config.managed_services == ("ssh.service",)
    assert config.allowed_user == "telegram-guard"


def test_invalid_managed_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANAGED_SERVICES", "nginx.service,../../bad")
    with pytest.raises(ConfigError):
        HelperConfig.from_env()


def test_bot_config_rejects_invalid_alert_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TELEGRAM_BOT_TOKEN",
        "not-a-real-token:abcdefghijklmnopqrstuvwxyz",
    )
    monkeypatch.setenv("TELEGRAM_ADMIN_IDS", "111111111")
    monkeypatch.setenv("ALERT_INTERVAL_SECONDS", "5")
    with pytest.raises(ConfigError):
        BotConfig.from_env()
