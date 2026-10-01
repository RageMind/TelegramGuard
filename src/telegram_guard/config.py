from __future__ import annotations

import os
import re
from dataclasses import dataclass

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


class ConfigError(RuntimeError):
    """Raised when runtime configuration is unsafe or incomplete."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or value.upper().startswith("REPLACE_"):
        raise ConfigError(f"{name} is required")
    return value


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _csv_ints(name: str) -> tuple[int, ...]:
    raw = _required(name)
    values: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item.isdigit():
            raise ConfigError(f"{name} must contain numeric Telegram user IDs")
        value = int(item)
        if value <= 0:
            raise ConfigError(f"{name} contains an invalid ID")
        values.append(value)
    if not values:
        raise ConfigError(f"{name} must not be empty")
    return tuple(dict.fromkeys(values))


def _csv_identifiers(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.environ.get(name, default).strip()
    if not raw:
        return ()
    values: list[str] = []
    for item in raw.split(","):
        item = item.strip()
        if not _IDENTIFIER_RE.fullmatch(item):
            raise ConfigError(f"{name} contains an invalid identifier")
        values.append(item)
    return tuple(dict.fromkeys(values))


def _identifier(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip()
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ConfigError(f"{name} contains an invalid identifier")
    return value


@dataclass(frozen=True, slots=True)
class BotConfig:
    token: str
    admin_ids: tuple[int, ...]
    poll_timeout: int
    rate_limit_per_minute: int
    alert_interval_seconds: int
    ssh_failed_alert_threshold: int
    state_db: str
    helper_socket: str

    @classmethod
    def from_env(cls) -> BotConfig:
        token = _required("TELEGRAM_BOT_TOKEN")
        if ":" not in token or len(token) < 20:
            raise ConfigError("TELEGRAM_BOT_TOKEN does not look valid")
        state_db = os.environ.get(
            "STATE_DB", "/var/lib/telegram-guard/state.sqlite3"
        ).strip()
        helper_socket = os.environ.get(
            "HELPER_SOCKET", "/run/telegram-guard/helper.sock"
        ).strip()
        if not state_db.startswith("/") or not helper_socket.startswith("/"):
            raise ConfigError("STATE_DB and HELPER_SOCKET must be absolute paths")
        return cls(
            token=token,
            admin_ids=_csv_ints("TELEGRAM_ADMIN_IDS"),
            poll_timeout=_int("TELEGRAM_POLL_TIMEOUT", 25, 5, 50),
            rate_limit_per_minute=_int("RATE_LIMIT_PER_MINUTE", 20, 5, 120),
            alert_interval_seconds=_int(
                "ALERT_INTERVAL_SECONDS", 60, 30, 3600
            ),
            ssh_failed_alert_threshold=_int(
                "SSH_FAILED_ALERT_THRESHOLD", 10, 1, 1000
            ),
            state_db=state_db,
            helper_socket=helper_socket,
        )


@dataclass(frozen=True, slots=True)
class HelperConfig:
    socket_path: str
    socket_group: str
    allowed_user: str
    firewall_mode: str
    firewall_state: str
    ssh_port: int
    nft_family: str
    nft_table: str
    nft_ipv4_set: str
    nft_ipv6_set: str
    managed_services: tuple[str, ...]
    ssh_journal_unit: str

    @classmethod
    def from_env(cls) -> HelperConfig:
        socket_path = os.environ.get(
            "HELPER_SOCKET", "/run/telegram-guard/helper.sock"
        ).strip()
        if not socket_path.startswith("/"):
            raise ConfigError("HELPER_SOCKET must be an absolute path")

        firewall_state = os.environ.get(
            "FIREWALL_STATE", "/var/lib/telegram-guard-helper/firewall.json"
        ).strip()
        if not firewall_state.startswith("/"):
            raise ConfigError("FIREWALL_STATE must be an absolute path")

        firewall_mode = os.environ.get("FIREWALL_MODE", "observe").strip().lower()
        if firewall_mode not in {"observe", "nft"}:
            raise ConfigError("FIREWALL_MODE must be observe or nft")

        allowed_user = os.environ.get(
            "HELPER_ALLOWED_USER", "telegram-guard"
        ).strip()
        if not re.fullmatch(r"^[a-z_][a-z0-9_-]{0,31}$", allowed_user):
            raise ConfigError("HELPER_ALLOWED_USER is invalid")

        return cls(
            socket_path=socket_path,
            socket_group=os.environ.get(
                "HELPER_SOCKET_GROUP", "telegram-guard"
            ).strip(),
            allowed_user=allowed_user,
            firewall_mode=firewall_mode,
            firewall_state=firewall_state,
            ssh_port=_int("SSH_PORT", 22, 1, 65535),
            nft_family=_identifier("NFT_FAMILY", "inet"),
            nft_table=_identifier("NFT_TABLE", "telegram_guard"),
            nft_ipv4_set=_identifier("NFT_IPV4_SET", "trusted_ipv4"),
            nft_ipv6_set=_identifier("NFT_IPV6_SET", "trusted_ipv6"),
            managed_services=_csv_identifiers(
                "MANAGED_SERVICES", "ssh.service"
            ),
            ssh_journal_unit=_identifier("SSH_JOURNAL_UNIT", "ssh.service"),
        )
