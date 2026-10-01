from __future__ import annotations

import argparse
import json
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Final

HELPER_ENV: Final = Path("/etc/telegram-guard/helper.env")
BOT_ENV: Final = Path("/etc/telegram-guard/bot.env")
STATE_FILE: Final = Path("/var/lib/telegram-guard/firewall.json")
HELPER_SOCKET: Final = Path("/run/telegram-guard/helper.sock")


def _resolve_binary(name: str, candidates: tuple[str, ...]) -> str:
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and path.stat().st_mode & stat.S_IXUSR:
            return candidate
    discovered = shutil.which(name)
    if discovered:
        return discovered
    raise RuntimeError(f"required binary is unavailable: {name}")


SYSTEMCTL: Final = _resolve_binary(
    "systemctl", ("/usr/bin/systemctl", "/bin/systemctl")
)
NFT: Final = _resolve_binary("nft", ("/usr/sbin/nft", "/usr/bin/nft"))


def _parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _mode(path: Path) -> str:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except OSError:
        return "missing"


def _active(unit: str) -> bool:
    result = subprocess.run(
        [SYSTEMCTL, "is-active", "--quiet", unit],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.returncode == 0


def _nft_active(family: str, table: str) -> bool:
    result = subprocess.run(
        [NFT, "list", "table", family, table],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.returncode == 0


def _state_entries(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return -1
    entries = payload.get("entries", {})
    return len(entries) if isinstance(entries, dict) else -1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe local TelegramGuard diagnostics without printing secrets."
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    helper_env = _parse_env(HELPER_ENV)
    firewall_mode = helper_env.get("FIREWALL_MODE", "unknown")
    family = helper_env.get("NFT_FAMILY", "inet")
    table = helper_env.get("NFT_TABLE", "telegram_guard")
    ssh_port = helper_env.get("SSH_PORT", "unknown")

    bot_configured = False
    if BOT_ENV.is_file():
        bot_values = _parse_env(BOT_ENV)
        token = bot_values.get("TELEGRAM_BOT_TOKEN", "")
        admins = bot_values.get("TELEGRAM_ADMIN_IDS", "")
        bot_configured = bool(token and ":" in token and admins)

    result = {
        "bot_configured": bot_configured,
        "bot_env_mode": _mode(BOT_ENV),
        "helper_env_mode": _mode(HELPER_ENV),
        "helper_socket": HELPER_SOCKET.exists(),
        "bot_service": _active("telegram-guard.service"),
        "helper_service": _active("telegram-guard-helper.service"),
        "firewall_mode": firewall_mode,
        "firewall_active": (
            _nft_active(family, table) if firewall_mode == "nft" else False
        ),
        "ssh_port": ssh_port,
        "whitelist_entries": _state_entries(STATE_FILE),
    }

    healthy = (
        result["bot_configured"]
        and result["helper_socket"]
        and result["bot_service"]
        and result["helper_service"]
        and (
            result["firewall_active"]
            if firewall_mode == "nft"
            else firewall_mode == "observe"
        )
    )
    result["healthy"] = healthy

    if args.json:
        print(json.dumps(result, sort_keys=True))
        return

    print("TelegramGuard doctor")
    print("====================")
    for key, value in result.items():
        marker = "OK" if bool(value) else "--"
        if key in {"firewall_mode", "ssh_port", "bot_env_mode", "helper_env_mode"}:
            marker = "INFO"
        print(f"[{marker:4}] {key}: {value}")

    if not healthy:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
