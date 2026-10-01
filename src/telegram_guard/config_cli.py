from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from telegram_guard.security import ValidationError, validate_unit

DEFAULT_HELPER_ENV = Path("/etc/telegram-guard/helper.env")
DEFAULT_BOT_ENV = Path("/etc/telegram-guard/bot.env")
HELPER_UNIT = "telegram-guard-helper.service"

EXPORT_HELPER_KEYS = (
    "FIREWALL_MODE",
    "SSH_PORT",
    "NFT_FAMILY",
    "NFT_TABLE",
    "NFT_IPV4_SET",
    "NFT_IPV6_SET",
    "MANAGED_SERVICES",
    "SSH_JOURNAL_UNIT",
)

EXPORT_BOT_KEYS = (
    "TELEGRAM_POLL_TIMEOUT",
    "RATE_LIMIT_PER_MINUTE",
    "ALERT_INTERVAL_SECONDS",
    "SSH_FAILED_ALERT_THRESHOLD",
)


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _render_env_update(original: str, key: str, value: str) -> str:
    if "\n" in key or "\n" in value:
        raise ValueError("environment value must be one line")

    lines = original.splitlines()
    replaced = False
    output: list[str] = []
    for line in lines:
        if line.startswith(f"{key}="):
            if not replaced:
                output.append(f"{key}={value}")
                replaced = True
            continue
        output.append(line)

    if not replaced:
        if output and output[-1].strip():
            output.append("")
        output.append(f"{key}={value}")

    return "\n".join(output).rstrip() + "\n"


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        temp_path.replace(path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _resolve_systemctl() -> str:
    for candidate in ("/usr/bin/systemctl", "/bin/systemctl"):
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    discovered = shutil.which("systemctl")
    if discovered:
        return discovered
    raise RuntimeError("systemctl is unavailable")


def _normalized_units(values: Iterable[str]) -> tuple[str, ...]:
    units: list[str] = []
    for value in values:
        unit = validate_unit(value)
        if unit not in units:
            units.append(unit)
    if not units:
        raise ValidationError("at least one managed service is required")
    return tuple(units)


def _restart_helper() -> None:
    systemctl = _resolve_systemctl()
    result = subprocess.run(
        [systemctl, "restart", HELPER_UNIT],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "restart failed").strip()
        raise RuntimeError(message[:500])


def set_managed_services(
    helper_env: Path,
    units: Iterable[str],
    *,
    restart: bool = True,
) -> tuple[str, ...]:
    normalized = _normalized_units(units)
    original = helper_env.read_text(encoding="utf-8") if helper_env.is_file() else ""
    original_mode = (
        stat.S_IMODE(helper_env.stat().st_mode)
        if helper_env.exists()
        else 0o600
    )
    updated = _render_env_update(
        original,
        "MANAGED_SERVICES",
        ",".join(normalized),
    )
    _atomic_write(helper_env, updated, original_mode)

    if not restart:
        return normalized

    try:
        _restart_helper()
    except Exception:
        _atomic_write(helper_env, original, original_mode)
        with contextlib_suppress_restart():
            _restart_helper()
        raise

    return normalized


class contextlib_suppress_restart:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return True


def export_non_secret_config(
    helper_env: Path,
    bot_env: Path,
) -> dict[str, object]:
    helper = _read_env(helper_env)
    bot = _read_env(bot_env)
    return {
        "helper": {
            key: helper[key]
            for key in EXPORT_HELPER_KEYS
            if key in helper
        },
        "bot": {
            key: bot[key]
            for key in EXPORT_BOT_KEYS
            if key in bot
        },
    }


def validate_config(helper_env: Path, bot_env: Path) -> list[str]:
    errors: list[str] = []
    helper = _read_env(helper_env)
    bot = _read_env(bot_env)

    raw_units = helper.get("MANAGED_SERVICES", "")
    if raw_units:
        try:
            _normalized_units(raw_units.split(","))
        except ValidationError as exc:
            errors.append(f"MANAGED_SERVICES: {exc}")
    else:
        errors.append("MANAGED_SERVICES: missing")

    for key, minimum, maximum in (
        ("SSH_PORT", 1, 65535),
        ("ALERT_INTERVAL_SECONDS", 30, 3600),
        ("SSH_FAILED_ALERT_THRESHOLD", 1, 1000),
    ):
        source = helper if key == "SSH_PORT" else bot
        raw = source.get(key)
        if raw is None:
            continue
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{key}: must be an integer")
            continue
        if not minimum <= value <= maximum:
            errors.append(f"{key}: must be between {minimum} and {maximum}")

    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local TelegramGuard configuration utility."
    )
    parser.add_argument(
        "--helper-env",
        type=Path,
        default=DEFAULT_HELPER_ENV,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--bot-env",
        type=Path,
        default=DEFAULT_BOT_ENV,
        help=argparse.SUPPRESS,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    services = sub.add_parser(
        "services",
        help="show or replace the local managed-service allowlist",
    )
    services.add_argument("units", nargs="*")
    services.add_argument(
        "--no-restart",
        action="store_true",
        help="write configuration without restarting the helper",
    )

    sub.add_parser(
        "validate",
        help="validate non-secret local configuration",
    )
    sub.add_parser(
        "export",
        help="print a non-secret JSON configuration export",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()

    if args.command == "services":
        if not args.units:
            values = _read_env(args.helper_env)
            print(values.get("MANAGED_SERVICES", ""))
            return
        units = set_managed_services(
            args.helper_env,
            args.units,
            restart=not args.no_restart,
        )
        print("managed services updated:")
        for unit in units:
            print(f"- {unit}")
        return

    if args.command == "validate":
        errors = validate_config(args.helper_env, args.bot_env)
        if errors:
            print("configuration errors:")
            for error in errors:
                print(f"- {error}")
            raise SystemExit(1)
        print("configuration valid")
        return

    if args.command == "export":
        print(
            json.dumps(
                export_non_secret_config(args.helper_env, args.bot_env),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return

    raise SystemExit(2)


if __name__ == "__main__":
    main()
