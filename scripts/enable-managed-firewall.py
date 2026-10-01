#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path


def parse_ssh_connection(value: str) -> tuple[str, int]:
    parts = value.split()
    if len(parts) != 4:
        raise ValueError("SSH_CONNECTION must contain four fields")
    client_ip = str(ipaddress.ip_address(parts[0]))
    ssh_port = int(parts[3])
    if not 1 <= ssh_port <= 65535:
        raise ValueError("SSH port is outside the valid range")
    address = ipaddress.ip_address(client_ip)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("SSH client address is not safe for bootstrap")
    return client_ip, ssh_port


def update_env(path: Path, values: dict[str, str]) -> None:
    existing: list[str] = []
    if path.exists():
        existing = path.read_text(encoding="utf-8").splitlines()

    replaced: set[str] = set()
    output: list[str] = []
    for line in existing:
        if "=" not in line or line.lstrip().startswith("#"):
            output.append(line)
            continue
        key = line.split("=", 1)[0]
        if key in values:
            output.append(f"{key}={values[key]}")
            replaced.add(key)
        else:
            output.append(line)

    for key, value in values.items():
        if key not in replaced:
            output.append(f"{key}={value}")

    path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def seed_state(path: Path, client_ip: str) -> None:
    payload: dict[str, object] = {"version": 1, "entries": {}}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = None
        if isinstance(loaded, dict) and isinstance(loaded.get("entries"), dict):
            payload = loaded

    entries = payload.setdefault("entries", {})
    if not isinstance(entries, dict):
        raise ValueError("firewall state has invalid entries")

    entries[client_ip] = {
        "expires_at": None,
        "source": "bootstrap",
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enable TelegramGuard managed SSH whitelist safely."
    )
    parser.add_argument(
        "--helper-env",
        default="/etc/telegram-guard/helper.env",
    )
    parser.add_argument(
        "--state",
        default="/var/lib/telegram-guard/firewall.json",
    )
    parser.add_argument(
        "--ssh-connection",
        default=os.environ.get("SSH_CONNECTION", ""),
    )
    args = parser.parse_args()

    client_ip, ssh_port = parse_ssh_connection(args.ssh_connection)
    helper_env = Path(args.helper_env)
    state = Path(args.state)

    update_env(
        helper_env,
        {
            "FIREWALL_MODE": "nft",
            "FIREWALL_STATE": str(state),
            "SSH_PORT": str(ssh_port),
            "NFT_FAMILY": "inet",
            "NFT_TABLE": "telegram_guard",
            "NFT_IPV4_SET": "trusted_ipv4",
            "NFT_IPV6_SET": "trusted_ipv6",
        },
    )
    seed_state(state, client_ip)

    print("Managed SSH whitelist prepared.")
    print(f"SSH port: {ssh_port}")
    print("Current SSH client was pinned as a permanent bootstrap address.")
    print("Restart telegram-guard-helper to apply the policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
