from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from telegram_guard.config import HelperConfig
from telegram_guard.security import bounded, parse_ip


def _resolve_nft() -> str:
    for candidate in ("/usr/sbin/nft", "/usr/bin/nft"):
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    discovered = shutil.which("nft")
    if discovered:
        return discovered
    raise RuntimeError("nft is unavailable")


class NftWhitelist:
    def __init__(self, config: HelperConfig) -> None:
        self.config = config
        self.nft = _resolve_nft()
        self.state_path = Path(config.firewall_state)

    def _run(
        self, argv: list[str], *, check: bool = True, timeout: float = 6.0
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [self.nft, *argv],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                bounded(result.stderr or result.stdout or "nft command failed", 360)
            )
        return result

    def _run_script(self, script: str) -> None:
        result = subprocess.run(
            [self.nft, "-f", "-"],
            input=script,
            check=False,
            capture_output=True,
            text=True,
            timeout=8.0,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        if result.returncode != 0:
            raise RuntimeError(
                bounded(result.stderr or result.stdout or "nft ruleset failed", 500)
            )

    def _set_for(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> str:
        return (
            self.config.nft_ipv4_set
            if address.version == 4
            else self.config.nft_ipv6_set
        )

    def _assert_write_mode(self) -> None:
        if self.config.firewall_mode != "nft":
            raise PermissionError("firewall write mode is disabled")

    def _load_entries(self) -> dict[str, dict[str, Any]]:
        if not self.state_path.exists():
            return {}

        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("firewall state is unreadable") from exc

        raw_entries = payload.get("entries", {})
        if not isinstance(raw_entries, dict):
            raise RuntimeError("firewall state has invalid entries")

        now = int(time.time())
        entries: dict[str, dict[str, Any]] = {}
        for raw_ip, raw_meta in raw_entries.items():
            if not isinstance(raw_ip, str) or not isinstance(raw_meta, dict):
                continue
            try:
                address = parse_ip(raw_ip)
            except ValueError:
                continue

            expires_at_raw = raw_meta.get("expires_at")
            expires_at: int | None
            if expires_at_raw is None:
                expires_at = None
            else:
                try:
                    expires_at = int(expires_at_raw)
                except (TypeError, ValueError):
                    continue
                if expires_at <= now:
                    continue

            entries[str(address)] = {
                "expires_at": expires_at,
                "source": str(raw_meta.get("source", "telegram"))[:32],
            }
        return entries

    def _save_entries(self, entries: dict[str, dict[str, Any]]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        payload = {"version": 1, "entries": entries}
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(tmp, 0o600)
        tmp.replace(self.state_path)
        os.chmod(self.state_path, 0o600)

    def _elements(
        self,
        entries: dict[str, dict[str, Any]],
        version: int,
    ) -> list[str]:
        now = int(time.time())
        result: list[str] = []
        for ip_value, meta in sorted(entries.items()):
            address = ipaddress.ip_address(ip_value)
            if address.version != version:
                continue
            expires_at = meta.get("expires_at")
            if expires_at is None:
                result.append(str(address))
                continue
            remaining = max(60, int(expires_at) - now)
            result.append(f"{address} timeout {remaining}s")
        return result

    @staticmethod
    def _set_block(name: str, address_type: str, elements: list[str]) -> str:
        lines = [
            f"    set {name} {{",
            f"        type {address_type};",
            "        flags timeout;",
        ]
        if elements:
            lines.append(f"        elements = {{ {', '.join(elements)} }}")
        lines.append("    }")
        return "\n".join(lines)

    def _ruleset(self, entries: dict[str, dict[str, Any]]) -> str:
        if self.config.nft_family != "inet":
            raise RuntimeError("managed firewall requires NFT_FAMILY=inet")

        ipv4 = self._set_block(
            self.config.nft_ipv4_set,
            "ipv4_addr",
            self._elements(entries, 4),
        )
        ipv6 = self._set_block(
            self.config.nft_ipv6_set,
            "ipv6_addr",
            self._elements(entries, 6),
        )
        port = self.config.ssh_port

        return (
            f"table inet {self.config.nft_table} {{\n"
            f"{ipv4}\n\n"
            f"{ipv6}\n\n"
            "    chain ssh_guard {\n"
            "        type filter hook input priority -150; policy accept;\n"
            "        ct state established,related accept\n"
            "        iifname \"lo\" accept\n"
            f"        tcp dport {port} ip saddr @{self.config.nft_ipv4_set} accept\n"
            f"        tcp dport {port} ip6 saddr @{self.config.nft_ipv6_set} accept\n"
            f"        tcp dport {port} reject with tcp reset\n"
            "    }\n"
            "}\n"
        )

    def ensure(self) -> None:
        self._assert_write_mode()
        entries = self._load_entries()
        self._run(
            ["delete", "table", self.config.nft_family, self.config.nft_table],
            check=False,
        )
        self._run_script(self._ruleset(entries))
        self._save_entries(entries)

    def seed_permanent(self, ip_value: str, source: str = "bootstrap") -> None:
        self._assert_write_mode()
        address = parse_ip(ip_value)
        entries = self._load_entries()
        entries[str(address)] = {
            "expires_at": None,
            "source": source[:32],
        }
        self._run(
            ["delete", "table", self.config.nft_family, self.config.nft_table],
            check=False,
        )
        self._run_script(self._ruleset(entries))
        self._save_entries(entries)

    def health(self) -> dict[str, Any]:
        if self.config.firewall_mode != "nft":
            return {
                "mode": self.config.firewall_mode,
                "active": False,
                "ssh_port": self.config.ssh_port,
                "entries": 0,
            }

        entries = self._load_entries()
        result = self._run(
            ["list", "table", self.config.nft_family, self.config.nft_table],
            check=False,
        )
        return {
            "mode": "nft",
            "active": result.returncode == 0,
            "ssh_port": self.config.ssh_port,
            "entries": len(entries),
        }

    def allow(self, ip_value: str, ttl_seconds: int) -> dict[str, str | int]:
        self._assert_write_mode()
        if not 60 <= ttl_seconds <= 7 * 86400:
            raise ValueError("TTL is outside the allowed range")

        address = parse_ip(ip_value)
        entries = self._load_entries()
        entries[str(address)] = {
            "expires_at": int(time.time()) + ttl_seconds,
            "source": "telegram",
        }

        self._run(
            ["delete", "table", self.config.nft_family, self.config.nft_table],
            check=False,
        )
        self._run_script(self._ruleset(entries))
        self._save_entries(entries)

        return {
            "ip": str(address),
            "ttl_seconds": ttl_seconds,
            "set": self._set_for(address),
        }

    def revoke(self, ip_value: str) -> dict[str, str | bool]:
        self._assert_write_mode()
        address = parse_ip(ip_value)
        entries = self._load_entries()
        removed = entries.pop(str(address), None) is not None

        self._run(
            ["delete", "table", self.config.nft_family, self.config.nft_table],
            check=False,
        )
        self._run_script(self._ruleset(entries))
        self._save_entries(entries)

        return {
            "ip": str(address),
            "set": self._set_for(address),
            "removed": removed,
        }

    def listing(self) -> str:
        if self.config.firewall_mode != "nft":
            return "unavailable: firewall is in observe mode"

        entries = self._load_entries()
        health = self.health()
        lines = [
            "mode: managed",
            f"status: {'active' if health['active'] else 'inactive'}",
            f"ssh-port: {self.config.ssh_port}",
            f"trusted: {len(entries)}",
        ]

        now = int(time.time())
        for ip_value, meta in sorted(entries.items()):
            expires_at = meta.get("expires_at")
            if expires_at is None:
                ttl = "permanent"
            else:
                remaining = max(0, int(expires_at) - now)
                ttl = f"{max(1, remaining // 60)}m"
            source = str(meta.get("source", "telegram"))
            lines.append(f"{ip_value} · {ttl} · {source}")

        return bounded("\n".join(lines), 6500)
