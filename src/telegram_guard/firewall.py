from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from pathlib import Path

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

    def _assert_set_exists(self, set_name: str) -> None:
        self._run(
            [
                "list",
                "set",
                self.config.nft_family,
                self.config.nft_table,
                set_name,
            ]
        )

    def allow(self, ip_value: str, ttl_seconds: int) -> dict[str, str | int]:
        self._assert_write_mode()
        if not 60 <= ttl_seconds <= 7 * 86400:
            raise ValueError("TTL is outside the allowed range")

        address = parse_ip(ip_value)
        set_name = self._set_for(address)
        self._assert_set_exists(set_name)

        self._run(
            [
                "delete",
                "element",
                self.config.nft_family,
                self.config.nft_table,
                set_name,
                "{",
                str(address),
                "}",
            ],
            check=False,
        )
        self._run(
            [
                "add",
                "element",
                self.config.nft_family,
                self.config.nft_table,
                set_name,
                "{",
                str(address),
                "timeout",
                f"{ttl_seconds}s",
                "}",
            ]
        )
        return {"ip": str(address), "ttl_seconds": ttl_seconds, "set": set_name}

    def revoke(self, ip_value: str) -> dict[str, str | bool]:
        self._assert_write_mode()
        address = parse_ip(ip_value)
        set_name = self._set_for(address)
        self._assert_set_exists(set_name)
        result = self._run(
            [
                "delete",
                "element",
                self.config.nft_family,
                self.config.nft_table,
                set_name,
                "{",
                str(address),
                "}",
            ],
            check=False,
        )
        return {
            "ip": str(address),
            "set": set_name,
            "removed": result.returncode == 0,
        }

    def listing(self) -> str:
        chunks: list[str] = []
        for set_name in (self.config.nft_ipv4_set, self.config.nft_ipv6_set):
            result = self._run(
                [
                    "list",
                    "set",
                    self.config.nft_family,
                    self.config.nft_table,
                    set_name,
                ],
                check=False,
            )
            if result.returncode == 0:
                chunks.append(result.stdout.strip())
            else:
                chunks.append(f"{set_name}: unavailable")
        return bounded("\n\n".join(chunks), 6500)
