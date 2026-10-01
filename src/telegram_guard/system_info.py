from __future__ import annotations

import contextlib
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from telegram_guard.config import HelperConfig
from telegram_guard.security import bounded, validate_unit


def _resolve_binary(name: str, candidates: tuple[str, ...]) -> str:
    for candidate in candidates:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    discovered = shutil.which(name)
    if discovered:
        return discovered
    raise RuntimeError(f"required binary is unavailable: {name}")


def _resolve_optional(name: str, candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which(name)


def _run(
    argv: list[str],
    *,
    timeout: float = 8.0,
    check: bool = True,
    max_output: int = 12_000,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if check and completed.returncode != 0:
        message = bounded(completed.stderr or completed.stdout or "command failed", 300)
        raise RuntimeError(message)
    if len(completed.stdout) > max_output:
        completed.stdout = completed.stdout[:max_output]
    if len(completed.stderr) > max_output:
        completed.stderr = completed.stderr[:max_output]
    return completed


def _read_os_name() -> str:
    path = Path("/etc/os-release")
    with contextlib.suppress(OSError):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')[:120]
    return platform.system()


class SystemController:
    def __init__(self, config: HelperConfig) -> None:
        self.config = config
        self.systemctl = _resolve_binary(
            "systemctl", ("/usr/bin/systemctl", "/bin/systemctl")
        )
        self.journalctl = _resolve_binary(
            "journalctl", ("/usr/bin/journalctl", "/bin/journalctl")
        )
        self.who = _resolve_binary("who", ("/usr/bin/who", "/bin/who"))
        self.ss = _resolve_optional(
            "ss", ("/usr/bin/ss", "/usr/sbin/ss", "/bin/ss")
        )
        self.apt = _resolve_optional("apt", ("/usr/bin/apt",))

    def host_status(self) -> dict[str, Any]:
        uptime_seconds = 0
        with contextlib.suppress(OSError, ValueError, IndexError):
            uptime_seconds = int(float(Path("/proc/uptime").read_text().split()[0]))

        memory: dict[str, int] = {}
        with contextlib.suppress(OSError, ValueError):
            for line in Path("/proc/meminfo").read_text().splitlines():
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if parts:
                    memory[key] = int(parts[0]) * 1024

        process_count = 0
        with contextlib.suppress(OSError):
            process_count = sum(
                1
                for item in Path("/proc").iterdir()
                if item.name.isdigit() and item.is_dir()
            )

        disk = shutil.disk_usage("/")
        statvfs = os.statvfs("/")
        load = os.getloadavg()
        return {
            "hostname": socket.gethostname()[:120],
            "os_name": _read_os_name(),
            "kernel": platform.release()[:120],
            "cpu_count": os.cpu_count() or 0,
            "process_count": process_count,
            "uptime_seconds": uptime_seconds,
            "load_1": round(load[0], 2),
            "load_5": round(load[1], 2),
            "load_15": round(load[2], 2),
            "memory_total": memory.get("MemTotal", 0),
            "memory_available": memory.get("MemAvailable", 0),
            "swap_total": memory.get("SwapTotal", 0),
            "swap_free": memory.get("SwapFree", 0),
            "disk_total": disk.total,
            "disk_free": disk.free,
            "inode_total": int(statvfs.f_files),
            "inode_free": int(statvfs.f_ffree),
        }

    def sessions(self) -> str:
        result = _run([self.who], timeout=4.0, check=False)
        return bounded(result.stdout or "No interactive sessions.", 5000)

    def network_status(self) -> dict[str, Any]:
        interfaces: list[dict[str, Any]] = []
        total_rx = 0
        total_tx = 0
        with contextlib.suppress(OSError, ValueError):
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
                if ":" not in line:
                    continue
                raw_name, raw_stats = line.split(":", 1)
                name = raw_name.strip()
                fields = raw_stats.split()
                if len(fields) < 16:
                    continue
                rx_bytes = int(fields[0])
                tx_bytes = int(fields[8])
                if name != "lo":
                    total_rx += rx_bytes
                    total_tx += tx_bytes
                interfaces.append(
                    {
                        "name": name[:32],
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                    }
                )

        interfaces.sort(
            key=lambda item: int(item["rx_bytes"]) + int(item["tx_bytes"]),
            reverse=True,
        )

        listeners: list[dict[str, str]] = []
        if self.ss:
            result = _run(
                [self.ss, "-H", "-lntu"],
                timeout=5.0,
                check=False,
                max_output=12_000,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5:
                    continue
                listeners.append(
                    {
                        "proto": parts[0][:12],
                        "local": parts[4][:160],
                    }
                )
                if len(listeners) >= 24:
                    break

        return {
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "interfaces": interfaces[:12],
            "listeners": listeners,
        }

    def system_health(self) -> dict[str, Any]:
        failed_result = _run(
            [
                self.systemctl,
                "--failed",
                "--no-legend",
                "--plain",
            ],
            timeout=6.0,
            check=False,
            max_output=12_000,
        )
        failed_units: list[str] = []
        for line in failed_result.stdout.splitlines():
            parts = line.split()
            if parts:
                failed_units.append(parts[0][:160])
            if len(failed_units) >= 30:
                break

        upgradable = 0
        package_manager = "unavailable"
        if self.apt:
            package_manager = "apt"
            result = _run(
                [self.apt, "list", "--upgradable"],
                timeout=12.0,
                check=False,
                max_output=24_000,
            )
            for line in result.stdout.splitlines():
                value = line.strip()
                if "/" in value and "[upgradable from:" in value:
                    upgradable += 1

        return {
            "failed_units": failed_units,
            "failed_unit_count": len(failed_units),
            "reboot_required": Path("/var/run/reboot-required").exists(),
            "upgradable_packages": upgradable,
            "package_manager": package_manager,
        }

    def system_events(self, minutes: int) -> str:
        minutes = max(1, min(minutes, 1440))
        result = _run(
            [
                self.journalctl,
                "--since",
                f"-{minutes} minutes",
                "-p",
                "warning..alert",
                "--no-pager",
                "-o",
                "short-iso",
                "-n",
                "80",
            ],
            timeout=8.0,
            check=False,
            max_output=20_000,
        )
        return bounded(
            result.stdout or "No warning-or-higher events in the requested window.",
            7000,
        )

    def _journal_lines(
        self,
        unit: str,
        *,
        minutes: int,
        max_lines: int = 120,
    ) -> list[str]:
        minutes = max(1, min(minutes, 1440))
        max_lines = max(1, min(max_lines, 300))
        result = _run(
            [
                self.journalctl,
                "-u",
                unit,
                "--since",
                f"-{minutes} minutes",
                "--no-pager",
                "-o",
                "short-iso",
                "-n",
                str(max_lines),
            ],
            timeout=8.0,
            check=False,
            max_output=30_000,
        )
        return (result.stdout or "").splitlines()[-max_lines:]

    def ssh_recent(self, minutes: int) -> str:
        lines = self._journal_lines(
            self.config.ssh_journal_unit,
            minutes=minutes,
            max_lines=80,
        )
        return bounded(
            "\n".join(lines) or "No SSH events in the requested window.",
            6500,
        )

    def ssh_summary(self, minutes: int) -> dict[str, int]:
        minutes = max(1, min(minutes, 1440))
        lines = self._journal_lines(
            self.config.ssh_journal_unit,
            minutes=minutes,
            max_lines=300,
        )
        failed = 0
        accepted = 0
        invalid_user = 0
        disconnected = 0

        for line in lines:
            lower = line.lower()
            if (
                "failed password" in lower
                or "authentication failure" in lower
                or "failed publickey" in lower
            ):
                failed += 1
            if "accepted publickey" in lower or "accepted password" in lower:
                accepted += 1
            if "invalid user" in lower:
                invalid_user += 1
            if "disconnected from" in lower or "connection closed by" in lower:
                disconnected += 1

        return {
            "minutes": minutes,
            "events": len(lines),
            "failed": failed,
            "accepted": accepted,
            "invalid_user": invalid_user,
            "disconnected": disconnected,
        }

    def list_services(self) -> list[str]:
        return list(self.config.managed_services)

    def service_status(self, unit: str) -> str:
        unit = validate_unit(unit)
        self._assert_managed(unit)
        result = _run(
            [
                self.systemctl,
                "show",
                unit,
                "--no-pager",
                "--property=Id,Description,LoadState,ActiveState,SubState",
            ],
            timeout=5.0,
        )
        return bounded(result.stdout, 3000)

    def service_logs(self, unit: str, lines: int = 40) -> str:
        unit = validate_unit(unit)
        self._assert_managed(unit)
        lines = max(5, min(lines, 120))
        result = _run(
            [
                self.journalctl,
                "-u",
                unit,
                "-n",
                str(lines),
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=8.0,
            check=False,
            max_output=14_000,
        )
        return bounded(result.stdout or "No recent service logs.", 6500)

    def restart_service(self, unit: str) -> str:
        unit = validate_unit(unit)
        self._assert_managed(unit)
        _run([self.systemctl, "restart", unit], timeout=20.0)
        return self.service_status(unit)

    def _assert_managed(self, unit: str) -> None:
        if unit not in self.config.managed_services:
            raise PermissionError("service is not in MANAGED_SERVICES")
