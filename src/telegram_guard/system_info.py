from __future__ import annotations

import contextlib
import os
import shutil
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

        disk = shutil.disk_usage("/")
        load = os.getloadavg()
        return {
            "uptime_seconds": uptime_seconds,
            "load_1": round(load[0], 2),
            "load_5": round(load[1], 2),
            "load_15": round(load[2], 2),
            "memory_total": memory.get("MemTotal", 0),
            "memory_available": memory.get("MemAvailable", 0),
            "disk_total": disk.total,
            "disk_free": disk.free,
        }

    def sessions(self) -> str:
        result = _run([self.who], timeout=4.0, check=False)
        return bounded(result.stdout or "No interactive sessions.", 5000)

    def ssh_recent(self, minutes: int) -> str:
        minutes = max(1, min(minutes, 180))
        result = _run(
            [
                self.journalctl,
                "-u",
                self.config.ssh_journal_unit,
                "--since",
                f"-{minutes} minutes",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            timeout=8.0,
            check=False,
            max_output=20_000,
        )
        lines = (result.stdout or "").splitlines()[-80:]
        return bounded("\n".join(lines) or "No SSH events in the requested window.", 6500)

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

    def restart_service(self, unit: str) -> str:
        unit = validate_unit(unit)
        self._assert_managed(unit)
        _run([self.systemctl, "restart", unit], timeout=20.0)
        return self.service_status(unit)

    def _assert_managed(self, unit: str) -> None:
        if unit not in self.config.managed_services:
            raise PermissionError("service is not in MANAGED_SERVICES")
