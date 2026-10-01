from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "public_safety_scan.py"


def run_scan(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_scanner_accepts_documentation_values(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "Example address 203.0.113.42\nQyAi https://qyai.ru\n",
        encoding="utf-8",
    )
    result = run_scan(tmp_path)
    assert result.returncode == 0, result.stderr


def test_scanner_rejects_runtime_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("TOKEN=placeholder\n", encoding="utf-8")
    result = run_scan(tmp_path)
    assert result.returncode == 1
    assert "environment file" in result.stderr


def test_scanner_rejects_non_documentation_ip(tmp_path: Path) -> None:
    live_looking_ip = ".".join(("8", "8", "8", "8"))
    (tmp_path / "notes.txt").write_text(
        f"server={live_looking_ip}\n",
        encoding="utf-8",
    )
    result = run_scan(tmp_path)
    assert result.returncode == 1
    assert "non-documentation IPv4" in result.stderr
