from __future__ import annotations

import socket
from pathlib import Path

import pytest

from telegram_guard.ssh_access import (
    PAM_BEGIN,
    PAM_COMMAND,
    PAM_END,
    SshApprovalControl,
)


def _controller(
    tmp_path: Path,
    *,
    broker_ready: bool = True,
    use_pam: bool = True,
    pam_exec: bool = True,
) -> tuple[SshApprovalControl, socket.socket | None, Path]:
    pam_file = tmp_path / "sshd"
    pam_file.write_text(
        "# PAM configuration for sshd\n"
        "account required pam_nologin.so\n",
        encoding="utf-8",
    )
    backup = tmp_path / "backup"
    socket_path = tmp_path / "approval.sock"

    server: socket.socket | None = None
    if broker_ready:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)

    controller = SshApprovalControl(
        pam_file=pam_file,
        backup_file=backup,
        socket_path=socket_path,
        use_pam_probe=lambda: use_pam,
        pam_exec_probe=lambda: pam_exec,
    )
    return controller, server, pam_file


def test_enable_and_disable_are_idempotent(tmp_path: Path) -> None:
    controller, server, pam_file = _controller(tmp_path)
    assert server is not None
    try:
        before = controller.status()
        assert before["enabled"] is False
        assert before["ready"] is True

        enabled = controller.enable()
        assert enabled["enabled"] is True
        content = pam_file.read_text(encoding="utf-8")
        assert content.count(PAM_BEGIN) == 1
        assert content.count(PAM_END) == 1
        assert content.count(PAM_COMMAND) == 1

        enabled_again = controller.enable()
        assert enabled_again["enabled"] is True
        assert pam_file.read_text(encoding="utf-8").count(PAM_BEGIN) == 1

        disabled = controller.disable()
        assert disabled["enabled"] is False
        content = pam_file.read_text(encoding="utf-8")
        assert PAM_BEGIN not in content
        assert PAM_COMMAND not in content

        disabled_again = controller.disable()
        assert disabled_again["enabled"] is False
    finally:
        server.close()


def test_enable_requires_live_broker(tmp_path: Path) -> None:
    controller, server, _pam_file = _controller(
        tmp_path,
        broker_ready=False,
    )
    assert server is None

    status = controller.status()
    assert status["ready"] is False
    assert status["broker_ready"] is False

    with pytest.raises(RuntimeError, match="approval broker"):
        controller.enable()


def test_enable_requires_usepam_and_pam_exec(tmp_path: Path) -> None:
    controller, server, _pam_file = _controller(
        tmp_path,
        use_pam=False,
        pam_exec=False,
    )
    assert server is not None
    try:
        with pytest.raises(RuntimeError, match="UsePAM"):
            controller.enable()
    finally:
        server.close()


def test_enable_creates_root_style_backup(tmp_path: Path) -> None:
    controller, server, pam_file = _controller(tmp_path)
    assert server is not None
    try:
        original = pam_file.read_text(encoding="utf-8")
        controller.enable()
        backup = tmp_path / "backup"
        assert backup.read_text(encoding="utf-8") == original
        assert backup.stat().st_mode & 0o777 == 0o600
    finally:
        server.close()
