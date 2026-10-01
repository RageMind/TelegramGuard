from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

PAM_BEGIN = "# BEGIN TELEGRAMGUARD SSH APPROVAL"
PAM_END = "# END TELEGRAMGUARD SSH APPROVAL"
PAM_COMMAND = (
    "account required pam_exec.so quiet "
    "/opt/telegram-guard/venv/bin/telegram-guard-pam"
)

DEFAULT_PAM_FILE = Path("/etc/pam.d/sshd")
DEFAULT_BACKUP_FILE = Path(
    "/var/lib/telegram-guard-helper/sshd.pam.before-telegramguard"
)
DEFAULT_SOCKET = Path("/run/telegram-guard-bot/approval.sock")


def _default_use_pam_probe() -> bool:
    sshd = next(
        (
            candidate
            for candidate in ("/usr/sbin/sshd", "/usr/bin/sshd")
            if Path(candidate).is_file() and os.access(candidate, os.X_OK)
        ),
        None,
    )
    if sshd is None:
        return False
    try:
        completed = subprocess.run(
            [sshd, "-T"],
            check=False,
            capture_output=True,
            text=True,
            timeout=6,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
            },
        )
    except (OSError, subprocess.SubprocessError):
        return False

    return any(
        line.strip().lower() == "usepam yes"
        for line in completed.stdout.splitlines()
    )


def _default_pam_exec_probe() -> bool:
    direct = (
        Path("/lib/security/pam_exec.so"),
        Path("/usr/lib/security/pam_exec.so"),
    )
    if any(candidate.is_file() for candidate in direct):
        return True

    roots = (Path("/lib"), Path("/usr/lib"))
    for root in roots:
        if not root.exists():
            continue
        try:
            for candidate in root.glob("*/security/pam_exec.so"):
                if candidate.is_file():
                    return True
        except OSError:
            continue
    return False


class SshApprovalControl:
    def __init__(
        self,
        *,
        pam_file: Path = DEFAULT_PAM_FILE,
        backup_file: Path = DEFAULT_BACKUP_FILE,
        socket_path: Path = DEFAULT_SOCKET,
        use_pam_probe: Callable[[], bool] = _default_use_pam_probe,
        pam_exec_probe: Callable[[], bool] = _default_pam_exec_probe,
    ) -> None:
        self.pam_file = pam_file
        self.backup_file = backup_file
        self.socket_path = socket_path
        self.use_pam_probe = use_pam_probe
        self.pam_exec_probe = pam_exec_probe

    def _read_pam(self) -> str:
        if not self.pam_file.is_file() or self.pam_file.is_symlink():
            raise RuntimeError("sshd PAM file is unavailable or unsafe")
        return self.pam_file.read_text(encoding="utf-8")

    def _write_pam(self, content: str) -> None:
        if self.pam_file.is_symlink():
            raise RuntimeError("refusing to write a symlink PAM file")

        flags = os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(self.pam_file, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("sshd PAM path is not a regular file")
            data = content.encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise RuntimeError("failed to write sshd PAM file")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _managed_block() -> str:
        return f"{PAM_BEGIN}\n{PAM_COMMAND}\n{PAM_END}\n"

    @staticmethod
    def _strip_managed_block(content: str) -> str:
        lines = content.splitlines()
        output: list[str] = []
        skipping = False
        for line in lines:
            if line.strip() == PAM_BEGIN:
                skipping = True
                continue
            if line.strip() == PAM_END:
                skipping = False
                continue
            if not skipping:
                output.append(line)

        cleaned = "\n".join(output).rstrip()
        return cleaned + ("\n" if cleaned else "")

    def _pam_enabled(self, content: str) -> bool:
        return (
            PAM_BEGIN in content
            and PAM_END in content
            and PAM_COMMAND in content
        )

    def _pam_writable(self) -> bool:
        if self.pam_file.is_symlink():
            return False

        flags = os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(self.pam_file, flags)
        except OSError:
            return False

        try:
            return stat.S_ISREG(os.fstat(fd).st_mode)
        finally:
            os.close(fd)

    def status(self) -> dict[str, Any]:
        try:
            content = self._read_pam()
            pam_enabled = self._pam_enabled(content)
            pam_file_ok = True
        except (OSError, UnicodeError, RuntimeError):
            pam_enabled = False
            pam_file_ok = False

        broker_ready = False
        try:
            broker_ready = stat.S_ISSOCK(self.socket_path.stat().st_mode)
        except OSError:
            broker_ready = False

        pam_writable = pam_file_ok and self._pam_writable()
        backup_dir_ready = (
            self.backup_file.parent.is_dir()
            and os.access(
                self.backup_file.parent,
                os.W_OK | os.X_OK,
            )
        )
        use_pam = self.use_pam_probe()
        pam_exec = self.pam_exec_probe()
        ready = (
            pam_file_ok
            and pam_writable
            and backup_dir_ready
            and broker_ready
            and use_pam
            and pam_exec
        )
        return {
            "enabled": pam_enabled,
            "ready": ready,
            "pam_file_ok": pam_file_ok,
            "pam_writable": pam_writable,
            "backup_dir_ready": backup_dir_ready,
            "broker_ready": broker_ready,
            "use_pam": use_pam,
            "pam_exec": pam_exec,
            "backup_present": self.backup_file.is_file(),
            "socket": str(self.socket_path),
        }

    def enable(self) -> dict[str, Any]:
        current = self.status()
        if current["enabled"]:
            return current
        if not current["ready"]:
            missing: list[str] = []
            if not current["pam_file_ok"]:
                missing.append("PAM file")
            if not current["pam_writable"]:
                missing.append("PAM write access")
            if not current["backup_dir_ready"]:
                missing.append("backup directory")
            if not current["use_pam"]:
                missing.append("UsePAM")
            if not current["pam_exec"]:
                missing.append("pam_exec")
            if not current["broker_ready"]:
                missing.append("approval broker")
            raise RuntimeError(
                "SSH approval preflight failed: " + ", ".join(missing)
            )

        original = self._read_pam()
        try:
            self.backup_file.parent.mkdir(parents=True, exist_ok=True)
            if not self.backup_file.exists():
                shutil.copyfile(self.pam_file, self.backup_file)
                os.chmod(self.backup_file, 0o600)
        except OSError as exc:
            detail = exc.strerror or type(exc).__name__
            raise RuntimeError(
                f"SSH approval backup failed: {detail}"
            ) from exc

        cleaned = self._strip_managed_block(original)
        updated = cleaned
        if updated and not updated.endswith("\n"):
            updated += "\n"
        updated += "\n" + self._managed_block()

        try:
            self._write_pam(updated)
        except Exception as exc:
            try:
                self._write_pam(original)
            except Exception as rollback_exc:
                raise RuntimeError(
                    "SSH approval PAM write failed and rollback failed"
                ) from rollback_exc

            if isinstance(exc, OSError):
                detail = exc.strerror or type(exc).__name__
            else:
                detail = str(exc) or type(exc).__name__
            raise RuntimeError(
                f"SSH approval PAM write failed: {detail}"
            ) from exc

        result = self.status()
        if not result["enabled"]:
            self._write_pam(original)
            raise RuntimeError("SSH approval did not become active")
        return result

    def disable(self) -> dict[str, Any]:
        original = self._read_pam()
        if not self._pam_enabled(original):
            return self.status()

        cleaned = self._strip_managed_block(original)
        self._write_pam(cleaned)
        result = self.status()
        if result["enabled"]:
            self._write_pam(original)
            raise RuntimeError("SSH approval did not disable")
        return result
