from __future__ import annotations

import ipaddress
import json
import os
import socket
from pathlib import Path

DEFAULT_SOCKET = "/run/telegram-guard-bot/approval.sock"
DEFAULT_TIMEOUT = 75
BOT_ENV = Path("/etc/telegram-guard/bot.env")


def _setting(name: str, default: str) -> str:
    if not BOT_ENV.is_file():
        return default
    try:
        lines = BOT_ENV.read_text(encoding="utf-8").splitlines()
    except OSError:
        return default
    for raw in lines:
        if raw.startswith(f"{name}="):
            return raw.split("=", 1)[1].strip() or default
    return default


def _pam_request() -> dict[str, object]:
    if os.environ.get("PAM_TYPE") != "account":
        raise ValueError("unsupported PAM phase")
    if os.environ.get("PAM_SERVICE") != "sshd":
        raise ValueError("unsupported PAM service")

    user = os.environ.get("PAM_USER", "").strip()
    if not user or len(user) > 64:
        raise ValueError("invalid PAM user")

    remote_raw = os.environ.get("PAM_RHOST", "").strip()
    if not remote_raw:
        raise ValueError("missing remote host")
    remote_ip = str(ipaddress.ip_address(remote_raw))

    tty = os.environ.get("PAM_TTY", "").strip()[:96] or "unknown"
    return {
        "version": 1,
        "user": user,
        "remote_ip": remote_ip,
        "service": "sshd",
        "tty": tty,
    }


def _timeout_seconds() -> int:
    raw = _setting("SSH_APPROVAL_TIMEOUT", str(DEFAULT_TIMEOUT))
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    return max(15, min(value, 180))


def main() -> None:
    try:
        payload = _pam_request()
        socket_path = _setting("SSH_APPROVAL_SOCKET", DEFAULT_SOCKET)
        if not socket_path.startswith("/"):
            raise ValueError("invalid approval socket")

        timeout = float(_timeout_seconds() + 5)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(socket_path)
            client.sendall(
                (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            )

            chunks = bytearray()
            while b"\n" not in chunks and len(chunks) < 4096:
                part = client.recv(1024)
                if not part:
                    break
                chunks.extend(part)

        line = bytes(chunks).split(b"\n", 1)[0]
        result = json.loads(line.decode("utf-8"))
        approved = (
            isinstance(result, dict)
            and result.get("ok") is True
            and result.get("decision") == "approve"
        )
    except Exception:
        approved = False

    raise SystemExit(0 if approved else 1)


if __name__ == "__main__":
    main()
