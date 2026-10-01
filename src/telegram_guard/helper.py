from __future__ import annotations

import asyncio
import contextlib
import grp
import json
import os
import pwd
import socket
import struct
from pathlib import Path
from typing import Any

from telegram_guard import BRAND
from telegram_guard.config import HelperConfig
from telegram_guard.firewall import NftWhitelist
from telegram_guard.security import parse_ip, validate_unit
from telegram_guard.system_info import SystemController

_MAX_REQUEST_BYTES = 16_384


class HelperServer:
    def __init__(self, config: HelperConfig) -> None:
        self.config = config
        self.system = SystemController(config)
        self.firewall = NftWhitelist(config)
        self.allowed_uid = pwd.getpwnam(config.allowed_user).pw_uid

    def _peer_allowed(self, writer: asyncio.StreamWriter) -> bool:
        raw_socket = writer.get_extra_info("socket")
        if raw_socket is None or not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            credentials = raw_socket.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            _pid, uid, _gid = struct.unpack("3i", credentials)
        except OSError:
            return False
        return int(uid) == self.allowed_uid

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if not self._peer_allowed(writer):
            writer.close()
            await writer.wait_closed()
            return

        response: dict[str, Any]
        request_id: str | None = None
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not line or len(line) > _MAX_REQUEST_BYTES:
                raise ValueError("invalid request size")
            payload = json.loads(line)
            if not isinstance(payload, dict) or payload.get("version") != 1:
                raise ValueError("unsupported request")
            request_id = str(payload.get("id", ""))[:64]
            action = str(payload.get("action", ""))
            args = payload.get("args", {})
            if not isinstance(args, dict):
                raise ValueError("args must be an object")
            result = self.dispatch(action, args)
            response = {"id": request_id, "ok": True, "result": result}
        except (ValueError, PermissionError, RuntimeError, KeyError) as exc:
            response = {
                "id": request_id,
                "ok": False,
                "error": str(exc)[:240] or "request rejected",
            }
        except Exception:
            response = {
                "id": request_id,
                "ok": False,
                "error": "internal helper error",
            }

        wire = (json.dumps(response, separators=(",", ":")) + "\n").encode()
        writer.write(wire[:65_536])
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def dispatch(self, action: str, args: dict[str, Any]) -> Any:
        if action == "host.status":
            return self.system.host_status()
        if action == "host.sessions":
            return self.system.sessions()
        if action == "ssh.recent":
            minutes = int(args.get("minutes", 30))
            if not 1 <= minutes <= 180:
                raise ValueError("minutes must be between 1 and 180")
            return self.system.ssh_recent(minutes)
        if action == "firewall.allow":
            ip_value = str(args["ip"])
            address = parse_ip(ip_value)
            ttl_seconds = int(args["ttl_seconds"])
            return self.firewall.allow(str(address), ttl_seconds)
        if action == "firewall.revoke":
            ip_value = str(args["ip"])
            address = parse_ip(ip_value)
            return self.firewall.revoke(str(address))
        if action == "firewall.list":
            return self.firewall.listing()
        if action == "service.list":
            return self.system.list_services()
        if action == "service.status":
            unit = validate_unit(str(args["unit"]))
            return self.system.service_status(unit)
        if action == "service.restart":
            unit = validate_unit(str(args["unit"]))
            return self.system.restart_service(unit)
        raise PermissionError("unknown helper action")


async def _serve(config: HelperConfig) -> None:
    socket_path = Path(config.socket_path)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        socket_path.unlink()

    server_impl = HelperServer(config)
    server = await asyncio.start_unix_server(
        server_impl.handle,
        path=str(socket_path),
        limit=_MAX_REQUEST_BYTES,
    )

    group = grp.getgrnam(config.socket_group)
    os.chown(socket_path, 0, group.gr_gid)
    os.chmod(socket_path, 0o660)

    print(f"{BRAND}: helper ready on local Unix socket", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    config = HelperConfig.from_env()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve(config))


if __name__ == "__main__":
    main()
