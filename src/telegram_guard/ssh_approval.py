from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import socket
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Decision = Literal["approve", "deny"]

_MAX_REQUEST_BYTES = 4096
_MAX_PENDING = 16


@dataclass(frozen=True, slots=True)
class SshApprovalRequest:
    user: str
    remote_ip: str
    service: str
    tty: str
    created_at: int


@dataclass(slots=True)
class PendingSshApproval:
    token: str
    request: SshApprovalRequest
    future: asyncio.Future[Decision]


def _clean_text(value: object, *, limit: int) -> str:
    text = str(value).strip()
    if not text or len(text) > limit:
        raise ValueError("invalid approval request")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError("invalid approval request")
    return text


def parse_request(payload: object) -> SshApprovalRequest:
    if not isinstance(payload, dict):
        raise ValueError("invalid approval request")
    if payload.get("version") != 1:
        raise ValueError("unsupported approval protocol")
    user = _clean_text(payload.get("user", ""), limit=64)
    remote_ip = _clean_text(payload.get("remote_ip", ""), limit=64)
    service = _clean_text(payload.get("service", ""), limit=32)
    tty_raw = str(payload.get("tty", "")).strip()
    tty = tty_raw[:96] if tty_raw else "unknown"
    return SshApprovalRequest(
        user=user,
        remote_ip=remote_ip,
        service=service,
        tty=tty,
        created_at=int(time.time()),
    )


class SshApprovalBroker:
    def __init__(
        self,
        socket_path: str,
        timeout_seconds: int,
        on_request: Callable[[str, SshApprovalRequest], Awaitable[None]],
        on_result: Callable[[str, SshApprovalRequest, Decision | str], Awaitable[None]],
    ) -> None:
        self.socket_path = Path(socket_path)
        self.timeout_seconds = timeout_seconds
        self.on_request = on_request
        self.on_result = on_result
        self.pending: dict[str, PendingSshApproval] = {}
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileNotFoundError):
            self.socket_path.unlink()

        self.server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.socket_path),
            limit=_MAX_REQUEST_BYTES,
        )
        os.chmod(self.socket_path, 0o600)

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        for item in list(self.pending.values()):
            if not item.future.done():
                item.future.set_result("deny")
        self.pending.clear()
        with contextlib.suppress(FileNotFoundError):
            self.socket_path.unlink()

    def decide(self, token: str, decision: Decision) -> SshApprovalRequest | None:
        item = self.pending.get(token)
        if item is None or item.future.done():
            return None
        item.future.set_result(decision)
        return item.request

    def status(self) -> dict[str, int | bool | str]:
        return {
            "active": self.server is not None,
            "pending": len(self.pending),
            "socket": str(self.socket_path),
            "timeout_seconds": self.timeout_seconds,
        }

    @staticmethod
    def _peer_is_root(writer: asyncio.StreamWriter) -> bool:
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
        return int(uid) == 0

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        decision: Decision | str = "deny"
        request: SshApprovalRequest | None = None
        token = ""
        try:
            if not self._peer_is_root(writer):
                raise PermissionError("approval client must be root")
            if len(self.pending) >= _MAX_PENDING:
                raise RuntimeError("too many pending SSH approvals")

            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            if not line or len(line) > _MAX_REQUEST_BYTES:
                raise ValueError("invalid approval request size")
            request = parse_request(json.loads(line))
            token = secrets.token_urlsafe(9)
            future: asyncio.Future[Decision] = asyncio.get_running_loop().create_future()
            self.pending[token] = PendingSshApproval(
                token=token,
                request=request,
                future=future,
            )
            await self.on_request(token, request)

            try:
                decision = await asyncio.wait_for(
                    future,
                    timeout=float(self.timeout_seconds),
                )
            except TimeoutError:
                decision = "timeout"

            response = {
                "ok": decision == "approve",
                "decision": decision,
            }
            writer.write((json.dumps(response, separators=(",", ":")) + "\n").encode())
            await writer.drain()
        except Exception:
            response = {"ok": False, "decision": "error"}
            writer.write((json.dumps(response, separators=(",", ":")) + "\n").encode())
            with contextlib.suppress(ConnectionError, BrokenPipeError):
                await writer.drain()
        finally:
            if token:
                self.pending.pop(token, None)
            if request is not None:
                await self.on_result(token, request, decision)
            writer.close()
            with contextlib.suppress(ConnectionError, BrokenPipeError):
                await writer.wait_closed()
