from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any


class HelperError(RuntimeError):
    pass


class HelperClient:
    def __init__(self, socket_path: str, timeout: float = 8.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    async def call(self, action: str, args: dict[str, Any] | None = None) -> Any:
        request_id = uuid.uuid4().hex
        payload = {
            "version": 1,
            "id": request_id,
            "action": action,
            "args": args or {},
        }
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path),
                timeout=self.timeout,
            )
            try:
                wire = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
                if len(wire) > 16_384:
                    raise HelperError("request too large")
                writer.write(wire)
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            raise HelperError("local helper is unavailable") from exc

        if not line or len(line) > 65_536:
            raise HelperError("invalid helper response")

        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HelperError("invalid helper response") from exc

        if response.get("id") != request_id:
            raise HelperError("helper response ID mismatch")
        if not response.get("ok"):
            message = str(response.get("error", "helper rejected the request"))
            raise HelperError(message[:240])
        return response.get("result")
