from __future__ import annotations

from typing import Any

import httpx

from telegram_guard import BRAND


class TelegramAPIError(RuntimeError):
    pass


class TelegramAPI:
    def __init__(self, token: str) -> None:
        self._base = f"https://api.telegram.org/bot{token}"
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(40.0, connect=10.0),
            headers={"User-Agent": "TelegramGuard/0.1 (QyAi)"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, payload: dict[str, Any]) -> Any:
        try:
            response = await self._client.post(f"{self._base}/{method}", json=payload)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise TelegramAPIError("Telegram API request failed") from exc

        if not isinstance(data, dict) or not data.get("ok"):
            raise TelegramAPIError("Telegram API rejected the request")
        return data.get("result")

    async def get_updates(
        self, offset: int | None, timeout: int
    ) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {
            "timeout": timeout,
            "allowed_updates": ["message", "callback_query"],
        }
        if offset is not None:
            payload["offset"] = offset
        result = await self._call("getUpdates", payload)
        if not isinstance(result, list):
            raise TelegramAPIError("Telegram API returned invalid updates")
        return [item for item in result if isinstance(item, dict)]

    async def send_message(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        await self._call("sendMessage", payload)

    async def answer_callback(self, callback_id: str, text: str = "") -> None:
        payload: dict[str, Any] = {
            "callback_query_id": callback_id,
            "text": text[:180],
            "show_alert": False,
        }
        await self._call("answerCallbackQuery", payload)

    async def set_commands(self) -> None:
        commands = [
            {"command": "status", "description": "VPS health summary"},
            {"command": "sessions", "description": "Active login sessions"},
            {"command": "ssh", "description": "Recent SSH events"},
            {"command": "allow", "description": "Temporarily whitelist an IP"},
            {"command": "revoke", "description": "Remove an IP from whitelist"},
            {"command": "whitelist", "description": "List whitelist entries"},
            {"command": "services", "description": "Managed systemd services"},
            {"command": "service", "description": "Service status"},
            {"command": "restart", "description": "Confirmed service restart"},
            {"command": "audit", "description": "Recent TelegramGuard audit"},
            {"command": "help", "description": "Command reference"},
        ]
        await self._call("setMyCommands", {"commands": commands})
