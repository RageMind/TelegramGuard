from __future__ import annotations

from typing import Any

import httpx

from telegram_guard import __version__


class TelegramAPIError(RuntimeError):
    pass


class TelegramAPI:
    def __init__(self, token: str) -> None:
        self._base = f"https://api.telegram.org/bot{token}"
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(40.0, connect=10.0),
            headers={"User-Agent": f"TelegramGuard/{__version__} (QyAi)"},
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
            description = (
                str(data.get("description", "Telegram API rejected the request"))
                if isinstance(data, dict)
                else "Telegram API rejected the request"
            )
            raise TelegramAPIError(description[:240])
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
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        await self._call("sendMessage", payload)

    async def edit_message_text(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            await self._call("editMessageText", payload)
        except TelegramAPIError as exc:
            if "message is not modified" not in str(exc).lower():
                raise

    async def answer_callback(
        self,
        callback_id: str,
        text: str = "",
        *,
        show_alert: bool = False,
    ) -> None:
        payload: dict[str, Any] = {
            "callback_query_id": callback_id,
            "text": text[:180],
            "show_alert": show_alert,
        }
        await self._call("answerCallbackQuery", payload)

    async def configure_profile(self) -> None:
        commands = [
            {"command": "start", "description": "Открыть Control Center"},
            {"command": "status", "description": "Состояние VPS"},
            {"command": "security", "description": "Безопасность и SSH"},
            {"command": "settings", "description": "Настройки TelegramGuard"},
            {"command": "help", "description": "Открыть панель"},
        ]
        await self._call("setMyCommands", {"commands": commands})
        await self._call(
            "setChatMenuButton",
            {"menu_button": {"type": "commands"}},
        )
        await self._call(
            "setMyName",
            {"name": "TelegramGuard"},
        )
        await self._call(
            "setMyShortDescription",
            {"short_description": "QyAi VPS Control OS"},
        )
        await self._call(
            "setMyDescription",
            {
                "description": (
                    "TelegramGuard by QyAi — приватный Control OS для VPS. "
                    "Состояние сервера, SSH-защита, доступы, сервисы, "
                    "уведомления и аудит в одном интерфейсе."
                )
            },
        )
