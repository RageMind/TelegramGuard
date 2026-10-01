from __future__ import annotations

from typing import Any

import pytest

from telegram_guard.telegram_api import TelegramAPI, TelegramAPIError
from telegram_guard.telegram_ui import TelegramView


@pytest.mark.asyncio
async def test_configure_profile_sets_clean_native_bot_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = TelegramAPI("test-token")
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_call(method: str, payload: dict[str, Any]) -> Any:
        calls.append((method, payload))
        return True

    monkeypatch.setattr(api, "_call", fake_call)

    try:
        await api.configure_profile()
    finally:
        await api.close()

    methods = [method for method, _ in calls]
    assert methods == [
        "setMyCommands",
        "setChatMenuButton",
        "setMyName",
        "setMyShortDescription",
        "setMyDescription",
    ]

    commands = calls[0][1]["commands"]
    assert [item["command"] for item in commands] == [
        "start",
        "status",
        "doctor",
        "network",
        "security",
        "settings",
    ]
    assert calls[1][1]["menu_button"]["type"] == "commands"


@pytest.mark.asyncio
async def test_send_message_prefers_rich_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = TelegramAPI("test-token")
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_call(method: str, payload: dict[str, Any]) -> Any:
        calls.append((method, payload))
        return True

    monkeypatch.setattr(api, "_call", fake_call)
    try:
        await api.send_message(
            42,
            TelegramView(
                text="<b>Fallback</b>",
                rich_html="<h2>Rich</h2>",
            ),
            {"inline_keyboard": []},
        )
    finally:
        await api.close()

    assert calls[0][0] == "sendRichMessage"
    assert calls[0][1]["rich_message"]["html"] == "<h2>Rich</h2>"


@pytest.mark.asyncio
async def test_send_message_falls_back_when_rich_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = TelegramAPI("test-token")
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake_call(method: str, payload: dict[str, Any]) -> Any:
        calls.append((method, payload))
        if method == "sendRichMessage":
            raise TelegramAPIError("rich messages unsupported")
        return True

    monkeypatch.setattr(api, "_call", fake_call)
    try:
        await api.send_message(
            42,
            TelegramView(
                text="<b>Fallback</b>",
                rich_html="<h2>Rich</h2>",
            ),
        )
    finally:
        await api.close()

    assert [method for method, _ in calls] == [
        "sendRichMessage",
        "sendMessage",
    ]
    assert calls[1][1]["text"] == "<b>Fallback</b>"
