from __future__ import annotations

from typing import Any

import pytest

from telegram_guard.telegram_api import TelegramAPI


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
        "security",
        "settings",
        "help",
    ]
    assert calls[1][1]["menu_button"]["type"] == "commands"
