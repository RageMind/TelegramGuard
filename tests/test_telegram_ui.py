from __future__ import annotations

from telegram_guard.telegram_ui import button, keyboard, screen


def test_button_supports_bot_api_style() -> None:
    assert button("Open", "ui:home", style="primary") == {
        "text": "Open",
        "callback_data": "ui:home",
        "style": "primary",
    }


def test_neutral_button_omits_style() -> None:
    assert button("Back", "ui:home") == {
        "text": "Back",
        "callback_data": "ui:home",
    }


def test_keyboard_preserves_rows() -> None:
    markup = keyboard(
        [button("Allow", "allow", style="success")],
        [button("Deny", "deny", style="danger")],
    )
    assert markup["inline_keyboard"][0][0]["style"] == "success"
    assert markup["inline_keyboard"][1][0]["style"] == "danger"


def test_screen_uses_compact_control_os_layout() -> None:
    value = screen("Control Center", "ONLINE")
    assert "<b>TelegramGuard</b>" in value
    assert "<code>QyAi Control OS</code>" in value
    assert "<blockquote><b>Control Center</b>" in value
    assert "━━━━━━━━" not in value
