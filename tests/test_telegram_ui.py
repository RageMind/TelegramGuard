from __future__ import annotations

from telegram_guard.telegram_ui import button, dashboard_screen, keyboard, screen


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


def test_dashboard_screen_has_rich_table_and_plain_fallback() -> None:
    view = dashboard_screen(
        "Control Center",
        "🟢 VPS ONLINE",
        [("RAM", "19%"), ("Access", "Telegram 2FA")],
        footer="System checked",
    )

    assert "<table bordered compact>" in view.rich_html
    assert "<p><b>Control Center</b>" in view.rich_html
    assert "<table compact striped>" in view.rich_html
    assert "<td><b>RAM</b></td>" in view.rich_html
    assert "<b>Control Center</b>" in view.text
    assert "Telegram 2FA" in view.text


def test_dashboard_can_pack_metrics_into_two_columns() -> None:
    view = dashboard_screen(
        "Control Center",
        "🟢 NORMAL",
        [
            ("RAM", "20%"),
            ("Disk", "26%"),
            ("Load", "0.03"),
            ("SSH", "0 fail"),
        ],
        columns=2,
        details_title="Details",
        details_text="read-only",
    )

    assert view.rich_html.count("<tr>") == 2
    assert "<details><summary>Details</summary>" in view.rich_html
    assert "<pre>read-only</pre>" in view.rich_html
