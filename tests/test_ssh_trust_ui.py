from __future__ import annotations

from telegram_guard.bot import _ttl_keyboard
from telegram_guard.ssh_trust import SSH_TRUST_CHOICES


def test_ip_firewall_allow_keyboard_contains_requested_durations():
    buttons = [
        item for row in _ttl_keyboard()["inline_keyboard"]
        for item in row
    ]
    actions = {button["callback_data"]: button["text"] for button in buttons}
    assert actions["ttl:36000"] == "10 часов"
    assert actions["ttl:72000"] == "20 часов"
    assert actions["ttl:172800"] == "2 дня"
    assert actions["ttl:259200"] == "3 дня"
    assert actions["ttl:604800"] == "7 дней"


def test_ssh_trust_buttons_are_well_bounded():
    assert 36000 in SSH_TRUST_CHOICES
    assert 72000 in SSH_TRUST_CHOICES
    assert 604800 in SSH_TRUST_CHOICES
    assert max(SSH_TRUST_CHOICES) == 7 * 86400


def test_ssh_trust_callbacks_fit_telegram_limit():
    token = "A" * 16
    for duration in SSH_TRUST_CHOICES:
        assert len(f"ssht:{token}:{duration}".encode()) <= 64
