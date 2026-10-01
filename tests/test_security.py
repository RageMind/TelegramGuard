from __future__ import annotations

import pytest

from telegram_guard.security import (
    RateLimiter,
    ValidationError,
    format_ttl,
    parse_ip,
    parse_ttl,
    validate_unit,
)


def test_parse_documentation_ip() -> None:
    assert str(parse_ip("203.0.113.42")) == "203.0.113.42"


def test_private_ip_is_allowed_for_private_networks() -> None:
    private_ip = ".".join(("10", "20", "30", "40"))
    assert str(parse_ip(private_ip)) == private_ip


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        ".".join(("0", "0", "0", "0")),
        ".".join(("224", "0", "0", "1")),
        "not-an-ip",
    ],
)
def test_unsafe_ips_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        parse_ip(value)


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [("15m", 900), ("1h", 3600), ("8h", 28800), ("1d", 86400), ("7d", 604800)],
)
def test_ttl_parser(raw: str, seconds: int) -> None:
    assert parse_ttl(raw) == seconds
    assert parse_ttl(format_ttl(seconds)) == seconds


@pytest.mark.parametrize("raw", ["0m", "8d", "forever", "1w", "-1h"])
def test_invalid_ttl(raw: str) -> None:
    with pytest.raises(ValidationError):
        parse_ttl(raw)


def test_unit_validation() -> None:
    assert validate_unit("nginx.service") == "nginx.service"
    with pytest.raises(ValidationError):
        validate_unit("../../tmp/unit")


def test_rate_limiter() -> None:
    limiter = RateLimiter(2, window_seconds=60)
    assert limiter.allow(7)
    assert limiter.allow(7)
    assert not limiter.allow(7)
    assert limiter.allow(8)
