from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict, deque

_TTL_RE = re.compile(r"^([1-9][0-9]{0,4})([mhd])$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9@_.:-]{1,128}$")


class ValidationError(ValueError):
    """User-controlled input failed a security validator."""


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError("invalid IP address") from exc

    if address.is_unspecified or address.is_multicast:
        raise ValidationError("unspecified or multicast addresses are not allowed")
    if address.is_loopback or address.is_link_local:
        raise ValidationError("loopback or link-local addresses are not allowed")
    return address


def parse_ttl(value: str) -> int:
    match = _TTL_RE.fullmatch(value.strip().lower())
    if not match:
        raise ValidationError("TTL must look like 15m, 1h, 8h or 1d")

    amount = int(match.group(1))
    unit = match.group(2)
    seconds = amount * {"m": 60, "h": 3600, "d": 86400}[unit]
    if seconds < 60 or seconds > 7 * 86400:
        raise ValidationError("TTL must be between 1 minute and 7 days")
    return seconds


def format_ttl(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


def validate_unit(value: str) -> str:
    unit = value.strip()
    if not _UNIT_RE.fullmatch(unit) or "/" in unit or ".." in unit:
        raise ValidationError("invalid systemd unit name")
    return unit


def bounded(text: str, limit: int = 3500) -> str:
    cleaned = text.replace("\x00", "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 24] + "\n… output truncated …"


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[int, deque[float]] = defaultdict(deque)

    def allow(self, actor_id: int) -> bool:
        now = time.monotonic()
        bucket = self._events[actor_id]
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True
