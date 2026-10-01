from __future__ import annotations

from typing import Any, Literal

ButtonStyle = Literal["primary", "success", "danger"]


def button(
    text: str,
    callback_data: str,
    *,
    style: ButtonStyle | None = None,
) -> dict[str, str]:
    item: dict[str, str] = {
        "text": text,
        "callback_data": callback_data,
    }
    if style is not None:
        item["style"] = style
    return item


def keyboard(*rows: list[dict[str, str]]) -> dict[str, Any]:
    return {"inline_keyboard": list(rows)}


def screen(
    title: str,
    body: str,
    footer: str | None = None,
    *,
    eyebrow: str = "QyAi Control OS",
) -> str:
    content = body.strip()
    parts = [
        f"<b>TelegramGuard</b> · <code>{eyebrow}</code>",
        "",
        f"<blockquote><b>{title}</b>\n{content}</blockquote>",
    ]
    if footer:
        parts.extend(["", f"<i>{footer}</i>"])
    return "\n".join(parts)


def status_word(ok: bool, *, good: str = "ONLINE", bad: str = "ATTENTION") -> str:
    return f"{'🟢' if ok else '🟡'} <b>{good if ok else bad}</b>"


def compact_metrics(**values: object) -> str:
    return "   ".join(
        f"<b>{key.upper()}</b> <code>{value}</code>"
        for key, value in values.items()
    )
