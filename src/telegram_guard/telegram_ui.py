from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Any, Literal

ButtonStyle = Literal["primary", "success", "danger"]


@dataclass(frozen=True, slots=True)
class TelegramView:
    text: str
    rich_html: str


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


def dashboard_screen(
    title: str,
    status: str,
    rows: list[tuple[str, object]],
    *,
    note: str | None = None,
    footer: str | None = None,
) -> TelegramView:
    safe_title = html.escape(title, quote=False)
    safe_status = html.escape(status, quote=False)

    fallback_lines = [f"<b>{safe_status}</b>"]
    for label, value in rows:
        fallback_lines.append(
            f"<b>{html.escape(label, quote=False)}</b>  "
            f"<code>{html.escape(str(value), quote=False)}</code>"
        )
    if note:
        fallback_lines.extend(["", html.escape(note, quote=False)])

    safe_footer = html.escape(footer, quote=False) if footer else None
    fallback = screen(title, "\n".join(fallback_lines), safe_footer)

    cells = []
    for label, value in rows:
        cells.append(
            "<tr>"
            f"<td><b>{html.escape(label, quote=False)}</b></td>"
            f"<td><code>{html.escape(str(value), quote=False)}</code></td>"
            "</tr>"
        )

    rich_parts = [
        "<h3>TelegramGuard</h3>",
        "<p><code>QyAi Control OS</code></p>",
        "<hr/>",
        f"<h2>{safe_title}</h2>",
        f"<p><b>{safe_status}</b></p>",
        "<table bordered compact>",
        *cells,
        "</table>",
    ]
    if note:
        rich_parts.append(f"<p>{html.escape(note, quote=False)}</p>")
    if footer:
        rich_parts.append(
            f"<footer>{html.escape(footer, quote=False)}</footer>"
        )

    return TelegramView(
        text=fallback,
        rich_html="\n".join(rich_parts),
    )


def status_word(ok: bool, *, good: str = "ONLINE", bad: str = "ATTENTION") -> str:
    return f"{'🟢' if ok else '🟡'} <b>{good if ok else bad}</b>"


def compact_metrics(**values: object) -> str:
    return "   ".join(
        f"<b>{key.upper()}</b> <code>{value}</code>"
        for key, value in values.items()
    )
