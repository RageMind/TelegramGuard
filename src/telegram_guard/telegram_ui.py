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
    eyebrow: str = "QyAi",
) -> str:
    content = body.strip()
    parts = [
        f"<b>TelegramGuard</b> · <code>{eyebrow}</code>",
        "",
        f"<b>{title}</b>",
        content,
    ]
    if footer:
        parts.extend(["", f"<i>{footer}</i>"])
    return "\n".join(parts)


def _rich_table(
    rows: list[tuple[str, object]],
    *,
    columns: int,
) -> str:
    safe_rows = [
        (
            html.escape(str(label), quote=False),
            html.escape(str(value), quote=False),
        )
        for label, value in rows
    ]

    rendered: list[str] = ["<table compact striped>"]
    if columns == 2:
        for index in range(0, len(safe_rows), 2):
            left = safe_rows[index]
            right = safe_rows[index + 1] if index + 1 < len(safe_rows) else None
            cells = [
                f"<td><b>{left[0]}</b></td>",
                f"<td><code>{left[1]}</code></td>",
            ]
            if right is not None:
                cells.extend(
                    [
                        f"<td><b>{right[0]}</b></td>",
                        f"<td><code>{right[1]}</code></td>",
                    ]
                )
            rendered.append("<tr>" + "".join(cells) + "</tr>")
    else:
        for label, value in safe_rows:
            rendered.append(
                "<tr>"
                f"<td><b>{label}</b></td>"
                f"<td><code>{value}</code></td>"
                "</tr>"
            )
    rendered.append("</table>")
    return "\n".join(rendered)


def dashboard_screen(
    title: str,
    status: str,
    rows: list[tuple[str, object]],
    *,
    note: str | None = None,
    footer: str | None = None,
    columns: int = 1,
    details_title: str | None = None,
    details_text: str | None = None,
) -> TelegramView:
    if columns not in {1, 2}:
        raise ValueError("columns must be 1 or 2")

    safe_title = html.escape(title, quote=False)
    safe_status = html.escape(status, quote=False)

    fallback_lines = [f"<code>{safe_status}</code>"]
    for label, value in rows:
        fallback_lines.append(
            f"<b>{html.escape(str(label), quote=False)}</b>  "
            f"<code>{html.escape(str(value), quote=False)}</code>"
        )
    if note:
        fallback_lines.extend(["", html.escape(note, quote=False)])
    if details_text:
        fallback_lines.extend(
            [
                "",
                f"<b>{html.escape(details_title or 'Детали', quote=False)}</b>",
                f"<pre>{html.escape(details_text, quote=False)}</pre>",
            ]
        )

    safe_footer = html.escape(footer, quote=False) if footer else None
    fallback = screen(title, "\n".join(fallback_lines), safe_footer)

    rich_parts = [
        "<p><b>TelegramGuard</b> <code>QyAi</code></p>",
        "<hr/>",
        f"<p><b>{safe_title}</b><br/><code>{safe_status}</code></p>",
        _rich_table(rows, columns=columns),
    ]

    detail_blocks: list[str] = []
    if note:
        detail_blocks.append(
            f"<p>{html.escape(note, quote=False)}</p>"
        )
    if details_text:
        detail_blocks.append(
            f"<pre>{html.escape(details_text, quote=False)}</pre>"
        )
    if detail_blocks:
        summary = html.escape(details_title or "Детали", quote=False)
        rich_parts.append(
            f"<details><summary>{summary}</summary>"
            + "".join(detail_blocks)
            + "</details>"
        )

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
