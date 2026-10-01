from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import html
from typing import Any

from telegram_guard import BRAND, PROJECT_URL, __version__
from telegram_guard.config import BotConfig
from telegram_guard.helper_client import HelperClient, HelperError
from telegram_guard.security import (
    RateLimiter,
    ValidationError,
    bounded,
    format_ttl,
    parse_ip,
    parse_ttl,
    validate_unit,
)
from telegram_guard.state import StateStore
from telegram_guard.telegram_api import TelegramAPI, TelegramAPIError


def _safe(value: object) -> str:
    return html.escape(str(value), quote=False)


def _human_bytes(value: int) -> str:
    number = float(max(value, 0))
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if number < 1024 or suffix == "TiB":
            return f"{number:.1f} {suffix}"
        number /= 1024
    return f"{number:.1f} TiB"


def _uptime(seconds: int) -> str:
    minutes = max(seconds, 0) // 60
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}д")
    if hours:
        parts.append(f"{hours}ч")
    parts.append(f"{minutes}м")
    return " ".join(parts)


def _percent(used: int, total: int) -> int:
    if total <= 0:
        return 0
    return max(0, min(100, round((used / total) * 100)))


def _bar(percent: int, width: int = 10) -> str:
    filled = round((max(0, min(percent, 100)) / 100) * width)
    return "▓" * filled + "░" * (width - filled)


def _screen(title: str, body: str, footer: str | None = None) -> str:
    parts = [
        "🛡 <b>TelegramGuard</b>  <code>QyAi</code>",
        "━━━━━━━━━━━━━━━━",
        f"<b>{_safe(title)}</b>",
        body.strip(),
    ]
    if footer:
        parts.extend(["", f"<i>{_safe(footer)}</i>"])
    return "\n".join(part for part in parts if part != "")


def _code(value: object, limit: int = 2800) -> str:
    return f"<pre>{_safe(bounded(str(value), limit))}</pre>"


def _home_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "🖥 Система", "callback_data": "ui:status"},
                {"text": "🔐 Доступ", "callback_data": "ui:access"},
            ],
            [
                {"text": "🛡 Безопасность", "callback_data": "ui:security"},
                {"text": "⚙️ Сервисы", "callback_data": "ui:services"},
            ],
            [
                {"text": "📜 Журнал", "callback_data": "ui:audit"},
                {"text": "ℹ️ О системе", "callback_data": "ui:about"},
            ],
            [{"text": "↻ Обновить", "callback_data": "ui:home"}],
        ]
    }


def _back_keyboard(refresh: str | None = None) -> dict[str, Any]:
    row: list[dict[str, str]] = []
    if refresh:
        row.append({"text": "↻ Обновить", "callback_data": refresh})
    row.append({"text": "⌂ Главная", "callback_data": "ui:home"})
    return {"inline_keyboard": [row]}


def _status_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "👥 Сессии", "callback_data": "ui:sessions"},
                {"text": "🔎 SSH", "callback_data": "ui:ssh"},
            ],
            [
                {"text": "↻ Обновить", "callback_data": "ui:status"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ],
        ]
    }


def _access_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "＋ Разрешить IP", "callback_data": "ui:allow"},
                {"text": "− Удалить IP", "callback_data": "ui:revoke"},
            ],
            [
                {"text": "↻ Обновить", "callback_data": "ui:access"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ],
        ]
    }


def _security_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "🔎 SSH события", "callback_data": "ui:ssh"},
                {"text": "👥 Сессии", "callback_data": "ui:sessions"},
            ],
            [
                {"text": "📜 Аудит", "callback_data": "ui:audit"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ],
        ]
    }


def _service_fields(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key] = value
    return fields


def _status_body(result: dict[str, Any]) -> str:
    total = int(result.get("memory_total", 0))
    available = int(result.get("memory_available", 0))
    used = max(total - available, 0)
    disk_total = int(result.get("disk_total", 0))
    disk_free = int(result.get("disk_free", 0))
    disk_used = max(disk_total - disk_free, 0)

    ram_percent = _percent(used, total)
    disk_percent = _percent(disk_used, disk_total)
    worst = max(ram_percent, disk_percent)
    health = "🟢" if worst < 80 else "🟡" if worst < 92 else "🔴"

    return (
        f"{health} <b>Сервер работает</b>\n"
        f"⏱ Аптайм: <b>{_safe(_uptime(int(result.get('uptime_seconds', 0))))}</b>\n\n"
        f"<b>Оперативная память</b>\n"
        f"<code>{_bar(ram_percent)} {ram_percent}%</code>\n"
        f"{_safe(_human_bytes(used))} из {_safe(_human_bytes(total))}\n\n"
        f"<b>Диск</b>\n"
        f"<code>{_bar(disk_percent)} {disk_percent}%</code>\n"
        f"{_safe(_human_bytes(disk_used))} из {_safe(_human_bytes(disk_total))}\n\n"
        f"<b>Нагрузка</b>\n"
        f"<code>{_safe(result.get('load_1'))} · "
        f"{_safe(result.get('load_5'))} · {_safe(result.get('load_15'))}</code>\n"
        "<i>1 / 5 / 15 минут</i>"
    )


class BotApp:
    def __init__(self, config: BotConfig) -> None:
        self.config = config
        self.api = TelegramAPI(config.token)
        self.helper = HelperClient(config.helper_socket)
        self.state = StateStore(config.state_db)
        self.rate = RateLimiter(config.rate_limit_per_minute)
        self.input_modes: dict[int, str] = {}

    def _is_admin(self, user_id: int) -> bool:
        return user_id in self.config.admin_ids

    async def _show(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any],
        message_id: int | None = None,
    ) -> None:
        if message_id is None:
            await self.api.send_message(chat_id, text, reply_markup)
            return
        await self.api.edit_message_text(chat_id, message_id, text, reply_markup)

    async def _show_home(
        self, chat_id: int, message_id: int | None = None
    ) -> None:
        try:
            result = await self.helper.call("host.status")
            if not isinstance(result, dict):
                raise HelperError("invalid status response")
            total = int(result.get("memory_total", 0))
            available = int(result.get("memory_available", 0))
            used = max(total - available, 0)
            disk_total = int(result.get("disk_total", 0))
            disk_free = int(result.get("disk_free", 0))
            disk_used = max(disk_total - disk_free, 0)
            ram = _percent(used, total)
            disk = _percent(disk_used, disk_total)
            firewall = await self.helper.call("firewall.health")
            firewall_active = (
                isinstance(firewall, dict)
                and firewall.get("mode") == "nft"
                and bool(firewall.get("active"))
            )
            firewall_text = (
                "🟢 SSH whitelist активен"
                if firewall_active
                else "🟡 SSH whitelist не активен"
            )
            body = (
                "🟢 <b>VPS на связи</b>\n"
                f"⏱ {_safe(_uptime(int(result.get('uptime_seconds', 0))))}\n"
                f"RAM <code>{ram}%</code>   ·   Диск <code>{disk}%</code>\n"
                f"{firewall_text}\n\n"
                "Выберите раздел. Все опасные действия требуют подтверждения."
            )
        except HelperError:
            body = (
                "🟠 <b>Панель доступна, helper не отвечает</b>\n\n"
                "Откройте «Система» после восстановления локального helper."
            )

        await self._show(
            chat_id,
            _screen("Центр управления", body, "Private control plane"),
            _home_keyboard(),
            message_id,
        )

    async def _show_status(
        self, chat_id: int, admin_id: int, message_id: int | None = None
    ) -> None:
        result = await self.helper.call("host.status")
        if not isinstance(result, dict):
            raise HelperError("invalid status response")
        self.state.audit(admin_id, "host.status", "ok")
        await self._show(
            chat_id,
            _screen("Система", _status_body(result)),
            _status_keyboard(),
            message_id,
        )

    async def _show_access(
        self, chat_id: int, admin_id: int, message_id: int | None = None
    ) -> None:
        health = await self.helper.call("firewall.health")
        result = await self.helper.call("firewall.list")
        self.state.audit(admin_id, "firewall.list", "ok")
        raw = str(result)

        active = (
            isinstance(health, dict)
            and health.get("mode") == "nft"
            and bool(health.get("active"))
        )
        port = (
            str(health.get("ssh_port"))
            if isinstance(health, dict)
            else "—"
        )
        entries = (
            int(health.get("entries", 0))
            if isinstance(health, dict)
            else 0
        )

        if active:
            body = (
                "🟢 <b>SSH whitelist активен</b>\n"
                f"Порт: <code>{_safe(port)}</code>\n"
                f"Доверенных адресов: <b>{entries}</b>\n\n"
                "Временный доступ истекает автоматически.\n\n"
                f"{_code(raw, 1900)}"
            )
        else:
            mode = (
                str(health.get("mode", "unknown"))
                if isinstance(health, dict)
                else "unknown"
            )
            body = (
                "🟡 <b>SSH whitelist не активен</b>\n"
                f"Режим: <code>{_safe(mode)}</code>\n"
                f"SSH-порт: <code>{_safe(port)}</code>\n\n"
                "На этом сервере TelegramGuard сейчас не ограничивает SSH. "
                "После повторного запуска установщика из активной SSH-сессии "
                "текущий IP будет закреплён и managed whitelist включится автоматически."
            )

        await self._show(
            chat_id,
            _screen("Доступ к VPS", body),
            _access_keyboard(),
            message_id,
        )

    async def _show_security(
        self, chat_id: int, message_id: int | None = None
    ) -> None:
        body = (
            "🟢 <b>Контур управления активен</b>\n\n"
            "🔒 Команды принимаются только в личном чате\n"
            "🧩 Privileged helper отделён от Telegram-бота\n"
            "✅ Опасные действия подтверждаются отдельно\n"
            "📝 Административные действия пишутся в аудит\n\n"
            "Выберите, что проверить."
        )
        await self._show(
            chat_id,
            _screen("Безопасность", body),
            _security_keyboard(),
            message_id,
        )

    async def _show_sessions(
        self, chat_id: int, admin_id: int, message_id: int | None = None
    ) -> None:
        result = await self.helper.call("host.sessions")
        self.state.audit(admin_id, "host.sessions", "ok")
        raw = str(result).strip()
        if not raw or raw == "No interactive sessions.":
            body = "🟢 <b>Интерактивных сессий нет</b>"
        else:
            body = "👥 <b>Активные сессии</b>\n\n" + _code(raw, 2500)
        await self._show(
            chat_id,
            _screen("Входы в систему", body),
            _back_keyboard("ui:sessions"),
            message_id,
        )

    async def _show_ssh(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
        minutes: int = 30,
    ) -> None:
        result = await self.helper.call("ssh.recent", {"minutes": minutes})
        self.state.audit(admin_id, "ssh.recent", "ok", {"minutes": minutes})
        raw = str(result).strip()
        body = (
            f"🔎 <b>Последние {minutes} минут</b>\n\n"
            f"{_code(raw or 'Событий нет.', 2800)}"
        )
        await self._show(
            chat_id,
            _screen("SSH события", body),
            _back_keyboard("ui:ssh"),
            message_id,
        )

    async def _show_services(
        self, chat_id: int, admin_id: int, message_id: int | None = None
    ) -> None:
        result = await self.helper.call("service.list")
        units = result if isinstance(result, list) else []
        self.state.audit(admin_id, "service.list", "ok")

        if units:
            body = (
                f"⚙️ <b>Под управлением: {len(units)}</b>\n\n"
                "Нажмите сервис, чтобы увидеть его состояние."
            )
        else:
            body = "🟡 <b>Управляемые сервисы не настроены</b>"

        rows: list[list[dict[str, str]]] = []
        for unit in units[:12]:
            label = str(unit)
            rows.append(
                [{"text": f"⚙️ {label}", "callback_data": f"svc:{label}"}]
            )
        rows.append(
            [
                {"text": "↻ Обновить", "callback_data": "ui:services"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ]
        )
        await self._show(
            chat_id,
            _screen("Сервисы", body),
            {"inline_keyboard": rows},
            message_id,
        )

    async def _show_service(
        self,
        chat_id: int,
        admin_id: int,
        unit: str,
        message_id: int | None = None,
    ) -> None:
        unit = validate_unit(unit)
        result = await self.helper.call("service.status", {"unit": unit})
        self.state.audit(admin_id, "service.status", "ok", {"unit": unit})

        fields = _service_fields(str(result))
        active = fields.get("ActiveState", "unknown")
        sub = fields.get("SubState", "unknown")
        icon = "🟢" if active == "active" else "🔴" if active == "failed" else "🟡"
        description = fields.get("Description", unit)

        body = (
            f"{icon} <b>{_safe(description)}</b>\n"
            f"Состояние: <code>{_safe(active)}</code> / <code>{_safe(sub)}</code>\n"
            f"Unit: <code>{_safe(unit)}</code>"
        )
        keyboard = {
            "inline_keyboard": [
                [{"text": "↻ Перезапустить", "callback_data": f"restart:{unit}"}],
                [
                    {"text": "← Сервисы", "callback_data": "ui:services"},
                    {"text": "⌂ Главная", "callback_data": "ui:home"},
                ],
            ]
        }
        await self._show(
            chat_id,
            _screen("Сервис", body),
            keyboard,
            message_id,
        )

    async def _show_audit(
        self, chat_id: int, message_id: int | None = None
    ) -> None:
        rows = self.state.recent_audit(12)
        if not rows:
            body = "🟢 <b>Журнал пока пуст</b>"
        else:
            lines: list[str] = []
            icons = {
                "ok": "✓",
                "confirmed": "✓",
                "pending": "…",
                "denied": "×",
                "error": "!",
                "helper_error": "!",
                "cancelled": "−",
            }
            for row in rows:
                stamp = dt.datetime.fromtimestamp(
                    int(row["created_at"]), tz=dt.UTC
                ).strftime("%H:%M")
                outcome = str(row["outcome"])
                icon = icons.get(outcome, "·")
                lines.append(
                    f"<code>{_safe(stamp)}</code>  {icon}  "
                    f"{_safe(row['action'])}  <i>{_safe(outcome)}</i>"
                )
            body = "📝 <b>Последние действия</b>\n\n" + "\n".join(lines)
        await self._show(
            chat_id,
            _screen("Журнал", body),
            _back_keyboard("ui:audit"),
            message_id,
        )

    async def _show_about(
        self, chat_id: int, message_id: int | None = None
    ) -> None:
        body = (
            f"<b>TelegramGuard {_safe(__version__)}</b>\n"
            "QyAi VPS Control\n\n"
            "Модель доступа: <code>private chat only</code>\n"
            "Привилегии: <code>split helper</code>\n"
            "Проект: <code>RageMind/TelegramGuard</code>\n\n"
            f"{_safe(PROJECT_URL)}"
        )
        await self._show(
            chat_id,
            _screen("О системе", body, "QyAi · TelegramGuard"),
            _back_keyboard(),
            message_id,
        )

    async def _show_input(
        self,
        chat_id: int,
        admin_id: int,
        mode: str,
        message_id: int | None = None,
    ) -> None:
        self.input_modes[admin_id] = mode
        if mode == "allow":
            body = (
                "Отправьте IP и, при желании, срок доступа.\n\n"
                "<b>Пример</b>\n"
                "<code>203.0.113.42 1h</code>\n\n"
                "Срок по умолчанию: <b>1 час</b>. Максимум: <b>7 дней</b>."
            )
            title = "Разрешить IP"
        else:
            body = (
                "Отправьте IP, который нужно убрать из whitelist.\n\n"
                "<b>Пример</b>\n"
                "<code>203.0.113.42</code>"
            )
            title = "Удалить IP"
        keyboard = {
            "inline_keyboard": [
                [{"text": "Отмена", "callback_data": "ui:access"}]
            ]
        }
        await self._show(
            chat_id,
            _screen(title, body, "Следующее сообщение будет обработано как ввод"),
            keyboard,
            message_id,
        )

    async def _confirmed_request(
        self,
        chat_id: int,
        admin_id: int,
        action: str,
        args: dict[str, Any],
        description: str,
        message_id: int | None = None,
    ) -> None:
        token = self.state.create_pending(admin_id, action, args)
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✓ Подтвердить", "callback_data": f"confirm:{token}"},
                    {"text": "Отмена", "callback_data": f"cancel:{token}"},
                ]
            ]
        }
        self.state.audit(admin_id, action, "pending", args)
        body = (
            "⚠️ <b>Требуется подтверждение</b>\n\n"
            f"{_safe(description)}\n\n"
            "Действие действительно 90 секунд."
        )
        await self._show(
            chat_id,
            _screen("Подтверждение", body),
            keyboard,
            message_id,
        )

    async def _execute_pending(
        self,
        chat_id: int,
        message_id: int,
        admin_id: int,
        token: str,
    ) -> None:
        pending = self.state.consume_pending(token, admin_id)
        if pending is None:
            await self._show(
                chat_id,
                _screen(
                    "Подтверждение устарело",
                    "🟡 Действие уже использовано или истекло.",
                ),
                _back_keyboard(),
                message_id,
            )
            return

        action, args = pending
        result = await self.helper.call(action, args)
        self.state.audit(admin_id, action, "confirmed", args)

        if action == "firewall.allow":
            body = (
                "🟢 <b>Доступ выдан</b>\n"
                f"IP: <code>{_safe(args['ip'])}</code>\n"
                f"Срок: <b>{_safe(format_ttl(int(args['ttl_seconds'])))}</b>"
            )
            keyboard = _access_keyboard()
        elif action == "firewall.revoke":
            removed = bool(result.get("removed")) if isinstance(result, dict) else False
            state = "удалён" if removed else "уже отсутствовал"
            body = (
                "🟢 <b>Whitelist обновлён</b>\n"
                f"IP <code>{_safe(args['ip'])}</code> {state}."
            )
            keyboard = _access_keyboard()
        elif action == "service.restart":
            body = (
                "🟢 <b>Сервис перезапущен</b>\n"
                f"<code>{_safe(args['unit'])}</code>"
            )
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "Открыть сервис",
                            "callback_data": f"svc:{args['unit']}",
                        }
                    ],
                    [{"text": "⌂ Главная", "callback_data": "ui:home"}],
                ]
            }
        else:
            body = "🟢 <b>Действие выполнено</b>"
            keyboard = _back_keyboard()

        await self._show(
            chat_id,
            _screen("Готово", body),
            keyboard,
            message_id,
        )

    async def _handle_callback(
        self,
        chat_id: int,
        message_id: int,
        admin_id: int,
        data: str,
    ) -> None:
        self.input_modes.pop(admin_id, None)

        if data == "ui:home":
            await self._show_home(chat_id, message_id)
        elif data == "ui:status":
            await self._show_status(chat_id, admin_id, message_id)
        elif data == "ui:access":
            await self._show_access(chat_id, admin_id, message_id)
        elif data == "ui:security":
            await self._show_security(chat_id, message_id)
        elif data == "ui:sessions":
            await self._show_sessions(chat_id, admin_id, message_id)
        elif data == "ui:ssh":
            await self._show_ssh(chat_id, admin_id, message_id)
        elif data == "ui:services":
            await self._show_services(chat_id, admin_id, message_id)
        elif data == "ui:audit":
            await self._show_audit(chat_id, message_id)
        elif data == "ui:about":
            await self._show_about(chat_id, message_id)
        elif data == "ui:allow":
            await self._show_input(chat_id, admin_id, "allow", message_id)
        elif data == "ui:revoke":
            await self._show_input(chat_id, admin_id, "revoke", message_id)
        elif data.startswith("svc:"):
            await self._show_service(chat_id, admin_id, data[4:], message_id)
        elif data.startswith("restart:"):
            unit = validate_unit(data.split(":", 1)[1])
            managed = await self.helper.call("service.list")
            if not isinstance(managed, list) or unit not in managed:
                raise ValidationError("service is not managed")
            await self._confirmed_request(
                chat_id,
                admin_id,
                "service.restart",
                {"unit": unit},
                f"Перезапустить {unit}?",
                message_id,
            )
        elif data.startswith("confirm:"):
            token = data.split(":", 1)[1]
            await self._execute_pending(chat_id, message_id, admin_id, token)
        elif data.startswith("cancel:"):
            token = data.split(":", 1)[1]
            self.state.consume_pending(token, admin_id)
            self.state.audit(admin_id, "confirmation", "cancelled")
            await self._show_home(chat_id, message_id)

    async def _handle_text_input(
        self, chat_id: int, admin_id: int, text: str
    ) -> bool:
        mode = self.input_modes.get(admin_id)
        if mode is None:
            return False

        try:
            if mode == "allow":
                parts = text.split()
                if not 1 <= len(parts) <= 2:
                    raise ValidationError("нужно: IP и необязательно TTL")
                address = parse_ip(parts[0])
                ttl = parse_ttl(parts[1] if len(parts) == 2 else "1h")
                self.input_modes.pop(admin_id, None)
                await self._confirmed_request(
                    chat_id,
                    admin_id,
                    "firewall.allow",
                    {"ip": str(address), "ttl_seconds": ttl},
                    f"Разрешить {address} на {format_ttl(ttl)}?",
                )
                return True

            if mode == "revoke":
                parts = text.split()
                if len(parts) != 1:
                    raise ValidationError("нужен только один IP")
                address = parse_ip(parts[0])
                self.input_modes.pop(admin_id, None)
                await self._confirmed_request(
                    chat_id,
                    admin_id,
                    "firewall.revoke",
                    {"ip": str(address)},
                    f"Удалить {address} из whitelist?",
                )
                return True
        except ValidationError as exc:
            await self.api.send_message(
                chat_id,
                _screen(
                    "Не понял ввод",
                    f"🔴 {_safe(exc)}\n\nПопробуйте ещё раз или нажмите /start.",
                ),
                _back_keyboard(),
            )
            return True

        return False

    async def _read_command(
        self, chat_id: int, admin_id: int, command: str, args: list[str]
    ) -> None:
        self.input_modes.pop(admin_id, None)

        if command in {"/start", "/help", "/dashboard", "/menu", "/panel"}:
            await self._show_home(chat_id)
            return
        if command == "/status":
            await self._show_status(chat_id, admin_id)
            return
        if command == "/sessions":
            await self._show_sessions(chat_id, admin_id)
            return
        if command == "/ssh":
            minutes = 30
            if args:
                if not args[0].isdigit():
                    raise ValidationError("minutes must be numeric")
                minutes = max(1, min(int(args[0]), 180))
            await self._show_ssh(chat_id, admin_id, minutes=minutes)
            return
        if command == "/whitelist":
            await self._show_access(chat_id, admin_id)
            return
        if command == "/allow":
            if not args:
                await self._show_input(chat_id, admin_id, "allow")
                return
            address = parse_ip(args[0])
            ttl = parse_ttl(args[1] if len(args) > 1 else "1h")
            await self._confirmed_request(
                chat_id,
                admin_id,
                "firewall.allow",
                {"ip": str(address), "ttl_seconds": ttl},
                f"Разрешить {address} на {format_ttl(ttl)}?",
            )
            return
        if command == "/revoke":
            if not args:
                await self._show_input(chat_id, admin_id, "revoke")
                return
            if len(args) != 1:
                raise ValidationError("usage: /revoke <ip>")
            address = parse_ip(args[0])
            await self._confirmed_request(
                chat_id,
                admin_id,
                "firewall.revoke",
                {"ip": str(address)},
                f"Удалить {address} из whitelist?",
            )
            return
        if command == "/services":
            await self._show_services(chat_id, admin_id)
            return
        if command == "/service":
            if len(args) != 1:
                raise ValidationError("usage: /service <unit>")
            await self._show_service(chat_id, admin_id, args[0])
            return
        if command == "/restart":
            if len(args) != 1:
                raise ValidationError("usage: /restart <unit>")
            unit = validate_unit(args[0])
            managed = await self.helper.call("service.list")
            if not isinstance(managed, list) or unit not in managed:
                raise ValidationError("service is not managed")
            await self._confirmed_request(
                chat_id,
                admin_id,
                "service.restart",
                {"unit": unit},
                f"Перезапустить {unit}?",
            )
            return
        if command == "/audit":
            await self._show_audit(chat_id)
            return
        if command == "/version":
            await self._show_about(chat_id)
            return
        if command == "/cancel":
            self.input_modes.pop(admin_id, None)
            await self._show_home(chat_id)
            return

        raise ValidationError("неизвестная команда; откройте /start")

    async def handle_update(self, update: dict[str, Any]) -> None:
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            user = callback.get("from", {})
            user_id = int(user.get("id", 0)) if isinstance(user, dict) else 0
            callback_id = str(callback.get("id", ""))
            if not self._is_admin(user_id):
                if callback_id:
                    await self.api.answer_callback(callback_id, "Нет доступа")
                return
            if not self.rate.allow(user_id):
                await self.api.answer_callback(callback_id, "Слишком часто")
                return

            message = callback.get("message", {})
            chat = message.get("chat", {}) if isinstance(message, dict) else {}
            chat_id = int(chat.get("id", 0)) if isinstance(chat, dict) else 0
            chat_type = str(chat.get("type", "")) if isinstance(chat, dict) else ""
            message_id = (
                int(message.get("message_id", 0))
                if isinstance(message, dict)
                else 0
            )
            if chat_type != "private" or not chat_id or not message_id:
                await self.api.answer_callback(callback_id, "Только личный чат")
                return

            await self.api.answer_callback(callback_id)
            data = str(callback.get("data", ""))
            try:
                await self._handle_callback(chat_id, message_id, user_id, data)
            except (ValidationError, HelperError) as exc:
                await self._show(
                    chat_id,
                    _screen("Не выполнено", f"🔴 {_safe(exc)}"),
                    _back_keyboard(),
                    message_id,
                )
            return

        message = update.get("message")
        if not isinstance(message, dict):
            return

        user = message.get("from", {})
        chat = message.get("chat", {})
        user_id = int(user.get("id", 0)) if isinstance(user, dict) else 0
        chat_id = int(chat.get("id", 0)) if isinstance(chat, dict) else 0
        chat_type = str(chat.get("type", "")) if isinstance(chat, dict) else ""

        if chat_type != "private":
            return
        if not self._is_admin(user_id) or not chat_id:
            return
        if not self.rate.allow(user_id):
            await self.api.send_message(
                chat_id,
                _screen("Слишком часто", "🟡 Подождите немного и повторите."),
                _back_keyboard(),
            )
            return

        text = str(message.get("text", "")).strip()
        if not text:
            return

        if not text.startswith("/"):
            handled = await self._handle_text_input(chat_id, user_id, text)
            if not handled:
                await self._show_home(chat_id)
            return

        first, *args = text.split()
        command = first.split("@", 1)[0].lower()

        try:
            await self._read_command(chat_id, user_id, command, args)
        except ValidationError as exc:
            self.state.audit(
                user_id,
                command.lstrip("/"),
                "denied",
                {"reason": str(exc)},
            )
            await self.api.send_message(
                chat_id,
                _screen("Не выполнено", f"🔴 {_safe(exc)}"),
                _back_keyboard(),
            )
        except HelperError:
            self.state.audit(user_id, command.lstrip("/"), "helper_error")
            await self.api.send_message(
                chat_id,
                _screen(
                    "Система недоступна",
                    "🔴 Локальный privileged helper не отвечает.",
                ),
                _back_keyboard(),
            )
        except Exception:
            self.state.audit(user_id, command.lstrip("/"), "error")
            await self.api.send_message(
                chat_id,
                _screen(
                    "Ошибка",
                    "🔴 Действие не выполнено. Детали оставлены в локальном журнале.",
                ),
                _back_keyboard(),
            )

    async def run(self) -> None:
        with contextlib.suppress(TelegramAPIError):
            await self.api.configure_profile()

        offset: int | None = None
        print(f"{BRAND}: dashboard bot started", flush=True)
        try:
            while True:
                try:
                    updates = await self.api.get_updates(
                        offset, self.config.poll_timeout
                    )
                    for update in updates:
                        update_id = update.get("update_id")
                        if isinstance(update_id, int):
                            offset = update_id + 1
                        await self.handle_update(update)
                except TelegramAPIError:
                    await asyncio.sleep(3)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    await asyncio.sleep(2)
        finally:
            await self.api.close()


def main() -> None:
    config = BotConfig.from_env()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(BotApp(config).run())


if __name__ == "__main__":
    main()
