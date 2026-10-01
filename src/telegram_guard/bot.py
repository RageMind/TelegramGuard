from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import html
import sys
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


def _remaining(seconds: int | None) -> str:
    if seconds is None:
        return "без срока"
    seconds = max(0, seconds)
    if seconds >= 86400:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}д {hours}ч" if hours else f"{days}д"
    if seconds >= 3600:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}ч {minutes}м" if minutes else f"{hours}ч"
    return f"{max(1, seconds // 60)}м"


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
                {"text": "🧩 Сервисы", "callback_data": "ui:services"},
            ],
            [
                {"text": "📜 Активность", "callback_data": "ui:audit"},
                {"text": "⚙️ Настройки", "callback_data": "ui:settings"},
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
                {"text": "↻ Обновить", "callback_data": "ui:security"},
                {"text": "📜 Аудит", "callback_data": "ui:audit"},
            ],
            [{"text": "⌂ Главная", "callback_data": "ui:home"}],
        ]
    }


def _settings_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "🧪 Самопроверка", "callback_data": "ui:selftest"}],
            [
                {"text": "ℹ️ О системе", "callback_data": "ui:about"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ],
        ]
    }


def _ttl_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "15 минут", "callback_data": "ttl:900"},
                {"text": "1 час", "callback_data": "ttl:3600"},
            ],
            [
                {"text": "8 часов", "callback_data": "ttl:28800"},
                {"text": "1 день", "callback_data": "ttl:86400"},
            ],
            [
                {"text": "7 дней", "callback_data": "ttl:604800"},
                {"text": "Свой срок", "callback_data": "ttl:custom"},
            ],
            [{"text": "Отмена", "callback_data": "ui:access"}],
        ]
    }


_ACTION_LABELS: dict[str, str] = {
    "host.status": "Система проверена",
    "host.sessions": "Сессии просмотрены",
    "ssh.recent": "SSH-события просмотрены",
    "security.summary": "Безопасность проверена",
    "firewall.list": "Whitelist просмотрен",
    "firewall.snapshot": "Доступ просмотрен",
    "firewall.allow": "Доступ выдан",
    "firewall.extend": "Доступ продлён",
    "firewall.revoke": "Доступ отозван",
    "service.list": "Сервисы просмотрены",
    "service.status": "Сервис проверен",
    "service.logs": "Логи сервиса просмотрены",
    "service.restart": "Сервис перезапущен",
    "settings.view": "Настройки открыты",
    "selftest": "Самопроверка выполнена",
    "confirmation": "Действие отменено",
}

_OUTCOME_LABELS: dict[str, str] = {
    "ok": "готово",
    "confirmed": "выполнено",
    "pending": "ожидает подтверждения",
    "denied": "отклонено",
    "error": "ошибка",
    "helper_error": "helper недоступен",
    "cancelled": "отменено",
    "attention": "требует внимания",
}


def _service_token(unit: str) -> str:
    return hashlib.sha256(unit.encode("utf-8")).hexdigest()[:12]


def _audit_target(details: object) -> str:
    if not isinstance(details, dict):
        return ""
    for key in ("ip", "unit"):
        value = details.get(key)
        if value:
            return f" · {_safe(value)}"
    return ""


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
        self.wizard: dict[int, dict[str, Any]] = {}
        self.alert_state: dict[str, bool] = {}

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
            firewall = await self.helper.call("firewall.health")
            services = await self.helper.call("service.list")
            ssh = await self.helper.call("ssh.summary", {"minutes": 15})
            if not isinstance(result, dict) or not isinstance(firewall, dict):
                raise HelperError("invalid control-plane status")

            total = int(result.get("memory_total", 0))
            available = int(result.get("memory_available", 0))
            used = max(total - available, 0)
            disk_total = int(result.get("disk_total", 0))
            disk_free = int(result.get("disk_free", 0))
            disk_used = max(disk_total - disk_free, 0)
            ram = _percent(used, total)
            disk = _percent(disk_used, disk_total)

            firewall_active = (
                firewall.get("mode") == "nft"
                and bool(firewall.get("active"))
            )
            units = services if isinstance(services, list) else []
            ssh_failed = (
                int(ssh.get("failed", 0))
                if isinstance(ssh, dict)
                else 0
            )
            attention = 0
            if not firewall_active:
                attention += 1
            if ssh_failed >= self.config.ssh_failed_alert_threshold:
                attention += 1

            last_rows = self.state.recent_audit(1)
            last_action = "нет действий"
            if last_rows:
                last = last_rows[0]
                action = str(last.get("action", ""))
                outcome = str(last.get("outcome", ""))
                label = _ACTION_LABELS.get(action, action)
                outcome_label = _OUTCOME_LABELS.get(outcome, outcome)
                last_action = f"{label} · {outcome_label}"

            body = (
                "🟢 <b>VPS на связи</b>\n"
                f"⏱ {_safe(_uptime(int(result.get('uptime_seconds', 0))))}\n"
                f"RAM <code>{ram}%</code>   ·   Диск <code>{disk}%</code>\n"
                f"{'🟢' if firewall_active else '🟡'} SSH whitelist: "
                f"<b>{'активен' if firewall_active else 'не активен'}</b>\n"
                f"🧩 Сервисов под контролем: <b>{len(units)}</b>\n"
                f"{'🟢' if attention == 0 else '🟡'} Требует внимания: "
                f"<b>{attention}</b>\n\n"
                f"<i>Последнее: {_safe(last_action)}</i>"
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
        snapshot = await self.helper.call("firewall.snapshot")
        self.state.audit(admin_id, "firewall.snapshot", "ok")
        if not isinstance(snapshot, dict):
            raise HelperError("invalid firewall snapshot")

        active = snapshot.get("mode") == "nft" and bool(snapshot.get("active"))
        port = int(snapshot.get("ssh_port", 0))
        raw_entries = snapshot.get("entries", [])
        entries = raw_entries if isinstance(raw_entries, list) else []

        rows: list[list[dict[str, str]]] = []
        if active:
            body_lines = [
                "🟢 <b>SSH whitelist активен</b>",
                f"Порт: <code>{port}</code>",
                f"Доверенных адресов: <b>{len(entries)}</b>",
                "",
                "<b>Доступ</b>",
            ]
            if not entries:
                body_lines.append("Записей пока нет.")
            for item in entries[:12]:
                if not isinstance(item, dict):
                    continue
                ip_value = str(item.get("ip", ""))
                protected = bool(item.get("protected"))
                remaining = item.get("remaining_seconds")
                remaining_value = int(remaining) if isinstance(remaining, int) else None
                state = "защищён" if protected else _remaining(remaining_value)
                icon = "🔒" if protected else "⏱"
                body_lines.append(
                    f"{icon} <code>{_safe(ip_value)}</code> · {_safe(state)}"
                )
                rows.append(
                    [
                        {
                            "text": f"{icon} {ip_value} · {state}",
                            "callback_data": f"acl:{ip_value}",
                        }
                    ]
                )
            body = "\n".join(body_lines)
            rows.append(
                [{"text": "＋ Выдать доступ", "callback_data": "ui:allow"}]
            )
        else:
            mode = str(snapshot.get("mode", "unknown"))
            body = (
                "🟡 <b>SSH whitelist не активен</b>\n"
                f"Режим: <code>{_safe(mode)}</code>\n"
                f"SSH-порт: <code>{port or '—'}</code>\n\n"
                "TelegramGuard не ограничивает SSH в этом состоянии. "
                "Запустите установщик повторно из активной SSH-сессии: "
                "он закрепит текущий IP и включит managed whitelist."
            )

        rows.append(
            [
                {"text": "↻ Обновить", "callback_data": "ui:access"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ]
        )
        await self._show(
            chat_id,
            _screen("Доступ к VPS", body),
            {"inline_keyboard": rows},
            message_id,
        )

    async def _show_access_entry(
        self,
        chat_id: int,
        admin_id: int,
        ip_value: str,
        message_id: int | None = None,
    ) -> None:
        address = str(parse_ip(ip_value))
        snapshot = await self.helper.call("firewall.snapshot")
        if not isinstance(snapshot, dict):
            raise HelperError("invalid firewall snapshot")
        raw_entries = snapshot.get("entries", [])
        entries = raw_entries if isinstance(raw_entries, list) else []
        item = next(
            (
                entry
                for entry in entries
                if isinstance(entry, dict) and str(entry.get("ip")) == address
            ),
            None,
        )
        if item is None:
            raise ValidationError("этого адреса уже нет в whitelist")

        protected = bool(item.get("protected"))
        permanent = bool(item.get("permanent"))
        remaining = item.get("remaining_seconds")
        remaining_value = int(remaining) if isinstance(remaining, int) else None
        source = str(item.get("source", "telegram"))
        if protected:
            entry_type = "bootstrap / защищён"
        elif permanent:
            entry_type = "постоянный"
        else:
            entry_type = "временный"

        body = (
            f"<b><code>{_safe(address)}</code></b>\n\n"
            f"Тип: {entry_type}\n"
            f"Осталось: <b>{_safe(_remaining(remaining_value))}</b>\n"
            f"Источник: <code>{_safe(source)}</code>"
        )

        rows: list[list[dict[str, str]]] = []
        if not permanent:
            rows.append(
                [
                    {
                        "text": "＋1 час",
                        "callback_data": f"ext1:{address}",
                    },
                    {
                        "text": "＋1 день",
                        "callback_data": f"extd:{address}",
                    },
                ]
            )
        if not protected:
            rows.append(
                [{"text": "− Отозвать доступ", "callback_data": f"rvk:{address}"}]
            )
        rows.append(
            [
                {"text": "← Доступ", "callback_data": "ui:access"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ]
        )
        await self._show(
            chat_id,
            _screen("Запись доступа", body),
            {"inline_keyboard": rows},
            message_id,
        )

    async def _show_security(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
    ) -> None:
        summary = await self.helper.call("ssh.summary", {"minutes": 60})
        sessions = await self.helper.call("host.sessions")
        firewall = await self.helper.call("firewall.health")
        if not isinstance(summary, dict) or not isinstance(firewall, dict):
            raise HelperError("invalid security status")

        raw_sessions = str(sessions).strip()
        session_count = (
            0
            if not raw_sessions or raw_sessions == "No interactive sessions."
            else len([line for line in raw_sessions.splitlines() if line.strip()])
        )
        firewall_ok = firewall.get("mode") == "nft" and bool(firewall.get("active"))
        failed = int(summary.get("failed", 0))
        invalid = int(summary.get("invalid_user", 0))
        accepted = int(summary.get("accepted", 0))
        icon = "🟢" if firewall_ok and failed < 10 else "🟡"

        body = (
            f"{icon} <b>Контур безопасности</b>\n\n"
            f"{'🟢' if firewall_ok else '🟡'} SSH whitelist: "
            f"<b>{'активен' if firewall_ok else 'не активен'}</b>\n"
            f"👥 Активных сессий: <b>{session_count}</b>\n"
            f"✓ Успешных SSH-входов за час: <b>{accepted}</b>\n"
            f"⚠ Неудачных попыток за час: <b>{failed}</b>\n"
            f"⚠ Invalid user за час: <b>{invalid}</b>\n\n"
            "Команды принимаются только в личном чате, "
            "а привилегированные действия выполняет отдельный helper."
        )
        self.state.audit(admin_id, "security.summary", "ok")
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
            label = validate_unit(str(unit))
            token = _service_token(label)
            rows.append(
                [{"text": f"⚙️ {label}", "callback_data": f"svc:{token}"}]
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
        token = _service_token(unit)
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "📄 Логи", "callback_data": f"logs:{token}"},
                    {"text": "↻ Перезапустить", "callback_data": f"restart:{token}"},
                ],
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

    async def _show_service_logs(
        self,
        chat_id: int,
        admin_id: int,
        unit: str,
        message_id: int | None = None,
    ) -> None:
        unit = validate_unit(unit)
        result = await self.helper.call("service.logs", {"unit": unit, "lines": 40})
        self.state.audit(admin_id, "service.logs", "ok", {"unit": unit})
        body = (
            f"<b><code>{_safe(unit)}</code></b>\n\n"
            f"{_code(str(result), 3000)}"
        )
        token = _service_token(unit)
        keyboard = {
            "inline_keyboard": [
                [{"text": "↻ Обновить", "callback_data": f"logs:{token}"}],
                [
                    {"text": "← Сервис", "callback_data": f"svc:{token}"},
                    {"text": "⌂ Главная", "callback_data": "ui:home"},
                ],
            ]
        }
        await self._show(
            chat_id,
            _screen("Последние логи", body),
            keyboard,
            message_id,
        )

    async def _show_settings(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
    ) -> None:
        firewall = await self.helper.call("firewall.health")
        services = await self.helper.call("service.list")
        if not isinstance(firewall, dict):
            raise HelperError("invalid firewall health")
        units = services if isinstance(services, list) else []
        active = firewall.get("mode") == "nft" and bool(firewall.get("active"))
        firewall_label = (
            "🟢 managed"
            if active
            else "🟡 " + _safe(firewall.get("mode", "unknown"))
        )
        body = (
            f"<b>TelegramGuard {_safe(__version__)}</b>\n\n"
            f"Firewall: {firewall_label}\n"
            f"SSH-порт: <code>{_safe(firewall.get('ssh_port', '—'))}</code>\n"
            f"Управляемых сервисов: <b>{len(units)}</b>\n"
            f"Проверка здоровья: <b>{self.config.alert_interval_seconds}с</b>\n"
            f"SSH alert: <b>{self.config.ssh_failed_alert_threshold}+ ошибок</b>\n"
            "Режим управления: <code>private chat only</code>\n\n"
            "Изменение системных параметров выполняется только через "
            "локальную конфигурацию VPS. В Telegram доступны безопасные операции."
        )
        self.state.audit(admin_id, "settings.view", "ok")
        await self._show(
            chat_id,
            _screen("Настройки", body),
            _settings_keyboard(),
            message_id,
        )

    async def _show_self_test(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
    ) -> None:
        checks: list[tuple[str, bool, str]] = []

        try:
            status = await self.helper.call("host.status")
            checks.append(("Helper", isinstance(status, dict), "локальный control plane"))
        except HelperError:
            checks.append(("Helper", False, "нет ответа"))

        try:
            firewall = await self.helper.call("firewall.health")
            fw_ok = (
                isinstance(firewall, dict)
                and firewall.get("mode") == "nft"
                and bool(firewall.get("active"))
            )
            fw_detail = (
                f"порт {firewall.get('ssh_port')}"
                if isinstance(firewall, dict)
                else "нет данных"
            )
            checks.append(("SSH whitelist", fw_ok, fw_detail))
        except HelperError:
            checks.append(("SSH whitelist", False, "нет данных"))

        try:
            services = await self.helper.call("service.list")
            units = services if isinstance(services, list) else []
            unhealthy = 0
            for unit in units[:12]:
                raw = await self.helper.call("service.status", {"unit": str(unit)})
                fields = _service_fields(str(raw))
                if fields.get("ActiveState") != "active":
                    unhealthy += 1
            checks.append(
                (
                    "Сервисы",
                    unhealthy == 0,
                    f"{len(units) - unhealthy}/{len(units)} active",
                )
            )
        except HelperError:
            checks.append(("Сервисы", False, "проверка не выполнена"))

        ok_count = sum(1 for _, ok, _ in checks if ok)
        lines = []
        for name, ok, detail in checks:
            lines.append(
                f"{'🟢' if ok else '🔴'} <b>{_safe(name)}</b> · {_safe(detail)}"
            )
        body = (
            f"<b>{ok_count}/{len(checks)} проверок успешно</b>\n\n"
            + "\n".join(lines)
        )
        self.state.audit(
            admin_id,
            "selftest",
            "ok" if ok_count == len(checks) else "attention",
            {"passed": ok_count, "total": len(checks)},
        )
        await self._show(
            chat_id,
            _screen("Самопроверка", body),
            {
                "inline_keyboard": [
                    [{"text": "↻ Повторить", "callback_data": "ui:selftest"}],
                    [
                        {"text": "← Настройки", "callback_data": "ui:settings"},
                        {"text": "⌂ Главная", "callback_data": "ui:home"},
                    ],
                ]
            },
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
                action = str(row["action"])
                outcome = str(row["outcome"])
                icon = icons.get(outcome, "·")
                label = _ACTION_LABELS.get(action, action)
                outcome_label = _OUTCOME_LABELS.get(outcome, outcome)
                target = _audit_target(row.get("details"))
                lines.append(
                    f"<code>{_safe(stamp)}</code>  {icon}  "
                    f"{_safe(label)}{target} · <i>{_safe(outcome_label)}</i>"
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
        if mode == "allow_ip":
            body = (
                "Отправьте IP, которому нужен доступ к SSH.\n\n"
                "<b>Пример</b>\n"
                "<code>203.0.113.42</code>\n\n"
                "После этого TelegramGuard предложит срок доступа."
            )
            title = "Новый доступ · 1/2"
        elif mode == "allow_ttl":
            body = (
                "Отправьте срок в формате <code>15m</code>, "
                "<code>2h</code> или <code>3d</code>.\n\n"
                "Минимум: <b>1 минута</b>\n"
                "Максимум: <b>7 дней</b>"
            )
            title = "Новый доступ · 2/2"
        else:
            body = (
                "Отправьте IP, который нужно убрать из whitelist.\n\n"
                "<b>Пример</b>\n"
                "<code>203.0.113.42</code>"
            )
            title = "Отозвать доступ"
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

    async def _show_ttl_choice(
        self,
        chat_id: int,
        admin_id: int,
        address: str,
        message_id: int | None = None,
    ) -> None:
        self.wizard[admin_id] = {"ip": address}
        body = (
            f"IP: <code>{_safe(address)}</code>\n\n"
            "Выберите, как долго этот адрес сможет подключаться к SSH."
        )
        await self._show(
            chat_id,
            _screen("Новый доступ · 2/2", body),
            _ttl_keyboard(),
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
        elif action == "firewall.extend":
            remaining = (
                int(result.get("remaining_seconds", 0))
                if isinstance(result, dict)
                else 0
            )
            body = (
                "🟢 <b>Доступ продлён</b>\n"
                f"IP: <code>{_safe(args['ip'])}</code>\n"
                f"Теперь осталось: <b>{_safe(_remaining(remaining))}</b>"
            )
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "Открыть запись",
                            "callback_data": f"acl:{args['ip']}",
                        }
                    ],
                    [{"text": "⌂ Главная", "callback_data": "ui:home"}],
                ]
            }
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
                            "callback_data": (
                                f"svc:{_service_token(str(args['unit']))}"
                            ),
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

    async def _resolve_service_ref(self, ref: str) -> str:
        managed = await self.helper.call("service.list")
        units = managed if isinstance(managed, list) else []
        for raw_unit in units:
            unit = validate_unit(str(raw_unit))
            if ref == unit or ref == _service_token(unit):
                return unit
        raise ValidationError("service is not managed")

    async def _handle_callback(
        self,
        chat_id: int,
        message_id: int,
        admin_id: int,
        data: str,
    ) -> None:
        self.input_modes.pop(admin_id, None)

        if data == "ui:home":
            self.wizard.pop(admin_id, None)
            await self._show_home(chat_id, message_id)
        elif data == "ui:status":
            await self._show_status(chat_id, admin_id, message_id)
        elif data == "ui:access":
            self.wizard.pop(admin_id, None)
            await self._show_access(chat_id, admin_id, message_id)
        elif data == "ui:security":
            await self._show_security(chat_id, admin_id, message_id)
        elif data == "ui:sessions":
            await self._show_sessions(chat_id, admin_id, message_id)
        elif data == "ui:ssh":
            await self._show_ssh(chat_id, admin_id, message_id)
        elif data == "ui:services":
            await self._show_services(chat_id, admin_id, message_id)
        elif data == "ui:audit":
            await self._show_audit(chat_id, message_id)
        elif data == "ui:settings":
            await self._show_settings(chat_id, admin_id, message_id)
        elif data == "ui:selftest":
            await self._show_self_test(chat_id, admin_id, message_id)
        elif data == "ui:about":
            await self._show_about(chat_id, message_id)
        elif data == "ui:allow":
            self.wizard.pop(admin_id, None)
            await self._show_input(chat_id, admin_id, "allow_ip", message_id)
        elif data == "ui:revoke":
            await self._show_input(chat_id, admin_id, "revoke", message_id)
        elif data.startswith("acl:"):
            await self._show_access_entry(
                chat_id, admin_id, data.split(":", 1)[1], message_id
            )
        elif data.startswith("ext1:"):
            address = str(parse_ip(data.split(":", 1)[1]))
            await self._confirmed_request(
                chat_id,
                admin_id,
                "firewall.extend",
                {"ip": address, "extra_seconds": 3600},
                f"Продлить доступ для {address} ещё на 1 час?",
                message_id,
            )
        elif data.startswith("extd:"):
            address = str(parse_ip(data.split(":", 1)[1]))
            await self._confirmed_request(
                chat_id,
                admin_id,
                "firewall.extend",
                {"ip": address, "extra_seconds": 86400},
                f"Продлить доступ для {address} ещё на 1 день?",
                message_id,
            )
        elif data.startswith("rvk:"):
            address = str(parse_ip(data.split(":", 1)[1]))
            await self._confirmed_request(
                chat_id,
                admin_id,
                "firewall.revoke",
                {"ip": address},
                f"Отозвать SSH-доступ у {address}?",
                message_id,
            )
        elif data.startswith("ttl:"):
            raw_ttl = data.split(":", 1)[1]
            wizard = self.wizard.get(admin_id)
            if not isinstance(wizard, dict) or "ip" not in wizard:
                raise ValidationError("мастер доступа устарел; начните заново")
            address = str(wizard["ip"])
            if raw_ttl == "custom":
                await self._show_input(
                    chat_id, admin_id, "allow_ttl", message_id
                )
            else:
                ttl = int(raw_ttl)
                self.wizard.pop(admin_id, None)
                await self._confirmed_request(
                    chat_id,
                    admin_id,
                    "firewall.allow",
                    {"ip": address, "ttl_seconds": ttl},
                    f"Разрешить {address} на {format_ttl(ttl)}?",
                    message_id,
                )
        elif data.startswith("svc:"):
            unit = await self._resolve_service_ref(data.split(":", 1)[1])
            await self._show_service(chat_id, admin_id, unit, message_id)
        elif data.startswith("logs:"):
            unit = await self._resolve_service_ref(data.split(":", 1)[1])
            await self._show_service_logs(
                chat_id, admin_id, unit, message_id
            )
        elif data.startswith("restart:"):
            unit = await self._resolve_service_ref(data.split(":", 1)[1])
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
            self.wizard.pop(admin_id, None)
            await self._show_home(chat_id, message_id)

    async def _handle_text_input(
        self, chat_id: int, admin_id: int, text: str
    ) -> bool:
        mode = self.input_modes.get(admin_id)
        if mode is None:
            return False

        try:
            if mode == "allow_ip":
                parts = text.split()
                if len(parts) != 1:
                    raise ValidationError("отправьте только один IP")
                address = str(parse_ip(parts[0]))
                self.input_modes.pop(admin_id, None)
                await self._show_ttl_choice(chat_id, admin_id, address)
                return True

            if mode == "allow_ttl":
                ttl = parse_ttl(text.strip())
                wizard = self.wizard.get(admin_id)
                if not isinstance(wizard, dict) or "ip" not in wizard:
                    raise ValidationError("мастер доступа устарел; начните заново")
                address = str(wizard["ip"])
                self.input_modes.pop(admin_id, None)
                self.wizard.pop(admin_id, None)
                await self._confirmed_request(
                    chat_id,
                    admin_id,
                    "firewall.allow",
                    {"ip": address, "ttl_seconds": ttl},
                    f"Разрешить {address} на {format_ttl(ttl)}?",
                )
                return True

            if mode == "revoke":
                parts = text.split()
                if len(parts) != 1:
                    raise ValidationError("нужен только один IP")
                address = str(parse_ip(parts[0]))
                self.input_modes.pop(admin_id, None)
                await self._confirmed_request(
                    chat_id,
                    admin_id,
                    "firewall.revoke",
                    {"ip": address},
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
                await self._show_input(chat_id, admin_id, "allow_ip")
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
        if command in {"/settings", "/doctor"}:
            if command == "/doctor":
                await self._show_self_test(chat_id, admin_id)
            else:
                await self._show_settings(chat_id, admin_id)
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

    async def _notify_admins(self, title: str, body: str) -> None:
        keyboard = {
            "inline_keyboard": [
                [{"text": "Открыть панель", "callback_data": "ui:home"}]
            ]
        }
        for admin_id in self.config.admin_ids:
            with contextlib.suppress(TelegramAPIError):
                await self.api.send_message(
                    admin_id,
                    _screen(title, body, "Автоматическое уведомление"),
                    keyboard,
                )

    async def _set_alert(
        self,
        key: str,
        active: bool,
        active_body: str,
        resolved_body: str | None = None,
    ) -> None:
        previous = self.alert_state.get(key)
        self.alert_state[key] = active

        if previous is None:
            if active:
                await self._notify_admins("Требует внимания", active_body)
            return

        if previous == active:
            return

        if active:
            await self._notify_admins("Требует внимания", active_body)
        elif resolved_body:
            await self._notify_admins("Состояние восстановлено", resolved_body)

    async def _watchdog_check(self) -> None:
        try:
            status = await self.helper.call("host.status")
            helper_ok = isinstance(status, dict)
        except HelperError:
            helper_ok = False

        await self._set_alert(
            "helper",
            not helper_ok,
            "🔴 Локальный privileged helper не отвечает.",
            "🟢 Локальный privileged helper снова отвечает.",
        )
        if not helper_ok:
            return

        firewall = await self.helper.call("firewall.health")
        if isinstance(firewall, dict):
            firewall_ok = (
                firewall.get("mode") == "nft"
                and bool(firewall.get("active"))
            )
            await self._set_alert(
                "firewall",
                not firewall_ok,
                "🟡 SSH whitelist не находится в активном managed-режиме.",
                "🟢 Managed SSH whitelist снова активен.",
            )

        summary = await self.helper.call("ssh.summary", {"minutes": 15})
        if isinstance(summary, dict):
            failed = int(summary.get("failed", 0))
            threshold = self.config.ssh_failed_alert_threshold
            await self._set_alert(
                "ssh-failures",
                failed >= threshold,
                (
                    "⚠ За последние 15 минут обнаружено "
                    f"<b>{failed}</b> неудачных SSH-аутентификаций."
                ),
                "🟢 Частота неудачных SSH-аутентификаций вернулась в норму.",
            )

        managed = await self.helper.call("service.list")
        units = managed if isinstance(managed, list) else []
        for raw_unit in units[:20]:
            unit = validate_unit(str(raw_unit))
            raw_status = await self.helper.call(
                "service.status", {"unit": unit}
            )
            fields = _service_fields(str(raw_status))
            active = fields.get("ActiveState") == "active"
            await self._set_alert(
                f"service:{unit}",
                not active,
                (
                    f"🔴 Сервис <code>{_safe(unit)}</code> "
                    "не находится в состоянии active."
                ),
                f"🟢 Сервис <code>{_safe(unit)}</code> восстановлен.",
            )

    async def _watchdog(self) -> None:
        await asyncio.sleep(5)
        while True:
            try:
                await self._watchdog_check()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print(
                    f"{BRAND}: watchdog check failed: {type(exc).__name__}",
                    file=sys.stderr,
                    flush=True,
                )
            await asyncio.sleep(self.config.alert_interval_seconds)

    async def run(self) -> None:
        with contextlib.suppress(TelegramAPIError):
            await self.api.configure_profile()

        offset: int | None = None
        watchdog_task = asyncio.create_task(self._watchdog())
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
            watchdog_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watchdog_task
            await self.api.close()


def main() -> None:
    config = BotConfig.from_env()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(BotApp(config).run())


if __name__ == "__main__":
    main()
