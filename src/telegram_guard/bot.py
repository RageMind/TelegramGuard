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
from telegram_guard.ssh_approval import SshApprovalBroker, SshApprovalRequest
from telegram_guard.state import StateStore
from telegram_guard.telegram_api import TelegramAPI, TelegramAPIError
from telegram_guard.telegram_ui import (
    ButtonStyle,
    TelegramView,
    button,
    dashboard_screen,
    keyboard,
)
from telegram_guard.telegram_ui import screen as _screen


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


def _code(value: object, limit: int = 2800) -> str:
    return f"<pre>{_safe(bounded(str(value), limit))}</pre>"


def _home_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            button("Система", "ui:status", style="primary"),
            button("Доступ", "ui:access", style="success"),
        ],
        [
            button("Безопасность", "ui:security", style="primary"),
            button("Сервисы", "ui:services"),
        ],
        [
            button("Диагностика", "ui:diagnostics", style="primary"),
            button("Журнал", "ui:audit"),
        ],
        [
            button("Настройки", "ui:settings"),
            button("Обновить", "ui:home"),
        ],
    )


def _back_keyboard(refresh: str | None = None) -> dict[str, Any]:
    row: list[dict[str, str]] = []
    if refresh:
        row.append(button("Обновить", refresh))
    row.append(button("Control Center", "ui:home", style="primary"))
    return keyboard(row)


def _status_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            button("Сеть", "ui:network", style="primary"),
            button("События", "ui:events"),
        ],
        [
            button("Обновления", "ui:updates"),
            button("Сессии", "ui:sessions"),
        ],
        [
            button("SSH", "ui:ssh"),
            button("Обновить", "ui:status"),
        ],
        [button("Control Center", "ui:home", style="primary")],
    )


def _diagnostics_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            button("Самопроверка", "ui:selftest", style="primary"),
            button("События", "ui:events"),
        ],
        [
            button("Обновления", "ui:updates"),
            button("Безопасность", "ui:security"),
        ],
        [
            button("Обновить", "ui:diagnostics"),
            button("Control Center", "ui:home"),
        ],
    )


def _events_keyboard(minutes: int) -> dict[str, Any]:
    return keyboard(
        [
            button("15 мин", "events:15", style="primary" if minutes == 15 else None),
            button("1 час", "events:60", style="primary" if minutes == 60 else None),
            button("24 часа", "events:1440", style="primary" if minutes == 1440 else None),
        ],
        [
            button("Система", "ui:status"),
            button("Control Center", "ui:home"),
        ],
    )


def _access_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            button("Выдать доступ", "ui:allow", style="success"),
            button("Отозвать", "ui:revoke", style="danger"),
        ],
        [
            button("Обновить", "ui:access"),
            button("Control Center", "ui:home", style="primary"),
        ],
    )


def _security_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            button("SSH события", "ui:ssh"),
            button("Сессии", "ui:sessions"),
        ],
        [
            button("Обновить", "ui:security"),
            button("Активность", "ui:audit"),
        ],
        [button("Control Center", "ui:home", style="primary")],
    )


def _settings_keyboard() -> dict[str, Any]:
    return keyboard(
        [button("Запустить самопроверку", "ui:selftest", style="primary")],
        [
            button("О системе", "ui:about"),
            button("Control Center", "ui:home"),
        ],
    )


def _ttl_keyboard() -> dict[str, Any]:
    return keyboard(
        [
            button("15 минут", "ttl:900"),
            button("1 час", "ttl:3600", style="primary"),
        ],
        [
            button("8 часов", "ttl:28800"),
            button("1 день", "ttl:86400"),
        ],
        [
            button("7 дней", "ttl:604800"),
            button("Свой срок", "ttl:custom"),
        ],
        [button("Отмена", "ui:access", style="danger")],
    )


_ACTION_LABELS: dict[str, str] = {
    "host.status": "Система проверена",
    "host.sessions": "Сессии просмотрены",
    "system.network": "Сеть проверена",
    "system.health": "Диагностика выполнена",
    "system.events": "Системные события просмотрены",
    "ssh.recent": "SSH-события просмотрены",
    "ssh.approval.request": "SSH-вход ожидает подтверждения",
    "ssh.approval.approved": "SSH-вход разрешён",
    "ssh.approval.denied": "SSH-вход отклонён",
    "ssh.approval.timeout": "SSH-вход истёк",
    "security.summary": "Безопасность проверена",
    "firewall.list": "Whitelist просмотрен",
    "firewall.snapshot": "Доступ просмотрен",
    "firewall.allow": "Доступ выдан",
    "firewall.extend": "Доступ продлён",
    "firewall.make_permanent": "Доступ сделан постоянным",
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
        self.ssh_approval = SshApprovalBroker(
            config.ssh_approval_socket,
            config.ssh_approval_timeout,
            self._on_ssh_approval_request,
            self._on_ssh_approval_result,
        )

    def _is_admin(self, user_id: int) -> bool:
        return user_id in self.config.admin_ids

    async def _show(
        self,
        chat_id: int,
        text: str | TelegramView,
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
            if isinstance(status, dict):
            total = int(status.get("memory_total", 0))
            available = int(status.get("memory_available", 0))
            ram = _percent(max(total - available, 0), total)
            disk_total = int(status.get("disk_total", 0))
            disk_free = int(status.get("disk_free", 0))
            disk = _percent(max(disk_total - disk_free, 0), disk_total)

            await self._set_alert(
                "ram",
                ram >= self.config.ram_alert_threshold,
                (
                    "🟡 RAM достигла "
                    f"<b>{ram}%</b> (порог {self.config.ram_alert_threshold}%)."
                ),
                "🟢 Использование RAM вернулось ниже порога.",
            )
            await self._set_alert(
                "disk",
                disk >= self.config.disk_alert_threshold,
                (
                    "🟡 Диск заполнен на "
                    f"<b>{disk}%</b> (порог {self.config.disk_alert_threshold}%)."
                ),
                "🟢 Использование диска вернулось ниже порога.",
            )

        health = await self.helper.call("system.health")
        if isinstance(health, dict):
            failed_units = int(health.get("failed_unit_count", 0))
            await self._set_alert(
                "failed-units",
                failed_units > 0,
                f"🔴 Systemd failed units: <b>{failed_units}</b>.",
                "🟢 Systemd failed units больше не обнаружены.",
            )

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
            uptime = _uptime(int(result.get("uptime_seconds", 0)))
            load_1 = float(result.get("load_1", 0.0))
            cpu_count = max(1, int(result.get("cpu_count", 0) or 1))

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
            approval_active = self.config.ssh_approval_enabled

            attention = 0
            if not approval_active and not firewall_active:
                attention += 1
            if ssh_failed >= self.config.ssh_failed_alert_threshold:
                attention += 1
            if ram >= self.config.ram_alert_threshold:
                attention += 1
            if disk >= self.config.disk_alert_threshold:
                attention += 1
            if load_1 >= cpu_count * 2:
                attention += 1

            last_rows = self.state.recent_audit(1)
            last_action = "Панель готова"
            if last_rows:
                last = last_rows[0]
                action = str(last.get("action", ""))
                outcome = str(last.get("outcome", ""))
                label = _ACTION_LABELS.get(action, action)
                outcome_label = _OUTCOME_LABELS.get(outcome, outcome)
                last_action = f"{label} · {outcome_label}"

            if approval_active:
                access_label = "Telegram 2FA · ON"
            elif firewall_active:
                access_label = "IP whitelist · ON"
            else:
                access_label = "OFF"

            status = (
                "🟢 NORMAL"
                if attention == 0
                else f"🟡 ATTENTION · {attention}"
            )
            view = dashboard_screen(
                "Control Center",
                status,
                [
                    ("RAM", f"{ram}%"),
                    ("Disk", f"{disk}%"),
                    ("Load", f"{load_1:.2f}"),
                    ("SSH", f"{ssh_failed} fail"),
                    ("Uptime", uptime),
                    ("Services", len(units)),
                ],
                note=f"Доступ: {access_label}",
                footer=last_action,
                columns=2,
                details_title="Доступ и состояние",
            )
        except HelperError:
            view = dashboard_screen(
                "Control Center",
                "🔴 DEGRADED",
                [
                    ("Bot", "online"),
                    ("Helper", "unavailable"),
                ],
                note=(
                    "Telegram-интерфейс доступен, но системные действия "
                    "временно заблокированы."
                ),
                columns=2,
                details_title="Что произошло",
            )

        await self._show(
            chat_id,
            view,
            _home_keyboard(),
            message_id,
        )

    async def _show_status(
        self, chat_id: int, admin_id: int, message_id: int | None = None
    ) -> None:
        result = await self.helper.call("host.status")
        if not isinstance(result, dict):
            raise HelperError("invalid status response")

        total = int(result.get("memory_total", 0))
        available = int(result.get("memory_available", 0))
        used = max(total - available, 0)
        swap_total = int(result.get("swap_total", 0))
        swap_free = int(result.get("swap_free", 0))
        swap_used = max(swap_total - swap_free, 0)
        disk_total = int(result.get("disk_total", 0))
        disk_free = int(result.get("disk_free", 0))
        disk_used = max(disk_total - disk_free, 0)
        inode_total = int(result.get("inode_total", 0))
        inode_free = int(result.get("inode_free", 0))
        inode_used = max(inode_total - inode_free, 0)

        ram = _percent(used, total)
        swap = _percent(swap_used, swap_total) if swap_total else 0
        disk = _percent(disk_used, disk_total)
        inode = _percent(inode_used, inode_total)
        cpu_count = int(result.get("cpu_count", 0))
        load_1 = float(result.get("load_1", 0.0))
        load_5 = float(result.get("load_5", 0.0))
        load_15 = float(result.get("load_15", 0.0))

        attention = (
            ram >= self.config.ram_alert_threshold
            or disk >= self.config.disk_alert_threshold
            or (cpu_count > 0 and load_1 >= cpu_count * 2)
        )
        details = (
            f"Host: {result.get('hostname', '—')}\n"
            f"OS: {result.get('os_name', '—')}\n"
            f"Kernel: {result.get('kernel', '—')}\n"
            f"Inodes: {inode}% used"
        )
        view = dashboard_screen(
            "Система",
            "🟡 ATTENTION" if attention else "🟢 HEALTHY",
            [
                ("CPU", f"{cpu_count or '—'} vCPU"),
                ("Load", f"{load_1:.2f}/{load_5:.2f}/{load_15:.2f}"),
                ("RAM", f"{ram}% · {_human_bytes(used)}"),
                ("Swap", f"{swap}% · {_human_bytes(swap_used)}"),
                ("Disk", f"{disk}% · {_human_bytes(disk_used)}"),
                ("Processes", int(result.get("process_count", 0))),
            ],
            footer=f"Uptime · {_uptime(int(result.get('uptime_seconds', 0)))}",
            columns=2,
            details_title="Система и ядро",
            details_text=details,
        )
        self.state.audit(admin_id, "host.status", "ok")
        await self._show(
            chat_id,
            view,
            _status_keyboard(),
            message_id,
        )

    async def _show_network(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
    ) -> None:
        result = await self.helper.call("system.network")
        if not isinstance(result, dict):
            raise HelperError("invalid network response")

        raw_interfaces = result.get("interfaces", [])
        interfaces = raw_interfaces if isinstance(raw_interfaces, list) else []
        raw_listeners = result.get("listeners", [])
        listeners = raw_listeners if isinstance(raw_listeners, list) else []

        detail_lines: list[str] = []
        for item in interfaces[:8]:
            if not isinstance(item, dict):
                continue
            detail_lines.append(
                f"{item.get('name', '?')}: "
                f"RX {_human_bytes(int(item.get('rx_bytes', 0)))} · "
                f"TX {_human_bytes(int(item.get('tx_bytes', 0)))}"
            )
        if listeners:
            if detail_lines:
                detail_lines.append("")
            detail_lines.append("Listening:")
            for item in listeners[:16]:
                if not isinstance(item, dict):
                    continue
                detail_lines.append(
                    f"{item.get('proto', '?')}  {item.get('local', '?')}"
                )

        view = dashboard_screen(
            "Сеть",
            "🟢 READ-ONLY",
            [
                ("RX", _human_bytes(int(result.get("rx_bytes", 0)))),
                ("TX", _human_bytes(int(result.get("tx_bytes", 0)))),
                ("Interfaces", len(interfaces)),
                ("Listeners", len(listeners)),
            ],
            columns=2,
            details_title="Интерфейсы и порты",
            details_text="\n".join(detail_lines) or "Нет данных.",
        )
        self.state.audit(admin_id, "system.network", "ok")
        await self._show(
            chat_id,
            view,
            keyboard(
                [
                    button("События", "ui:events"),
                    button("Обновить", "ui:network"),
                ],
                [
                    button("Система", "ui:status", style="primary"),
                    button("Control Center", "ui:home"),
                ],
            ),
            message_id,
        )

    async def _show_events(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
        minutes: int = 60,
    ) -> None:
        raw = await self.helper.call("system.events", {"minutes": minutes})
        text_value = str(raw).strip()
        no_events = text_value.startswith("No warning-or-higher")
        event_count = 0 if no_events else len(
            [line for line in text_value.splitlines() if line.strip()]
        )
        window = "24ч" if minutes == 1440 else (
            "1ч" if minutes == 60 else f"{minutes}м"
        )
        view = dashboard_screen(
            "Системные события",
            "🟢 CLEAN" if event_count == 0 else f"🟡 {event_count} EVENT(S)",
            [
                ("Window", window),
                ("Priority", "warning+"),
            ],
            columns=2,
            details_title="journalctl",
            details_text=text_value or "Событий нет.",
        )
        self.state.audit(
            admin_id,
            "system.events",
            "ok",
            {"minutes": minutes},
        )
        await self._show(
            chat_id,
            view,
            _events_keyboard(minutes),
            message_id,
        )

    async def _show_updates(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
    ) -> None:
        health = await self.helper.call("system.health")
        if not isinstance(health, dict):
            raise HelperError("invalid health response")

        failed_raw = health.get("failed_units", [])
        failed = failed_raw if isinstance(failed_raw, list) else []
        upgradable = int(health.get("upgradable_packages", 0))
        reboot = bool(health.get("reboot_required"))
        attention = bool(failed or reboot)

        view = dashboard_screen(
            "Обновления",
            "🟡 MAINTENANCE" if attention else "🟢 READY",
            [
                ("Packages", f"{upgradable} upgradable"),
                ("Reboot", "required" if reboot else "not required"),
                ("Failed units", len(failed)),
                ("Manager", health.get("package_manager", "—")),
            ],
            columns=2,
            details_title="Failed systemd units",
            details_text="\n".join(str(x) for x in failed) or "Нет failed units.",
        )
        self.state.audit(admin_id, "system.health", "ok")
        await self._show(
            chat_id,
            view,
            keyboard(
                [
                    button("События", "ui:events"),
                    button("Обновить", "ui:updates"),
                ],
                [
                    button("Система", "ui:status", style="primary"),
                    button("Control Center", "ui:home"),
                ],
            ),
            message_id,
        )

    async def _show_diagnostics(
        self,
        chat_id: int,
        admin_id: int,
        message_id: int | None = None,
    ) -> None:
        host = await self.helper.call("host.status")
        health = await self.helper.call("system.health")
        firewall = await self.helper.call("firewall.health")
        services = await self.helper.call("service.list")
        ssh = await self.helper.call("ssh.summary", {"minutes": 15})
        if (
            not isinstance(host, dict)
            or not isinstance(health, dict)
            or not isinstance(firewall, dict)
            or not isinstance(ssh, dict)
        ):
            raise HelperError("invalid diagnostics response")

        total = int(host.get("memory_total", 0))
        available = int(host.get("memory_available", 0))
        ram = _percent(max(total - available, 0), total)
        disk_total = int(host.get("disk_total", 0))
        disk_free = int(host.get("disk_free", 0))
        disk = _percent(max(disk_total - disk_free, 0), disk_total)

        units = services if isinstance(services, list) else []
        unhealthy_services = 0
        for raw_unit in units[:20]:
            unit = validate_unit(str(raw_unit))
            raw = await self.helper.call("service.status", {"unit": unit})
            fields = _service_fields(str(raw))
            if fields.get("ActiveState") != "active":
                unhealthy_services += 1

        firewall_ok = (
            firewall.get("mode") == "nft"
            and bool(firewall.get("active"))
        )
        access_ok = self.config.ssh_approval_enabled or firewall_ok
        failed_units = int(health.get("failed_unit_count", 0))
        ssh_failed = int(ssh.get("failed", 0))
        reboot = bool(health.get("reboot_required"))

        issues = sum(
            (
                not access_ok,
                ram >= self.config.ram_alert_threshold,
                disk >= self.config.disk_alert_threshold,
                failed_units > 0,
                unhealthy_services > 0,
                ssh_failed >= self.config.ssh_failed_alert_threshold,
                reboot,
            )
        )

        failed_raw = health.get("failed_units", [])
        failed_list = failed_raw if isinstance(failed_raw, list) else []
        details = "\n".join(str(x) for x in failed_list)
        if not details:
            details = "Критических failed units нет."

        view = dashboard_screen(
            "Диагностика",
            "🟢 ALL CHECKS OK" if issues == 0 else f"🟡 {issues} ATTENTION",
            [
                ("Access", "OK" if access_ok else "OFF"),
                ("Services", f"{len(units) - unhealthy_services}/{len(units)} active"),
                ("RAM", f"{ram}%"),
                ("Disk", f"{disk}%"),
                ("SSH / 15m", f"{ssh_failed} fail"),
                ("Updates", int(health.get("upgradable_packages", 0))),
                ("Failed units", failed_units),
                ("Reboot", "yes" if reboot else "no"),
            ],
            columns=2,
            note="Все проверки read-only; изменяющие действия остаются отдельными и подтверждаемыми.",
            details_title="Проблемные units",
            details_text=details,
        )
        self.state.audit(
            admin_id,
            "system.health",
            "ok" if issues == 0 else "attention",
            {"issues": issues},
        )
        await self._show(
            chat_id,
            view,
            _diagnostics_keyboard(),
            message_id,
        )

    async def _show_access(
        self, chat_id: int, admin_id: int, message_id: int | None = None
    ) -> None:
        if self.config.ssh_approval_enabled:
            status = self.ssh_approval.status()
            body = (
                "🟢 <b>SSH 2FA · ACTIVE</b>\n"
                "<code>Пароль/ключ → Telegram → Shell</code>\n\n"
                f"<b>Timeout</b>   <code>{self.config.ssh_approval_timeout}s</code>\n"
                f"<b>Pending</b>   <code>{int(status['pending'])}</code>\n\n"
                "После успешной проверки пароля или ключа вход всё равно "
                "останавливается до вашего подтверждения в Telegram. "
                "Секреты в бота не передаются."
            )
            await self._show(
                chat_id,
                _screen("Доступ к VPS", body),
                keyboard(
                    [
                        button("Обновить", "ui:access"),
                        button("Безопасность", "ui:security", style="primary"),
                    ],
                    [button("Control Center", "ui:home")],
                ),
                message_id,
            )
            self.state.audit(admin_id, "firewall.snapshot", "ok")
            return

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
                "🟢 <b>IP WHITELIST · ACTIVE</b>",
                f"<b>SSH port</b>   <code>{port}</code>",
                f"<b>Trusted</b>    <code>{len(entries)}</code>",
                "",
                "<b>Разрешённые адреса</b>",
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
                        button(
                            f"{icon} {ip_value} · {state}",
                            f"acl:{ip_value}",
                        )
                    ]
                )
            body = "\n".join(body_lines)
            rows.append(
                [button("Выдать доступ", "ui:allow", style="success")]
            )
        else:
            mode = str(snapshot.get("mode", "unknown"))
            body = (
                "🟡 <b>SSH PROTECTION · OFF</b>\n\n"
                f"<b>Mode</b>      <code>{_safe(mode)}</code>\n"
                f"<b>SSH port</b>  <code>{port or '—'}</code>\n\n"
                "Сейчас TelegramGuard не ограничивает SSH. "
                "Включение защиты выполняется локально на VPS, чтобы "
                "ошибка в Telegram не могла заблокировать аварийный доступ."
            )

        rows.append(
            [
                button("Обновить", "ui:access"),
                button("Control Center", "ui:home", style="primary"),
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
        added_raw = item.get("added_at")
        added_text = "неизвестно"
        if isinstance(added_raw, int) and added_raw > 0:
            added_text = dt.datetime.fromtimestamp(
                added_raw, tz=dt.UTC
            ).strftime("%Y-%m-%d %H:%MZ")
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
            f"Добавлен: <code>{_safe(added_text)}</code>\n"
            f"Источник: <code>{_safe(source)}</code>"
        )

        rows: list[list[dict[str, str]]] = []
        if not permanent:
            rows.append(
                [
                    button("＋1 час", f"ext1:{address}"),
                    button("＋1 день", f"extd:{address}"),
                ]
            )
            rows.append(
                [
                    button(
                        "Сделать постоянным",
                        f"perm:{address}",
                        style="primary",
                    )
                ]
            )
        if not protected:
            rows.append(
                [button("Отозвать доступ", f"rvk:{address}", style="danger")]
            )
        rows.append(
            [
                button("Назад", "ui:access"),
                button("Control Center", "ui:home"),
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
        approval_active = self.config.ssh_approval_enabled
        failed = int(summary.get("failed", 0))
        invalid = int(summary.get("invalid_user", 0))
        accepted = int(summary.get("accepted", 0))
        access_ok = approval_active or firewall_ok
        security_ok = (
            access_ok
            and failed < self.config.ssh_failed_alert_threshold
        )

        if approval_active:
            access_label = "Telegram 2FA"
        elif firewall_ok:
            access_label = "IP whitelist"
        else:
            access_label = "OFF"

        status = "🟢 SECURE" if security_ok else "🟡 ATTENTION"
        view = dashboard_screen(
            "Безопасность",
            status,
            [
                ("Protection", access_label),
                ("Sessions", session_count),
                ("Accepted", accepted),
                ("Failed", failed),
                ("Invalid", invalid),
                ("Window", "60m"),
            ],
            note=(
                "Управление доступно только в личном чате. "
                "Privileged helper отделён от Telegram-процесса."
            ),
            columns=2,
            details_title="Модель безопасности",
        )
        self.state.audit(admin_id, "security.summary", "ok")
        await self._show(
            chat_id,
            view,
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
                "🟢 <b>SERVICE CONTROL READY</b>\n"
                f"<b>Managed units</b>  <code>{len(units)}</code>\n\n"
                "Выберите сервис для статуса, логов или безопасного restart."
            )
        else:
            body = (
                "🟡 <b>NO MANAGED SERVICES</b>\n\n"
                "Allowlist сервисов настраивается локально на VPS."
            )

        rows: list[list[dict[str, str]]] = []
        for unit in units[:12]:
            label = validate_unit(str(unit))
            token = _service_token(label)
            rows.append(
                [button(label, f"svc:{token}", style="primary")]
            )
        rows.append(
            [
                button("Обновить", "ui:services"),
                button("Control Center", "ui:home"),
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
            f"{icon} <b>{_safe(description)}</b>\n\n"
            f"<b>State</b>  <code>{_safe(active)} / {_safe(sub)}</code>\n"
            f"<b>Unit</b>   <code>{_safe(unit)}</code>"
        )
        token = _service_token(unit)
        keyboard_markup = keyboard(
            [
                button("Логи", f"logs:{token}", style="primary"),
                button("Restart", f"restart:{token}", style="danger"),
            ],
            [
                button("Назад", "ui:services"),
                button("Control Center", "ui:home"),
            ],
        )
        await self._show(
            chat_id,
            _screen("Сервис", body),
            keyboard_markup,
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
        keyboard_markup = keyboard(
            [button("Обновить", f"logs:{token}")],
            [
                button("Назад к сервису", f"svc:{token}"),
                button("Control Center", "ui:home"),
            ],
        )
        await self._show(
            chat_id,
            _screen("Последние логи", body),
            keyboard_markup,
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
        firewall_active = (
            firewall.get("mode") == "nft"
            and bool(firewall.get("active"))
        )
        access_mode = (
            "Telegram 2FA"
            if self.config.ssh_approval_enabled
            else "IP whitelist"
            if firewall_active
            else "off"
        )
        view = dashboard_screen(
            "Настройки",
            "QyAi Control OS",
            [
                ("Version", __version__),
                ("Access", access_mode),
                ("SSH port", firewall.get("ssh_port", "—")),
                ("Services", len(units)),
                ("Health", f"{self.config.alert_interval_seconds}s"),
                ("SSH alert", f"{self.config.ssh_failed_alert_threshold}+"),
                ("RAM alert", f"{self.config.ram_alert_threshold}%"),
                ("Disk alert", f"{self.config.disk_alert_threshold}%"),
            ],
            note=(
                "Критические настройки меняются локально на VPS. "
                "Telegram получает только безопасный ограниченный набор операций."
            ),
            columns=2,
            details_title="Политика управления",
        )
        self.state.audit(admin_id, "settings.view", "ok")
        await self._show(
            chat_id,
            view,
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
            if self.config.ssh_approval_enabled:
                approval = self.ssh_approval.status()
                checks.append(
                    (
                        "SSH Telegram approval",
                        bool(approval["active"]),
                        f"timeout {self.config.ssh_approval_timeout}s",
                    )
                )
            else:
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
        self,
        chat_id: int,
        message_id: int | None = None,
        page: int = 0,
    ) -> None:
        page_size = 10
        total = self.state.audit_count()
        max_page = max(0, (max(total, 1) - 1) // page_size)
        page = max(0, min(page, max_page))
        rows = self.state.audit_page(
            limit=page_size,
            offset=page * page_size,
        )

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
                "attention": "!",
            }
            for row in rows:
                stamp = dt.datetime.fromtimestamp(
                    int(row["created_at"]), tz=dt.UTC
                ).strftime("%d.%m %H:%M")
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
            body = (
                f"📝 <b>Действия {page * page_size + 1}–"
                f"{page * page_size + len(rows)} из {total}</b>\n\n"
                + "\n".join(lines)
            )

        nav: list[dict[str, str]] = []
        if page > 0:
            nav.append(
                {
                    "text": "← Новее",
                    "callback_data": f"audit:{page - 1}",
                }
            )
        if page < max_page:
            nav.append(
                {
                    "text": "Старее →",
                    "callback_data": f"audit:{page + 1}",
                }
            )

        keyboard_rows: list[list[dict[str, str]]] = []
        if nav:
            keyboard_rows.append(nav)
        keyboard_rows.append(
            [
                {"text": "↻ Обновить", "callback_data": f"audit:{page}"},
                {"text": "⌂ Главная", "callback_data": "ui:home"},
            ]
        )
        await self._show(
            chat_id,
            _screen("Активность", body),
            {"inline_keyboard": keyboard_rows},
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
        positive_style: ButtonStyle = (
            "success" if action == "firewall.allow" else "danger"
        )
        keyboard_markup = keyboard(
            [
                button(
                    "Подтвердить",
                    f"confirm:{token}",
                    style=positive_style,
                ),
                button("Отмена", f"cancel:{token}"),
            ]
        )
        self.state.audit(admin_id, action, "pending", args)
        body = (
            "🟡 <b>CONFIRM ACTION</b>\n\n"
            f"{_safe(description)}\n\n"
            "<code>TTL 90s</code> · после истечения запрос будет отклонён."
        )
        await self._show(
            chat_id,
            _screen("Confirmation", body),
            keyboard_markup,
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
        elif action == "firewall.make_permanent":
            body = (
                "🟢 <b>Доступ стал постоянным</b>\n"
                f"IP: <code>{_safe(args['ip'])}</code>\n"
                "Этот адрес больше не истекает автоматически."
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

        if data.startswith("ssha:"):
            token = data.split(":", 1)[1]
            request = self.ssh_approval.decide(token, "approve")
            if request is None:
                raise ValidationError("запрос уже завершён или истёк")
            self.state.audit(
                admin_id,
                "ssh.approval.approved",
                "confirmed",
                {"ip": request.remote_ip, "user": request.user},
            )
            await self._show(
                chat_id,
                _screen(
                    "SSH вход разрешён",
                    (
                        "🟢 <b>Сессия может продолжить вход</b>\n\n"
                        f"Пользователь: <code>{_safe(request.user)}</code>\n"
                        f"IP: <code>{_safe(request.remote_ip)}</code>"
                    ),
                ),
                _back_keyboard(),
                message_id,
            )
        elif data.startswith("sshd:"):
            token = data.split(":", 1)[1]
            request = self.ssh_approval.decide(token, "deny")
            if request is None:
                raise ValidationError("запрос уже завершён или истёк")
            self.state.audit(
                admin_id,
                "ssh.approval.denied",
                "denied",
                {"ip": request.remote_ip, "user": request.user},
            )
            await self._show(
                chat_id,
                _screen(
                    "SSH вход отклонён",
                    (
                        "🔴 <b>Сессия не получит доступ</b>\n\n"
                        f"Пользователь: <code>{_safe(request.user)}</code>\n"
                        f"IP: <code>{_safe(request.remote_ip)}</code>"
                    ),
                ),
                _back_keyboard(),
                message_id,
            )
        elif data == "ui:home":
            self.wizard.pop(admin_id, None)
            await self._show_home(chat_id, message_id)
        elif data == "ui:status":
            await self._show_status(chat_id, admin_id, message_id)
        elif data == "ui:network":
            await self._show_network(chat_id, admin_id, message_id)
        elif data == "ui:events":
            await self._show_events(chat_id, admin_id, message_id)
        elif data.startswith("events:"):
            raw_minutes = data.split(":", 1)[1]
            if not raw_minutes.isdigit():
                raise ValidationError("invalid event window")
            minutes = max(1, min(int(raw_minutes), 1440))
            await self._show_events(
                chat_id, admin_id, message_id, minutes=minutes
            )
        elif data == "ui:updates":
            await self._show_updates(chat_id, admin_id, message_id)
        elif data == "ui:diagnostics":
            await self._show_diagnostics(chat_id, admin_id, message_id)
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
            await self._show_audit(chat_id, message_id, 0)
        elif data.startswith("audit:"):
            raw_page = data.split(":", 1)[1]
            if not raw_page.isdigit():
                raise ValidationError("invalid audit page")
            await self._show_audit(chat_id, message_id, int(raw_page))
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
        elif data.startswith("perm:"):
            address = str(parse_ip(data.split(":", 1)[1]))
            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "Продолжить",
                            "callback_data": f"permc:{address}",
                        }
                    ],
                    [{"text": "Отмена", "callback_data": f"acl:{address}"}],
                ]
            }
            await self._show(
                chat_id,
                _screen(
                    "Постоянный доступ",
                    (
                        "⚠️ <b>Адрес перестанет истекать автоматически.</b>\n\n"
                        f"IP: <code>{_safe(address)}</code>\n"
                        "Используйте это только для доверенного стабильного адреса."
                    ),
                ),
                keyboard,
                message_id,
            )
        elif data.startswith("permc:"):
            address = str(parse_ip(data.split(":", 1)[1]))
            await self._confirmed_request(
                chat_id,
                admin_id,
                "firewall.make_permanent",
                {"ip": address},
                f"Окончательно сделать {address} постоянным?",
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
        if command == "/network":
            await self._show_network(chat_id, admin_id)
            return
        if command == "/events":
            minutes = 60
            if args:
                if not args[0].isdigit():
                    raise ValidationError("minutes must be numeric")
                minutes = max(1, min(int(args[0]), 1440))
            await self._show_events(chat_id, admin_id, minutes=minutes)
            return
        if command == "/updates":
            await self._show_updates(chat_id, admin_id)
            return
        if command == "/doctor":
            await self._show_diagnostics(chat_id, admin_id)
            return
        if command == "/selftest":
            await self._show_self_test(chat_id, admin_id)
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
        if command == "/settings":
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

            data = str(callback.get("data", ""))
            feedback = ""
            if data in {
                "ui:home",
                "ui:status",
                "ui:access",
                "ui:security",
                "ui:services",
                "ui:network",
                "ui:events",
                "ui:updates",
                "ui:diagnostics",
            } or data.startswith(("logs:", "audit:", "events:")):
                feedback = "Обновляю…"
            elif data.startswith(("confirm:", "ssha:", "sshd:")):
                feedback = "Выполняю…"
            await self.api.answer_callback(callback_id, feedback)
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

    async def _on_ssh_approval_request(
        self,
        token: str,
        request: SshApprovalRequest,
    ) -> None:
        self.state.audit(
            0,
            "ssh.approval.request",
            "pending",
            {"ip": request.remote_ip, "user": request.user},
        )
        body = (
            "🟡 <b>SSH SIGN-IN WAITING</b>\n"
            "Первичная аутентификация уже успешна. Shell ещё не открыт.\n\n"
            f"<b>User</b>  <code>{_safe(request.user)}</code>\n"
            f"<b>IP</b>    <code>{_safe(request.remote_ip)}</code>\n"
            f"<b>TTY</b>   <code>{_safe(request.tty)}</code>\n"
            f"<b>TTL</b>   <code>{self.config.ssh_approval_timeout}s</code>"
        )
        keyboard_markup = keyboard(
            [
                button(
                    "Разрешить вход",
                    f"ssha:{token}",
                    style="success",
                ),
                button(
                    "Отклонить",
                    f"sshd:{token}",
                    style="danger",
                ),
            ]
        )
        delivered = 0
        for admin_id in self.config.admin_ids:
            try:
                await self.api.send_message(
                    admin_id,
                    _screen("SSH Access Gate", body),
                    keyboard_markup,
                )
                delivered += 1
            except TelegramAPIError:
                continue
        if delivered == 0:
            self.ssh_approval.decide(token, "deny")

    async def _on_ssh_approval_result(
        self,
        token: str,
        request: SshApprovalRequest,
        decision: str,
    ) -> None:
        if decision == "timeout":
            self.state.audit(
                0,
                "ssh.approval.timeout",
                "denied",
                {"ip": request.remote_ip, "user": request.user},
            )
        elif decision == "error":
            self.state.audit(
                0,
                "ssh.approval.denied",
                "error",
                {"ip": request.remote_ip, "user": request.user},
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
        if isinstance(firewall, dict) and not self.config.ssh_approval_enabled:
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

        if self.config.ssh_approval_enabled:
            await self.ssh_approval.start()

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
            if self.config.ssh_approval_enabled:
                await self.ssh_approval.close()
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
