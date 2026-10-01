from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
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
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _brand(text: str) -> str:
    return bounded(f"{text.strip()}\n\n{BRAND}", 3900)


HELP = _brand(
    """
TelegramGuard — управление VPS без общего удалённого shell.

/status — состояние VPS
/sessions — активные сессии
/ssh [минуты] — последние SSH-события
/allow <ip> [ttl] — временно разрешить IP
/revoke <ip> — удалить IP из whitelist
/whitelist — показать whitelist
/services — список управляемых systemd-сервисов
/service <unit> — статус сервиса
/restart <unit> — запросить подтверждённый restart
/audit [count] — локальный аудит
/version — версия
/help — эта справка

TTL: 15m, 1h, 8h, 1d. Максимум 7d.
"""
)


class BotApp:
    def __init__(self, config: BotConfig) -> None:
        self.config = config
        self.api = TelegramAPI(config.token)
        self.helper = HelperClient(config.helper_socket)
        self.state = StateStore(config.state_db)
        self.rate = RateLimiter(config.rate_limit_per_minute)

    def _is_admin(self, user_id: int) -> bool:
        return user_id in self.config.admin_ids

    async def _send(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> None:
        await self.api.send_message(chat_id, _brand(text), reply_markup)

    async def _confirmed_request(
        self,
        chat_id: int,
        admin_id: int,
        action: str,
        args: dict[str, Any],
        description: str,
    ) -> None:
        token = self.state.create_pending(admin_id, action, args)
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "Подтвердить", "callback_data": f"confirm:{token}"},
                    {"text": "Отмена", "callback_data": f"cancel:{token}"},
                ]
            ]
        }
        self.state.audit(admin_id, action, "pending", args)
        await self._send(
            chat_id,
            f"{description}\n\nПодтверждение действует 90 секунд.",
            keyboard,
        )

    async def _read_command(
        self, chat_id: int, admin_id: int, command: str, args: list[str]
    ) -> None:
        if command in {"/start", "/help"}:
            await self.api.send_message(chat_id, HELP)
            return

        if command == "/version":
            await self._send(
                chat_id,
                f"TelegramGuard {__version__}\nQyAi: {PROJECT_URL}",
            )
            return

        if command == "/status":
            result = await self.helper.call("host.status")
            if not isinstance(result, dict):
                raise HelperError("invalid status response")
            total = int(result.get("memory_total", 0))
            available = int(result.get("memory_available", 0))
            used = max(total - available, 0)
            disk_total = int(result.get("disk_total", 0))
            disk_free = int(result.get("disk_free", 0))
            message = (
                f"VPS status\n"
                f"Uptime: {_uptime(int(result.get('uptime_seconds', 0)))}\n"
                f"Load: {result.get('load_1')} / {result.get('load_5')} / "
                f"{result.get('load_15')}\n"
                f"RAM: {_human_bytes(used)} / {_human_bytes(total)}\n"
                f"Disk: {_human_bytes(disk_total - disk_free)} / "
                f"{_human_bytes(disk_total)}"
            )
            self.state.audit(admin_id, "host.status", "ok")
            await self._send(chat_id, message)
            return

        if command == "/sessions":
            result = await self.helper.call("host.sessions")
            self.state.audit(admin_id, "host.sessions", "ok")
            await self._send(chat_id, f"Активные сессии\n\n{result}")
            return

        if command == "/ssh":
            minutes = 30
            if args:
                if not args[0].isdigit():
                    raise ValidationError("minutes must be numeric")
                minutes = max(1, min(int(args[0]), 180))
            result = await self.helper.call("ssh.recent", {"minutes": minutes})
            self.state.audit(
                admin_id, "ssh.recent", "ok", {"minutes": minutes}
            )
            await self._send(
                chat_id, f"SSH события за {minutes} мин.\n\n{result}"
            )
            return

        if command == "/whitelist":
            result = await self.helper.call("firewall.list")
            self.state.audit(admin_id, "firewall.list", "ok")
            await self._send(chat_id, f"Whitelist\n\n{result}")
            return

        if command == "/allow":
            if not args:
                raise ValidationError("usage: /allow <ip> [15m|1h|1d]")
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
            result = await self.helper.call("service.list")
            units = result if isinstance(result, list) else []
            self.state.audit(admin_id, "service.list", "ok")
            if not units:
                await self._send(chat_id, "Управляемые сервисы не настроены.")
            else:
                await self._send(
                    chat_id,
                    "Управляемые сервисы\n\n" + "\n".join(map(str, units)),
                )
            return

        if command == "/service":
            if len(args) != 1:
                raise ValidationError("usage: /service <unit>")
            unit = validate_unit(args[0])
            result = await self.helper.call("service.status", {"unit": unit})
            self.state.audit(
                admin_id, "service.status", "ok", {"unit": unit}
            )
            await self._send(chat_id, f"{unit}\n\n{result}")
            return

        if command == "/restart":
            if len(args) != 1:
                raise ValidationError("usage: /restart <unit>")
            unit = validate_unit(args[0])
            managed = await self.helper.call("service.list")
            if not isinstance(managed, list) or unit not in managed:
                raise ValidationError("service is not in MANAGED_SERVICES")
            await self._confirmed_request(
                chat_id,
                admin_id,
                "service.restart",
                {"unit": unit},
                f"Перезапустить {unit}?",
            )
            return

        if command == "/audit":
            count = 15
            if args:
                if not args[0].isdigit():
                    raise ValidationError("count must be numeric")
                count = max(1, min(int(args[0]), 40))
            rows = self.state.recent_audit(count)
            if not rows:
                await self._send(chat_id, "Аудит пока пуст.")
                return
            lines = []
            for row in rows:
                stamp = dt.datetime.fromtimestamp(
                    int(row["created_at"]), tz=dt.UTC
                ).strftime("%Y-%m-%d %H:%MZ")
                lines.append(
                    f"{stamp} · {row['action']} · {row['outcome']} · "
                    f"admin:{row['actor_id']}"
                )
            await self._send(chat_id, "Аудит\n\n" + "\n".join(lines))
            return

        raise ValidationError("unknown command; use /help")

    async def _execute_pending(
        self,
        callback_id: str,
        chat_id: int,
        admin_id: int,
        token: str,
    ) -> None:
        pending = self.state.consume_pending(token, admin_id)
        if pending is None:
            await self.api.answer_callback(callback_id, "Истекло или уже использовано")
            return

        action, args = pending
        result = await self.helper.call(action, args)
        self.state.audit(admin_id, action, "confirmed", args)
        await self.api.answer_callback(callback_id, "Выполнено")

        if action == "firewall.allow":
            await self._send(
                chat_id,
                f"IP {args['ip']} разрешён на "
                f"{format_ttl(int(args['ttl_seconds']))}.",
            )
        elif action == "firewall.revoke":
            removed = bool(result.get("removed")) if isinstance(result, dict) else False
            suffix = "удалён" if removed else "уже отсутствовал"
            await self._send(chat_id, f"IP {args['ip']} {suffix} в whitelist.")
        elif action == "service.restart":
            await self._send(
                chat_id, f"{args['unit']} перезапущен.\n\n{result}"
            )
        else:
            await self._send(chat_id, "Действие выполнено.")

    async def handle_update(self, update: dict[str, Any]) -> None:
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            user = callback.get("from", {})
            user_id = int(user.get("id", 0)) if isinstance(user, dict) else 0
            callback_id = str(callback.get("id", ""))
            if not self._is_admin(user_id):
                if callback_id:
                    await self.api.answer_callback(callback_id, "Not authorized")
                return
            if not self.rate.allow(user_id):
                await self.api.answer_callback(callback_id, "Rate limit")
                return

            message = callback.get("message", {})
            chat = message.get("chat", {}) if isinstance(message, dict) else {}
            chat_id = int(chat.get("id", 0)) if isinstance(chat, dict) else 0
            data = str(callback.get("data", ""))

            if data.startswith("cancel:"):
                token = data.split(":", 1)[1]
                self.state.consume_pending(token, user_id)
                self.state.audit(user_id, "confirmation", "cancelled")
                await self.api.answer_callback(callback_id, "Отменено")
                return

            if data.startswith("confirm:") and chat_id:
                token = data.split(":", 1)[1]
                await self._execute_pending(
                    callback_id, chat_id, user_id, token
                )
            return

        message = update.get("message")
        if not isinstance(message, dict):
            return
        user = message.get("from", {})
        chat = message.get("chat", {})
        user_id = int(user.get("id", 0)) if isinstance(user, dict) else 0
        chat_id = int(chat.get("id", 0)) if isinstance(chat, dict) else 0
        if not self._is_admin(user_id) or not chat_id:
            return
        if not self.rate.allow(user_id):
            await self._send(chat_id, "Слишком много запросов. Повтори позже.")
            return

        text = str(message.get("text", "")).strip()
        if not text.startswith("/"):
            return

        first, *args = text.split()
        command = first.split("@", 1)[0].lower()

        try:
            await self._read_command(chat_id, user_id, command, args)
        except ValidationError as exc:
            self.state.audit(
                user_id, command.lstrip("/"), "denied", {"reason": str(exc)}
            )
            await self._send(chat_id, f"Отклонено: {exc}")
        except HelperError:
            self.state.audit(user_id, command.lstrip("/"), "helper_error")
            await self._send(
                chat_id,
                "Локальный privileged helper недоступен или отклонил запрос.",
            )
        except Exception:
            self.state.audit(user_id, command.lstrip("/"), "error")
            await self._send(
                chat_id,
                "Действие не выполнено. Подробности оставлены только в локальном журнале.",
            )

    async def run(self) -> None:
        with contextlib.suppress(TelegramAPIError):
            await self.api.set_commands()

        offset: int | None = None
        print(f"{BRAND}: bot started", flush=True)
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
