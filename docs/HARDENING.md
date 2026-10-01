# Hardening Guide

TelegramGuard is designed to complement host security, not replace it.

## Recommended baseline

- Use SSH public-key authentication.
- Disable password login when operationally possible.
- Disable direct root SSH login.
- Keep a provider console / rescue path before enforcing a strict whitelist.
- Apply OS security updates.
- Use a host firewall with an explicit policy you understand.
- Run TelegramGuard's bot process as the dedicated unprivileged user.
- Keep the bot token in `/etc/telegram-guard/bot.env`, mode `0640` or stricter.
- Keep helper configuration root-owned.
- Keep `FIREWALL_MODE=observe` until nftables sets are tested.
- Use short whitelist TTLs.
- Restrict `MANAGED_SERVICES` to only what is genuinely required.
- Review the local audit log.

## SSH

TelegramGuard never edits `sshd_config`.

A common hardened configuration uses key-only authentication and a separate console recovery path. Validate changes with:

```bash
sshd -t
```

before reloading SSH.

## nftables

The included example creates only named sets. Your firewall should reference those sets explicitly.

Do not paste an unfamiliar full firewall ruleset onto a remote server. A mistake can lock you out.

## systemd sandboxing

The packaged services use systemd hardening directives. If your distribution needs a compatibility change, prefer relaxing one directive at a time instead of running the bot as root.

## Telegram

- Never paste the bot token into chat screenshots or issue reports.
- Numeric admin IDs are secrets only in a privacy sense, not authentication secrets. Still keep them out of public Git.
- Regenerate the bot token through BotFather if it is ever exposed.
- Remove former administrators immediately from `TELEGRAM_ADMIN_IDS`.

## Logs

TelegramGuard bounds command output, but SSH journal entries may contain usernames and source addresses. Treat service logs as private operational data.

## Backups

Back up configuration securely, not in the public repository. The SQLite audit database is optional to back up and may contain operational metadata.

QyAi • https://qyai.ru
