# Architecture

## Overview

TelegramGuard separates network-facing Telegram code from privileged host control.

```text
┌──────────────────────┐
│ Telegram Bot API     │
└──────────┬───────────┘
           │ HTTPS
┌──────────▼───────────┐
│ telegram-guard       │  user: telegram-guard
│ - admin ID check     │
│ - rate limit         │
│ - validation         │
│ - confirmations      │
│ - audit              │
└──────────┬───────────┘
           │ Unix socket
           │ /run/telegram-guard/helper.sock
┌──────────▼───────────┐
│ root helper          │  user: root
│ finite action set    │
├──────────────────────┤
│ host.status          │
│ host.sessions        │
│ ssh.recent           │
│ firewall.allow       │
│ firewall.revoke      │
│ firewall.list        │
│ service.list         │
│ service.status       │
│ service.restart      │
└──────────────────────┘
```

There is no generic `exec` action.

## Trust boundaries

### Telegram boundary

A message is trusted only after the sender's numeric Telegram user ID matches `TELEGRAM_ADMIN_IDS`.

Usernames, display names, chat titles and message text are untrusted.

### Bot/helper boundary

The helper listens on a local Unix socket owned by `root:telegram-guard` with mode `0660`.

The helper still validates every action and argument because local authorization alone is not sufficient input validation.

### Firewall boundary

The helper can only add/delete elements in configured nftables sets. It does not create tables, chains, rules or policies.

This prevents a compromised bot process from replacing the firewall architecture.

### systemd boundary

Only units in `MANAGED_SERVICES` can be queried/restarted through privileged actions. Unit names are validated before any subprocess call.

## Confirmation flow

```text
/admin command
      │
      ▼
validate input
      │
      ▼
store random single-use token
(action + args + admin + expiry)
      │
      ▼
Telegram confirm / cancel buttons
      │
      ▼
consume token atomically
      │
      ▼
call root helper once
      │
      ▼
audit result
```

Confirmation tokens expire quickly and are bound to one admin.

## Data

SQLite contains only local runtime state:

- audit events;
- pending confirmation tokens.

It is stored outside Git at `/var/lib/telegram-guard/state.sqlite3`.

## Failure modes

- Telegram unavailable → no privileged action is performed.
- Invalid sender → ignored.
- Helper unavailable → bot reports a local control-plane failure.
- nftables set missing → whitelist mutation fails closed.
- service not allowlisted → denied.
- confirmation expired/reused → denied.
- malformed helper request → denied.

QyAi • https://qyai.ru
