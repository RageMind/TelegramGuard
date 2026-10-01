# TelegramGuard — Compatibility Matrix

This document defines the supported deployment envelope for the public project.

## Supported target

### Operating system

Primary tested target:

- Ubuntu 24.04 LTS
- systemd
- Python 3.11+
- nftables
- root access for installation

Expected compatible, but requiring release validation before being called fully supported:

- Ubuntu 22.04 LTS with Python 3.11+ available
- Debian 12 with systemd and nftables

## Installation modes

### Managed SSH whitelist

Requirements:

- install is executed from an active SSH session;
- `SSH_CONNECTION` is available and valid;
- the current source address can be parsed as IPv4/IPv6;
- the Telegram bot identity is configured;
- nftables is available.

The installer pins the current source address as protected bootstrap access before starting managed mode.

### Observe mode

Used when a safe bootstrap cannot be established.

Observe mode keeps the bot/helper usable for read-only/status features but does not enforce SSH whitelist writes.

## Firewall coexistence

TelegramGuard owns only its configured nftables table (default `inet telegram_guard`).

It does not:

- flush the global nftables ruleset;
- modify UFW configuration;
- modify firewalld configuration;
- replace unrelated tables/chains;
- change the SSH port;
- edit `sshd_config`.

Hosts with an existing firewall should verify policy interaction before relying on TelegramGuard as the only SSH access layer.

## Network

Required outbound access:

- Telegram Bot API over HTTPS;
- package repositories during installation/update;
- GitHub only when installing/updating from GitHub.

No inbound HTTP service is exposed by TelegramGuard.

## Telegram

Administrative control requires:

- a bot token stored locally outside Git;
- one or more immutable numeric Telegram user IDs;
- private chat with the bot.

Group/channel administration is intentionally rejected.

## Recovery

Provider console or equivalent out-of-band recovery is recommended before enabling any remote firewall automation.

Local emergency rollback:

```bash
/usr/local/sbin/telegram-guard-firewall-off
```

This removes only TelegramGuard's managed nftables table and returns the helper to observe mode.

## Unsupported by design

- non-systemd init systems;
- Windows hosts;
- unrestricted remote shell;
- arbitrary systemd unit control;
- unrestricted nftables command execution;
- Docker socket administration;
- SSH key custody.
