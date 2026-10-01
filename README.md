# TelegramGuard

<p align="center">
  <img src="assets/telegramguard-mark.svg" width="760" alt="TelegramGuard by QyAi">
</p>

<p align="center">
  <strong>Telegram-first control plane for a private VPS.</strong><br>
  Whitelist access, review SSH activity, inspect host health, and run a small set of explicitly allowed administrative actions without exposing a general remote shell.
</p>

<p align="center">
  <a href="https://qyai.ru">QyAi</a> · Built for defensive server administration · Apache-2.0
</p>

> [!IMPORTANT]
> TelegramGuard is intentionally **not** a “run any shell command from Telegram” bot. The public design uses an unprivileged Telegram process and a separate local root helper with a finite allowlist of actions.

## What it does

- Telegram admin authorization by numeric user ID, never by mutable username.
- Temporary IPv4/IPv6 whitelist entries with TTL through pre-existing nftables sets.
- Revoke and list current whitelist entries.
- VPS health summary: uptime, load, memory and filesystem usage.
- Active login/session view.
- Recent SSH security events from journald.
- Status and restart for explicitly allowlisted systemd services.
- Two-step confirmation for service restarts and other sensitive actions.
- Local SQLite audit trail.
- Unix-socket privilege separation between the bot and the root helper.
- Rate limiting, strict input validation and bounded output.
- No arbitrary command execution, no `shell=True`, no remote Docker socket.
- Public-repository safety scanner that rejects common secret formats and accidental real IP addresses.

## Security model

```text
Telegram
   │ HTTPS long polling
   ▼
telegram-guard (unprivileged)
   │ authenticated admin ID
   │ validated request
   ▼
/run/telegram-guard/helper.sock
   │ local Unix socket, group-restricted
   ▼
telegram-guard-helper (root)
   │ fixed action registry only
   ├── nft
   ├── journalctl
   ├── systemctl (allowlisted units)
   └── local host metrics
```

The root helper does not accept arbitrary executable names or shell fragments. Every privileged action has its own validator and subprocess argument vector.

## Quick start

Requirements:

- Ubuntu/Debian-style Linux with systemd;
- Python 3.11+;
- nftables if whitelist control is enabled;
- a Telegram bot token;
- your numeric Telegram user ID.

```bash
git clone https://github.com/RageMind/TelegramGuard.git
cd TelegramGuard
sudo ./packaging/install.sh
```

The installer creates the service account and systemd units, but **does not edit SSH or firewall policy and does not start the services**.

Then:

```bash
sudo cp /etc/telegram-guard/bot.env.example /etc/telegram-guard/bot.env
sudo cp /etc/telegram-guard/helper.env.example /etc/telegram-guard/helper.env
sudo chmod 600 /etc/telegram-guard/bot.env /etc/telegram-guard/helper.env
sudoedit /etc/telegram-guard/bot.env
sudoedit /etc/telegram-guard/helper.env

sudo systemctl enable --now telegram-guard-helper
sudo systemctl enable --now telegram-guard
```

See [docs/INSTALL.md](docs/INSTALL.md) before enabling whitelist enforcement.

## Telegram commands

| Command | Purpose |
| --- | --- |
| `/status` | Host uptime, load, memory and disk |
| `/sessions` | Logged-in sessions |
| `/ssh [minutes]` | Recent SSH security events |
| `/allow <ip> [ttl]` | Add a temporary whitelist entry |
| `/revoke <ip>` | Remove a whitelist entry |
| `/whitelist` | List active whitelist entries |
| `/services` | Show managed systemd units |
| `/restart <unit>` | Request a confirmed restart of an allowlisted unit |
| `/audit [count]` | Show recent TelegramGuard audit entries |
| `/help` | Command help |

TTL examples: `15m`, `1h`, `8h`, `1d`. Permanent entries are intentionally not created from Telegram.

## Firewall integration

TelegramGuard manages nftables **sets**, not your whole firewall. This is deliberate.

By default:

```env
FIREWALL_MODE=observe
```

In observe mode, whitelist mutation commands are disabled.

To use nftables mode, create the table/sets yourself (an example is in [packaging/nftables/telegram-guard.nft.example](packaging/nftables/telegram-guard.nft.example)), verify you still have console access, then set:

```env
FIREWALL_MODE=nft
NFT_TABLE=telegram_guard
NFT_IPV4_SET=trusted_ipv4
NFT_IPV6_SET=trusted_ipv6
```

TelegramGuard will refuse to create missing tables, chains, or sets automatically. That prevents a bad deployment from silently replacing the host firewall.

## Public-repository hygiene

This repository contains no deployment-specific values. Runtime secrets and identity data belong in `/etc/telegram-guard/*.env` and `/var/lib/telegram-guard/`, both outside the repository.

Before every CI build:

```bash
python scripts/public_safety_scan.py .
```

The scanner rejects:

- Telegram bot tokens;
- GitHub/OpenAI/Hugging Face/Slack-style token patterns;
- private key blocks;
- non-documentation public IPv4 addresses;
- committed `.env`, SQLite databases, logs and key files.

If you find a security issue, follow [SECURITY.md](SECURITY.md) and do not open a public exploit report.

## Design principles

1. **Least privilege.** Telegram handling runs without root.
2. **No generic RCE.** Administrative operations are explicit capabilities.
3. **Fail closed.** Invalid IDs, IPs, TTLs, units and callbacks are denied.
4. **Short-lived access.** Whitelist changes from chat require TTLs.
5. **Human confirmation.** Sensitive changes use single-use confirmation tokens.
6. **Auditability.** Every accepted or denied administrative request is recorded.
7. **Safe by default.** Firewall write mode is off until explicitly configured.
8. **No deployment identity in Git.** Tokens, real IPs, chat IDs and hostnames are runtime configuration.

## Project layout

```text
src/telegram_guard/        application + privileged helper
packaging/systemd/         hardened systemd units
packaging/nftables/        optional nftables integration example
scripts/                   public-repo safety tooling
tests/                     unit tests
docs/                      deployment and security documentation
```

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
ruff check .
mypy src
pytest
python scripts/public_safety_scan.py .
```

## Brand

**TelegramGuard** is a QyAi project.

- Product: TelegramGuard
- Creator: QyAi
- Website: https://qyai.ru
- Source: https://github.com/RageMind/TelegramGuard

The QyAi/TelegramGuard mark in this repository is project branding, not an authentication mechanism.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright © 2026 QyAi.
