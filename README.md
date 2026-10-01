# TelegramGuard

<p align="center">
  <img src="assets/telegramguard-mark.svg" width="760" alt="TelegramGuard by QyAi">
</p>

<p align="center">
  <strong>Telegram-first VPS Control OS by QyAi.</strong><br>
  Manage access, inspect SSH activity, watch server health, control approved services and audit sensitive actions without exposing a generic remote shell.
</p>

<p align="center">
  <a href="https://qyai.ru">QyAi</a> · Apache-2.0 · Linux / systemd · Python 3.11+
</p>

> TelegramGuard is built for defensive server administration. It intentionally does not provide arbitrary shell execution, unrestricted filesystem access, SSH key storage, or direct Docker socket access.

## What the project is

TelegramGuard turns Telegram into a compact control surface for a private VPS.

The interface is organized like a small operating system rather than a command bot:

- **System** — uptime, RAM, disk, load, sessions;
- **Access** — managed SSH whitelist, TTL, grant/revoke/extend;
- **Security** — whitelist health, SSH successes/failures, active sessions;
- **Services** — allowlisted systemd units, status, logs, confirmed restart;
- **Activity** — local administrative audit;
- **Settings** — runtime configuration summary and self-test.

Slash commands remain a fallback. Normal use starts from `/start` and the inline control panel.

## Security architecture

```text
Telegram private chat
        │
        ▼
telegram-guard
unprivileged service
        │
        │ local Unix socket
        ▼
telegram-guard-helper
root, finite action registry
        │
        ├── nftables managed SSH whitelist
        ├── systemd allowlisted services
        ├── journald bounded reads
        └── local host metrics
```

The privileged helper has no generic `exec` action. Every privileged operation has a dedicated action name, argument validation and bounded output.

## Zero-VPS install

Supported happy path: Ubuntu/Debian-style systemd host, active SSH session, bot token and numeric Telegram user ID.

```bash
apt-get update
apt-get install -y git

git clone --depth 1 https://github.com/RageMind/TelegramGuard.git /opt/telegramguard-src
cd /opt/telegramguard-src

sudo ./packaging/install.sh
```

The installer can install missing Python/venv/nftables dependencies on apt-based systems.

On first setup it asks for:

- Telegram bot token;
- numeric Telegram administrator ID.

When installation runs from a valid SSH session, TelegramGuard:

1. detects the SSH source IP;
2. detects the current SSH port;
3. stores the current source as a protected bootstrap entry;
4. enables its own managed nftables table;
5. starts helper and bot;
6. verifies both services.

Then open the bot and send:

```text
/start
```

### Important safety behavior

TelegramGuard manages only its own nftables table. It does not flush the host firewall, change the SSH port, or edit `sshd_config`.

A protected bootstrap entry cannot be revoked from Telegram.

Emergency local recovery:

```bash
sudo /usr/local/sbin/telegram-guard-firewall-off
```

That command deletes only TelegramGuard's managed table and switches the helper back to observe mode.

## Update

```bash
cd /opt/telegramguard-src
git pull --ff-only
sudo ./packaging/install.sh
```

Re-running the installer is designed to preserve:

- bot identity configuration;
- existing managed whitelist state;
- bootstrap entry;
- managed service list.

## Local diagnostics

```bash
sudo /opt/telegram-guard/venv/bin/telegram-guard-doctor
```

Machine-readable output:

```bash
sudo /opt/telegram-guard/venv/bin/telegram-guard-doctor --json
```

The doctor command intentionally does not print the bot token or other secrets.

## Telegram UI

The visible command menu is intentionally short:

| Command | Purpose |
| --- | --- |
| `/start` | Open Control Center |
| `/status` | Open System |
| `/help` | Open Control Center / help |

Advanced command compatibility remains available for administrators, but the project is designed to be operated through buttons and guided flows.

### Access manager

The Access screen shows structured whitelist entries.

Temporary access supports:

- 15 minutes;
- 1 hour;
- 8 hours;
- 1 day;
- 7 days;
- custom TTL up to 7 days;
- extension from the entry detail screen;
- confirmed revoke.

Bootstrap access is visually marked and protected.

### Service control

Only units in `MANAGED_SERVICES` can be accessed.

Supported operations:

- list;
- status;
- bounded recent logs;
- confirmed restart.

There is no unrestricted `systemctl` command path.

## Runtime files

Runtime identity and secrets stay outside Git:

```text
/etc/telegram-guard/bot.env
/etc/telegram-guard/helper.env
/var/lib/telegram-guard/state.sqlite3
/var/lib/telegram-guard/firewall.json
/run/telegram-guard/helper.sock
```

Never publish these files.

## Public-repository safety

CI runs:

```bash
python scripts/public_safety_scan.py .
ruff check .
mypy src
pytest -q
```

The public safety scanner rejects common credential formats, private key blocks, runtime databases/logs and non-documentation public IPv4 literals.

CodeQL and Dependabot are also configured.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

python scripts/public_safety_scan.py .
ruff check .
mypy src
pytest -q
```

## Documentation

- [Product specification](docs/PRODUCT_SPEC.md)
- [Telegram Control OS UX](docs/UX_SPEC.md)
- [Zero-VPS install flow](docs/INSTALL_FLOW.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Hardening](docs/HARDENING.md)
- [Roadmap](docs/ROADMAP.md)
- [Public release checklist](docs/PUBLIC_RELEASE.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## Project principles

1. Least privilege.
2. Private-chat administration only.
3. No generic remote command execution.
4. Short-lived access by default.
5. Human confirmation for sensitive operations.
6. Persistent audit.
7. Fail closed on malformed input.
8. Deployment identity never belongs in public Git.
9. UI should be usable without memorizing Linux commands.
10. Local recovery must remain possible when Telegram is unavailable.

## Brand

**TelegramGuard** is a QyAi project.

- Product: TelegramGuard
- Company: QyAi
- Website: https://qyai.ru
- Source: https://github.com/RageMind/TelegramGuard

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright © 2026 QyAi.
