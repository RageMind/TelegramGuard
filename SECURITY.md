# Security Policy

TelegramGuard is security-sensitive infrastructure software.

## Supported versions

Security fixes are applied to the current `main` branch until tagged releases are introduced.

## Reporting a vulnerability

Do **not** publish working exploits, server addresses, bot tokens, Telegram IDs, SSH material, firewall dumps, or other deployment-specific data in a public issue.

Use GitHub's private security reporting / security advisory flow for this repository when available. If private reporting is unavailable, open a minimal issue that contains no exploit details and asks the maintainers for a private contact channel.

A useful report includes:

- affected commit or version;
- security impact;
- preconditions;
- minimal reproduction with fake/documentation-only values;
- suggested mitigation, if known.

## Security boundaries

TelegramGuard assumes:

- Telegram's Bot API transport is reachable over HTTPS;
- the bot token is secret and stored outside Git;
- admin authorization uses immutable numeric Telegram user IDs;
- administrative commands and callback actions are accepted only in private chats;
- the unprivileged bot cannot become root;
- only the local root helper can perform privileged operations;
- the helper socket is accessible only to the TelegramGuard service group;
- managed systemd units are explicitly allowlisted;
- nftables sets already exist before write mode is enabled.

TelegramGuard deliberately does **not** provide:

- arbitrary shell execution;
- arbitrary file read/write;
- SSH private-key management;
- Docker socket access;
- automatic edits to `sshd_config`;
- automatic replacement of a host firewall;
- CAPTCHA / MFA bypass or credential collection.

## Secret handling

Never commit:

- bot tokens;
- real Telegram admin IDs;
- VPS IP addresses or hostnames;
- SSH keys;
- cloud API credentials;
- production environment files;
- runtime SQLite databases;
- exported logs.

CI runs `scripts/public_safety_scan.py` to catch common mistakes, but scanners are not a substitute for review.

QyAi • https://qyai.ru
