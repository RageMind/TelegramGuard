# TelegramGuard v0.6.1: SSH approval memory

This feature solves repeated *PAM Telegram 2FA* prompts for the same authenticated SSH user from the same source IP. It is separate from the nftables SSH IP whitelist.

## Telegram buttons

During a pending SSH login the admin sees:
- Разрешить 1 раз / Отклонить
- Разрешить 10 ч / Разрешить 20 ч
- Разрешить 1 день / Разрешить 2 дня
- Разрешить 3 дня / Разрешить 7 дней

A timed approval both approves the **current** pending login and stores an exact **SSH username + IP + service=sshd** grace period for the selected duration. Every subsequent SSH attempt must still complete OpenSSH password/public-key authentication. Only its PAM Telegram approval is skipped. Other usernames, IPs, services and expired grants still need Telegram approval.

The grants live in the **existing bot SQLite state DB** (default `/var/lib/telegram-guard/state.sqlite3`) and survive bot restarts. Expiry is enforced against Unix time on every new login (no cron timer required). No wildcard IP/user and no permanent Telegram-PAM bypass is supported; maximum 7 days.

In Telegram: **Доступ → Доверенные SSH IP** shows user, IP, time remaining and expiry. Each grant may be revoked via a dedicated confirmation. It revokes **future** new logins, not existing SSH sessions. Audited grant, auto-trusted login and revoke events appear in the TelegramGuard audit log.

The original **IP whitelist** screen also gets 10h, 20h, 2d, 3d buttons; these permit traffic at the firewall only when nftables mode is ON. The two permissions do not implicitly enable each other.

## Threat model / caveats

- **IP address is not a second factor.** A trusted address might be shared (office VPN, NAT, CGNAT, proxy, public Wi-Fi); if an attacker knows valid SSH credentials from that IP they can skip Telegram 2FA during the grace interval. Prefer 10h, revoke after use, and require SSH keys.
- A change of mobile carrier/public IP will require a new Telegram grant. This is expected and fail-closed.
- The broker checks `SO_PEERCRED` root on its Unix socket before applying any trust. PAM checks a valid authenticated SSH account first. A stopped bot, malformed requests or database failures must block the login in PAM, not bypass it.
- Never make IP-based trust a permanent bypass. Automatic expiry and admin-controlled revocation are mandatory.
- A trusted SSH login may still be blocked by nftables. Do not disable or flush firewall as a troubleshooting shortcut.

## VPS installation on your existing QYAI host

Keep your **current working SSH session open**, and have console/recovery access. This update restarts the TelegramGuard service and may briefly make new SSH logins unavailable when 2FA is active.

```bash
set -e
cd /opt/telegramguard-src
test -d .git
git status --short
git fetch origin feature/ssh-trusted-ip-expiring-20261012
git switch -c feature/ssh-trusted-ip-expiring-20261012 --track origin/feature/ssh-trusted-ip-expiring-20261012
python3 -m compileall -q src tests
sudo bash packaging/install.sh
systemctl is-active telegram-guard telegram-guard-helper
/opt/telegram-guard/venv/bin/python -c 'from telegram_guard import __version__; print(__version__)'
```

If branch is already present locally, use `git switch feature/ssh-trusted-ip-expiring-20261012 && git pull --ff-only`. If `git status --short` shows local edits, do **not** discard them. Stop and reconcile before switching.

The existing Telegram token, allowed admin IDs, helper mode, and bot state database must be preserved; do not copy the sample env over live env. Do not run the installer unless the new source has passed `python -m compileall` and its tests.

## Acceptance test

1. From a current valid SSH IP, authenticate and select **Разрешить 10 ч**.
2. Verify an entirely **new** SSH session from **the same IP and username** requires usual SSH authentication but does not request Telegram approval again.
3. In Telegram **Доступ → Доверенные SSH IP**, verify countdown.
4. Verify a different SSH username/IP still triggers a Telegram request.
5. Revoke the grant and verify that the next new session again requires Telegram approval.
6. Verify service restart preserves the grant, and expiry requires Telegram approval again.

This feature has no effect on the QYAI web apps and does not change OpenSSH/PAM config or unrelated systemd services.
