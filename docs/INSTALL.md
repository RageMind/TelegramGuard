# Installation

This guide assumes a systemd-based Linux host and a fresh checkout of TelegramGuard.

## 1. Install

```bash
sudo ./packaging/install.sh
```

The script:

- creates the `telegram-guard` system account;
- creates `/etc/telegram-guard`, `/var/lib/telegram-guard` and `/run/telegram-guard`;
- installs an isolated Python virtual environment under `/opt/telegram-guard`;
- installs hardened systemd units;
- places configuration examples under `/etc/telegram-guard`;
- does **not** start services;
- does **not** edit SSH;
- does **not** edit or activate firewall rules.

## 2. Configure the bot

```bash
sudo cp /etc/telegram-guard/bot.env.example /etc/telegram-guard/bot.env
sudoedit /etc/telegram-guard/bot.env
```

Set:

```env
TELEGRAM_BOT_TOKEN=replace_with_your_token
TELEGRAM_ADMIN_IDS=replace_with_your_numeric_user_id
```

Multiple admins are comma-separated.

Then protect the file:

```bash
sudo chown root:telegram-guard /etc/telegram-guard/bot.env
sudo chmod 640 /etc/telegram-guard/bot.env
```

## 3. Configure the helper

```bash
sudo cp /etc/telegram-guard/helper.env.example /etc/telegram-guard/helper.env
sudoedit /etc/telegram-guard/helper.env
sudo chown root:root /etc/telegram-guard/helper.env
sudo chmod 600 /etc/telegram-guard/helper.env
```

Keep `FIREWALL_MODE=observe` for the first start.

Choose systemd units you actually want to manage:

```env
MANAGED_SERVICES=ssh.service,nginx.service
```

## 4. Start in observe mode

```bash
sudo systemctl enable --now telegram-guard-helper
sudo systemctl enable --now telegram-guard
sudo systemctl status telegram-guard-helper telegram-guard
```

In Telegram, run:

```text
/status
/services
/sessions
```

## 5. Optional whitelist mode

First install the example sets manually:

```bash
sudo nft -f packaging/nftables/telegram-guard.nft.example
sudo nft list table inet telegram_guard
```

This example defines sets only. It does not block SSH by itself.

Integrate the sets into your existing firewall **only after verifying you have an out-of-band recovery path**. A conceptual allow expression looks like:

```text
tcp dport <your-ssh-port> ip saddr @trusted_ipv4 accept
tcp dport <your-ssh-port> ip6 saddr @trusted_ipv6 accept
```

The exact placement depends on your firewall policy.

Test with documentation-only address syntax, not a real value in public notes:

```text
/allow 203.0.113.42 15m
```

Then set:

```env
FIREWALL_MODE=nft
```

and restart only the helper:

```bash
sudo systemctl restart telegram-guard-helper
```

## 6. Verify

```bash
sudo systemctl --no-pager --full status telegram-guard-helper telegram-guard
sudo journalctl -u telegram-guard -u telegram-guard-helper --since "10 minutes ago" --no-pager
```

Do not paste production logs into public issues without redaction.

QyAi • https://qyai.ru
