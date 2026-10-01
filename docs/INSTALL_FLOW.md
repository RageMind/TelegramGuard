# TelegramGuard — Zero-VPS Installation Flow

## 1. Goal

A new VPS installation must end in a working TelegramGuard instance, not a half-configured package.

The installer owns the setup lifecycle until the bot, helper and managed access layer are either verified or explicitly left in observe mode.

## 2. Supported happy path

Preconditions:

- Ubuntu/Debian-style systemd host;
- Python 3.11+;
- nftables available;
- installation performed from an active SSH session;
- Telegram bot token;
- numeric Telegram administrator ID.

Expected result:

- bot configured;
- helper configured;
- current SSH source IP pinned;
- SSH port detected from `SSH_CONNECTION`;
- managed nftables whitelist enabled;
- services started;
- self-check passed;
- recovery command installed.

## 3. Install phases

### Phase A — Preflight

Check:

- root privileges;
- Python version;
- nft binary;
- systemd;
- write permissions;
- existing installation;
- valid SSH session metadata.

### Phase B — Runtime

Create:

- service user/group;
- `/opt/telegram-guard`;
- `/etc/telegram-guard`;
- `/var/lib/telegram-guard`;
- venv;
- package install;
- systemd units.

### Phase C — Identity

Use existing bot configuration if present.

Otherwise obtain:

- Telegram bot token;
- numeric Telegram admin ID.

Secrets must not be printed back to terminal or stored in the repository.

### Phase D — Firewall bootstrap

If a valid SSH session exists:

- detect client IP;
- detect server SSH port;
- write persistent bootstrap entry;
- configure `FIREWALL_MODE=nft`;
- generate managed table and sets;
- start helper;
- verify table exists.

If any required condition is missing:

- remain in observe mode;
- explain why.

### Phase E — Start and verify

Start:

- helper first;
- bot second.

Verify:

- helper active;
- bot active;
- helper socket exists;
- firewall health reports active when managed mode is selected;
- bootstrap entry exists.

### Phase F — Recovery

Install local recovery command:

`/usr/local/sbin/telegram-guard-firewall-off`

The recovery action:

- deletes TelegramGuard's own nftables table only;
- switches helper back to observe mode;
- restarts helper;
- never edits unrelated firewall tables.

## 4. Reinstall / update behavior

Running installer again must be idempotent:

- preserve bot token/admin IDs;
- preserve whitelist state;
- preserve managed service list;
- update Python package;
- update systemd units;
- reapply managed firewall;
- restart services;
- re-run health checks.

## 5. Safety rules

- Never replace the entire host firewall.
- Never flush global nftables rules.
- Never change SSH port.
- Never modify `sshd_config`.
- Never enable managed mode without a validated bootstrap IP.
- Never delete existing access state during update.
- Never print secrets.

## 6. Failure behavior

If helper fails after firewall activation:

1. disable TelegramGuard managed table;
2. switch to observe mode;
3. preserve logs and configuration;
4. exit non-zero with recovery instructions.

If bot fails but helper/firewall are healthy:

- leave bootstrap IP intact;
- report bot failure;
- do not widen SSH access.

## 7. Installer UX

Final summary must state:

- Bot: RUNNING / NOT CONFIGURED
- Helper: RUNNING / FAILED
- SSH whitelist: ACTIVE / OBSERVE
- SSH port
- bootstrap protection state
- recovery command
- next Telegram action: `/start`

## 8. Definition of Done

A fresh VPS setup should require:

1. clone;
2. run installer;
3. provide token + admin ID once;
4. open Telegram;
5. press `/start`.

No manual editing of helper.env or nftables should be required for the supported happy path.
