# TelegramGuard — Product Specification

Version: 1.0 draft  
Project: TelegramGuard  
Company: QyAi  
Scope: Telegram-first VPS Control OS

## 1. Product goal

TelegramGuard must turn a fresh Linux VPS into a remotely manageable, private control surface that can be operated from Telegram without exposing a generic shell.

The product is not a chat bot with a list of commands. It is a compact operations console with three layers:

1. **Control UI in Telegram** — dashboards, menus, confirmations, alerts and guided flows.
2. **Local privileged helper** — a strict finite action registry with no generic shell execution.
3. **Managed host security layer** — SSH whitelist, service control, audit and health monitoring.

The product must be understandable to a non-technical owner while remaining useful to an experienced administrator.

## 2. Core product principles

- Install once; sane defaults work immediately.
- No arbitrary remote shell.
- Dangerous actions always require confirmation.
- The current administrator must not be locked out during installation.
- UI is task-oriented, not command-oriented.
- Every action is attributable and auditable.
- Public repository contains no deployment identity or secrets.
- Telegram is a control plane, not the storage location for secrets.
- A broken Telegram connection must never leave the VPS in an unsafe transient state.
- The visual system must feel like a small operating system, not a support bot.

## 3. Installation outcome

A successful installation on a supported fresh VPS must result in:

- `telegram-guard.service` active;
- `telegram-guard-helper.service` active;
- bot profile configured;
- Telegram admin authenticated by numeric ID;
- SSH port detected automatically;
- current SSH client IP pinned as bootstrap access;
- nftables managed whitelist active when safe bootstrap conditions are met;
- emergency local rollback command installed;
- status/self-test report shown after install;
- `/start` opening the control dashboard immediately.

If safe bootstrap conditions cannot be established, the installer must remain in observe mode and state the exact reason.

## 4. Main user journeys

### 4.1 First launch

`/start` opens **Control Center**.

User sees:

- VPS online/offline state;
- uptime;
- RAM usage;
- disk usage;
- SSH whitelist state;
- security alert count;
- managed service count;
- last administrative action.

Primary buttons:

- System
- Access
- Security
- Services
- Activity
- Settings

### 4.2 Grant temporary access

Flow:

1. Open Access.
2. Press “Grant access”.
3. Enter an IP or select current requester IP if available.
4. Choose TTL: 15m / 1h / 8h / 1d / custom up to 7d.
5. Review.
6. Confirm.
7. TelegramGuard writes the entry into persistent state and applies nftables.
8. UI shows expiry time and active state.

### 4.3 Revoke access

Flow:

1. Open Access.
2. Select an existing entry.
3. Press Revoke.
4. Confirm.
5. Rule is removed and state is persisted.
6. UI updates in the same dashboard message.

### 4.4 Restart a service

Flow:

1. Open Services.
2. Select allowlisted service.
3. View active/sub state and recent status.
4. Press Restart.
5. Confirm.
6. Execute and verify.
7. Show resulting status and log the action.

## 5. Functional modules

### System

- uptime;
- load 1/5/15;
- RAM total/used/free;
- disk total/used/free;
- active user sessions;
- basic network identity without exposing secrets;
- helper status;
- bot status;
- firewall health.

### Access

- active whitelist entries;
- IPv4 + IPv6;
- TTL;
- source;
- added-at;
- expires-at;
- permanent bootstrap entry indicator;
- add;
- revoke;
- extend;
- convert temporary to permanent only through an advanced confirmation flow;
- firewall health;
- emergency status.

### Security

- recent SSH authentication events;
- failed SSH attempts summary;
- current sessions;
- whitelist status;
- denied/invalid admin actions;
- helper availability;
- security posture summary.

### Services

- configured allowlist;
- active state;
- substate;
- restart;
- optional start/stop in a later milestone;
- bounded recent journal output;
- confirmation for mutating operations.

### Activity

- local audit;
- action;
- actor;
- time;
- target;
- outcome;
- reason;
- pagination;
- export later.

### Settings

- managed services;
- SSH port;
- firewall mode;
- UI language;
- alert thresholds;
- notification preferences;
- QyAi branding visibility;
- backup/export in later milestone.

## 6. Product limits

TelegramGuard must never expose:

- arbitrary command execution;
- arbitrary filesystem browsing;
- unrestricted systemctl access;
- unrestricted nftables commands;
- raw Docker socket access;
- SSH private keys;
- stored Telegram token in UI;
- full environment dumps;
- unbounded journal output.

## 7. Branding

Product identity:

- Brand: **TelegramGuard**
- Company: **QyAi**
- Website: **qyai.ru**
- Repository: **RageMind/TelegramGuard**

Required visual assets:

- `assets/telegramguard-mark.svg`
- QyAi logo asset when supplied in source quality;
- Telegram bot avatar;
- Telegram welcome/control-center banner;
- GitHub social preview;
- Mini App app icon in future release.

No third-party template attribution may appear in the UI.

## 8. Definition of Done

TelegramGuard v1 is considered ready when:

- clean install succeeds on supported Ubuntu;
- bot and helper are active after installation;
- managed whitelist works immediately when installation is performed over SSH;
- current admin connection remains whitelisted;
- access add/revoke works from Telegram;
- service restart confirmation works;
- status screens are understandable without knowing Linux commands;
- no generic RCE exists;
- audit is complete;
- CI is green;
- public safety scan is green;
- README and docs match actual behavior;
- visual dashboard no longer depends on memorizing slash commands.
