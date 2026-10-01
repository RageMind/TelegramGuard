# TelegramGuard — Telegram Control OS UX Specification

## 1. UX objective

TelegramGuard must feel like a compact operating system embedded inside Telegram.

The user should navigate by buttons and screens, not by remembering commands.

One dashboard message should be edited in place whenever possible. Notifications and completed actions may create separate messages only when useful.

## 2. Visual language

### Header

Every primary screen begins with:

`🛡 TelegramGuard   QyAi`

Then a compact divider and the screen title.

Avoid long ASCII banners and excessive emoji.

### Status colors

- 🟢 healthy / active / safe
- 🟡 attention / partially configured
- 🔴 failure / denied / unsafe
- 🔵 informational state

Color is never the only signal; always include text.

### Typography

Telegram HTML formatting:

- bold for state and section names;
- monospace only for IDs, ports, IPs and unit names;
- italic for helper text;
- no giant command dumps.

## 3. Global navigation

Home screen layout:

```text
TelegramGuard   QyAi
Control Center

🟢 VPS online
Uptime 1h 25m
RAM 19%   Disk 26%
SSH access: protected

[ System ]   [ Access ]
[ Security ] [ Services ]
[ Activity ] [ Settings ]

[ Refresh ]
```

Maximum 6 top-level destinations.

## 4. Screen specifications

### Home / Control Center

Must show only high-value information:

- VPS state;
- uptime;
- RAM percentage;
- disk percentage;
- whitelist active/inactive;
- active access entries count;
- services needing attention count.

No explanatory paragraphs unless there is a problem.

### System

Blocks:

1. Health
2. Resources
3. Sessions
4. Runtime

Buttons:

- Sessions
- SSH events
- Refresh
- Home

### Access

Healthy state:

```text
Access to VPS

🟢 SSH whitelist active
Port: 22
Trusted addresses: 2

Permanent
• <bootstrap IP> — Bootstrap

Temporary
• <IP> — 47m remaining

[ Grant access ] [ Revoke ]
[ Refresh ]      [ Home ]
```

Unhealthy state:

- exact cause;
- exact safe action;
- no vague “not connected” wording.

### Grant access wizard

Step 1: IP input  
Step 2: TTL selection  
Step 3: review  
Step 4: confirmation  
Step 5: success

If input is malformed, explain the one error and keep the wizard active.

### Security

Summary first:

- SSH protection;
- failed logins count;
- sessions count;
- helper state;
- last denied operation.

Buttons lead to details.

### Services

List only allowlisted units.

Each row:

- icon;
- service name;
- status.

Service detail:

- description;
- ActiveState;
- SubState;
- restart button;
- recent bounded logs in later milestone.

### Activity

Newest first.

Human-readable labels replace internal action names where possible.

Example:

`19:42 ✓ Access granted · 1h`

Raw technical action names may appear in a details view.

## 5. Confirmation design

Sensitive action confirmation screen must state:

- action;
- target;
- effect;
- expiry of confirmation;
- cancel option.

Buttons:

- Confirm
- Cancel

Single-use token, bound to admin, expires within 90 seconds.

## 6. Notification policy

TelegramGuard should notify only for:

- service failure;
- helper failure;
- repeated SSH authentication failures above threshold;
- bootstrap whitelist danger;
- managed firewall inactive unexpectedly;
- access granted/revoked;
- destructive action result.

Routine refreshes should not create notifications.

## 7. Slash commands

Slash commands remain a power-user fallback only.

Visible command menu should contain only:

- `/start` — Control Center
- `/status` — System
- `/help` — Control Center/help

Advanced commands may still work but do not need to be advertised.

## 8. Branding assets

Use:

- TelegramGuard/QyAi mark in bot avatar;
- a branded welcome banner when a high-quality raster asset is available;
- matching dark visual language for future Telegram Mini App.

Do not use low-resolution crops from screenshots as permanent brand assets.

## 9. Accessibility

- labels must be understandable without emoji;
- buttons use verbs;
- avoid jargon where a plain term exists;
- explain “nftables” only in Advanced/Technical details;
- use consistent Back/Home placement;
- never present raw Linux logs as the primary screen.

## 10. Acceptance tests

A first-time non-Linux user must be able to:

- find server health;
- grant 1 hour access;
- revoke access;
- find active sessions;
- restart an allowed service;
- return home;

without typing any slash command after `/start`.
