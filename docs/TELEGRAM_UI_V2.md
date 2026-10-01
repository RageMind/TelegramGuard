# Telegram UI v2 — QyAi Control OS

TelegramGuard uses Telegram as a compact operating surface, not as a scrolling command console.

## Design basis

The interface follows Telegram's current bot guidance:

- inline keyboards are preferred for navigation and settings because they can update a message in place instead of filling the chat with commands;
- Bot API 9.4 button styles are used semantically: primary for navigation, success for granting/approving, danger for destructive or deny actions;
- the bot profile exposes a minimal global command set and the menu button;
- one editable control message is preferred for normal navigation;
- critical access requests remain separate notifications so they cannot be hidden inside the dashboard state.

Official references:

- https://core.telegram.org/bots/features
- https://core.telegram.org/bots/guidelines
- https://core.telegram.org/bots/api
- https://core.telegram.org/bots/webapps

## Visual hierarchy

### Header

Every screen uses the same compact identity:

`TelegramGuard · QyAi Control OS`

No ASCII separator bars and no repeated marketing copy.

### Content card

Screen content is rendered inside a Telegram blockquote. This gives native visual separation without imitating a web card with text characters.

### Status language

Use short operational states:

- `VPS ONLINE`
- `NORMAL`
- `ATTENTION`
- `SSH 2FA · ACTIVE`
- `IP WHITELIST · ACTIVE`
- `SERVICE CONTROL READY`

Status emoji are limited to state indicators. Navigation buttons do not depend on emoji.

### Buttons

- blue / primary: main navigation and selected safe actions;
- green / success: allow, approve, grant;
- red / danger: deny, revoke, restart, destructive confirmations;
- neutral: refresh, back, secondary navigation.

Buttons never use color as the only signal: text still describes the action.

## Main navigation

The Control Center is a 2-column launcher:

1. System / Access
2. Security / Services
3. Activity / Settings
4. Refresh

The body contains only the current operational summary:

- uptime;
- RAM and disk;
- access protection mode;
- managed service count;
- failed SSH count;
- attention state;
- last meaningful action.

## SSH approval

An SSH approval is intentionally a separate message.

It shows only:

- authentication stage;
- user;
- remote IP;
- TTY;
- remaining approval TTL.

The actions are a green `Разрешить вход` button and a red `Отклонить` button.

Passwords, private keys and Telegram secrets are never displayed.

## Native bot shell

At startup TelegramGuard configures:

- bot name: TelegramGuard;
- short description: QyAi VPS Control OS;
- concise full description;
- commands: /start, /status, /security, /settings, /help;
- Telegram menu button using the command menu.

## Mini App boundary

A Mini App is the correct next step only when Telegram's native message UI becomes insufficient for complex realtime charts, multi-host navigation or dense configuration.

The security control path must remain server-side. Mini App input must never become an unrestricted command or shell channel.
