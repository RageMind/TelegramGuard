# TelegramGuard Admin Console v0.6

The v0.6 interface is optimized for one-handed mobile server administration inside Telegram.

## Visual rules

- no large rich-message headings on routine screens;
- one compact product line: **TelegramGuard** + `QyAi`;
- a short screen title and operational state;
- compact striped telemetry tables;
- two metric pairs per row on the Control Center and diagnostic views;
- detailed information is collapsed into native `<details>` blocks;
- inline keyboards remain the primary navigation surface;
- Telegram semantic styles are reserved for meaning:
  - primary — navigation or selected view;
  - success — grant/approve;
  - danger — revoke/deny/restart.

The result is intentionally denser than v0.5 and avoids the oversized serif heading stack visible in the first Rich Message implementation.

## Home

The home screen shows only the six metrics required for quick triage:

- RAM;
- disk;
- load;
- failed SSH attempts;
- uptime;
- managed service count.

Access mode and the latest action are secondary information.

## System

The System view shows:

- vCPU count;
- 1/5/15-minute load;
- RAM usage;
- swap usage;
- root filesystem usage;
- process count;
- hostname;
- OS release;
- kernel;
- inode usage.

## Network

Read-only network visibility includes:

- aggregate RX/TX counters;
- interfaces;
- bounded listening TCP/UDP endpoints.

Process arguments and unrestricted socket control are not exposed.

## Diagnostics

The diagnostic view aggregates:

- access protection;
- managed service health;
- RAM and disk thresholds;
- failed SSH activity;
- failed systemd units;
- locally known package upgrades;
- reboot-required state.

## Events

Global journald warnings and higher-priority events can be viewed for:

- 15 minutes;
- 1 hour;
- 24 hours.

Output is bounded and read-only.

## Updates

The update screen reads the local package cache. It does not run `apt update`, install packages or reboot the VPS.

## Safety boundary

v0.6 does not introduce a generic shell, arbitrary systemctl, arbitrary journal queries, direct Docker socket access, package installation, reboot, shutdown or arbitrary filesystem browsing.

All privileged helper actions remain finite and argument-bounded.
