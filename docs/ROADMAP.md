# TelegramGuard — Development Roadmap

## v0.2 — Functional Control Plane

Status: current implementation target

- OS-style Telegram dashboard;
- in-place screen editing;
- system health;
- access screen;
- SSH/session views;
- service views;
- audit;
- managed persistent nftables whitelist;
- bootstrap current SSH IP;
- emergency firewall rollback;
- automatic reinstall/update path.

Exit criteria:

- clean install works;
- whitelist add/revoke works;
- helper restart restores rules;
- no SSH lockout on supported happy path.

## v0.3 — Complete VPS Operations UX

- firewall health surfaced in UI;
- per-entry access detail screens;
- extend TTL;
- revoke from selected entry;
- human-readable audit actions;
- service recent logs;
- configurable managed service allowlist;
- notification thresholds;
- self-test page;
- installer diagnostics;
- safer migration from observe to managed.

## v0.4 — Security & Reliability Pass

- structured security events;
- failed SSH attempt aggregation;
- alert deduplication;
- health watchdog;
- config validation command;
- backup/export of non-secret configuration;
- richer tests for nftables rendering;
- integration tests in disposable VM/container where possible;
- release artifacts and signed checksums.

## v0.5 — QyAi Brand Pass

- final QyAi logo source asset;
- TelegramGuard avatar;
- welcome/banner artwork;
- GitHub social preview;
- consistent icons and copy;
- Russian + English localization framework;
- polished public README screenshots.

## v1.0 — Public Stable

- stable install/update/uninstall;
- documented compatibility matrix;
- migration policy;
- versioned config;
- tagged releases;
- changelog;
- security reporting workflow;
- complete public documentation;
- reproducible tests;
- hardened default systemd units.

## v2.0 — Telegram Mini App / QyAi Control OS

A full graphical control surface opened inside Telegram.

Planned modules:

- live dashboard;
- charts;
- access manager;
- services;
- SSH security;
- sessions;
- audit explorer;
- settings;
- branded QyAi visual system.

The Mini App must call a local/server API protected by Telegram WebApp authentication and must not expose the privileged helper directly.

## Non-goals

TelegramGuard will not become:

- a generic shell bot;
- a remote desktop;
- a password vault;
- a Docker admin panel with unrestricted socket access;
- a replacement for full infrastructure orchestration platforms.
