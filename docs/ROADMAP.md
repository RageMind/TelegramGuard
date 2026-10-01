# TelegramGuard — Development Roadmap

## v0.2 — Functional Control Plane

Status: implemented in the 0.2 release branch; release validation in progress

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

Most originally planned v0.3 items were pulled forward into v0.2:

- firewall health surfaced in UI — implemented;
- per-entry access detail screens — implemented;
- extend TTL — implemented;
- revoke from selected entry — implemented;
- human-readable audit actions — implemented;
- service recent logs — implemented;
- notification thresholds — implemented;
- self-test page — implemented;
- installer diagnostics — implemented;
- safer migration from observe to managed — implemented.

Remaining v0.3 focus:

- local-only managed-service allowlist editor/validator;
- richer access-entry metadata and notes;
- pagination for long activity history;
- optional non-secret diagnostics export.

## v0.4 — Security & Reliability Pass

Implemented early:

- structured SSH security summary;
- failed SSH attempt aggregation;
- alert deduplication;
- health watchdog;
- secret-safe diagnostics command;
- richer nftables rendering/state tests;
- atomic managed nftables replacement.

Remaining:

- backup/export of non-secret configuration;
- disposable-VM installation/firewall integration tests;
- tagged release artifacts and signed checksums;
- formal upgrade/migration compatibility tests.

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
