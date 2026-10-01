# Changelog

All notable TelegramGuard changes are recorded here.

## [0.6.0] - 2026-10-01

### Added

- Live Telegram on/off control for SSH approval without restarting the bot.
- Green enable and red disable controls with expiring confirmation.
- Dynamic readiness checks for PAM, pam_exec and the local approval broker.
- Compact mobile-first Control Center with two-column telemetry.
- Read-only Network, Events, Updates and Diagnostics sysadmin screens.
- RAM, disk, failed-unit and SSH health alerts.
- Safe SSH approval controller with PAM backup and bounded fixed actions.

### Changed

- The approval broker now stays available continuously; PAM decides whether the second factor is enforced.
- Access, Security, Settings and diagnostics read the live SSH protection state instead of a startup-only flag.
- The installer never enables a new SSH firewall automatically.
- Rich dashboards are denser and use expandable detail sections.
- Package version is now 0.6.0.

### Security

- SSH approval enable/disable remains a fixed helper action; arbitrary shell execution is still unavailable.
- Disabling Telegram 2FA requires an explicit expiring confirmation.
- PAM mutations are limited to TelegramGuard's managed sshd block.

## [0.5.0] - 2026-10-01

### Added

- Bot API 10.3 Rich Message dashboards for core control screens.
- Native headings, dividers and compact bordered tables for VPS telemetry.
- Automatic fallback to the v0.4 HTML interface if rich rendering is rejected.
- Regression tests for rich-message delivery and fallback behavior.

### Changed

- Control Center, Security and Settings now render as structured native Telegram dashboards.
- Package version is now 0.5.0.

## [0.4.0] - 2026-10-01

### Added

- QyAi Control OS v2 visual system for Telegram.
- Native Bot API 9.4 styled inline buttons.
- Consistent primary, success and danger action semantics.
- Cleaner Control Center, Security, Access, Services and Settings screens.
- Polished SSH approval card with explicit allow/deny styling.
- Native bot profile, command menu and menu-button configuration.
- UI regression tests for screen and button primitives.

### Changed

- Removed decorative ASCII separator bars and reduced emoji noise.
- Reworked status copy into compact operational summaries.
- Navigation stays inside editable inline-keyboard screens.
- Package version is now 0.4.0.

## [0.3.0] - 2026-10-01

### Added

- Paginated Telegram activity explorer.
- Local `telegram-guard-config` utility for safe managed-service allowlist changes.
- Non-secret configuration export.
- Local configuration validation.
- Rollback of managed-service config when helper restart fails.

### Changed

- Activity timestamps now include date and time.
- Managed-service editing remains local-only and outside Telegram privilege boundaries.

## [0.2.0] - 2026-10-01

### Added

- Telegram Control OS navigation with in-place dashboard screens.
- Structured managed SSH whitelist view.
- Protected bootstrap access entry.
- Guided access wizard with preset and custom TTL.
- TTL extension for temporary access.
- Live SSH security summary.
- Service detail and bounded service logs.
- Settings and self-test screens.
- Persistent managed firewall state.
- Safe bootstrap utility for current SSH connection.
- Emergency local firewall rollback command.
- Secret-safe `telegram-guard-doctor` diagnostics.
- Firewall and SSH summary regression tests.
- Deduplicated health watchdog with recovery notifications.
- Configurable failed-SSH and health-check alert thresholds.
- Human-readable activity labels and targets.
- Stable short callback tokens for long systemd unit names.
- Atomic nftables table replacement transactions.
- Live attention, service-count and last-action summary on Control Center.
- Product, UX, install-flow and roadmap specifications.

### Changed

- Package version is now 0.2.0.
- Installer preserves existing managed firewall state on upgrades.
- Installer can install required Ubuntu/Debian dependencies when missing.
- Bot profile and visible commands are intentionally minimal.

### Security

- Bootstrap whitelist entries cannot be revoked remotely.
- Administrative UI remains private-chat only.
- Arbitrary shell execution remains unavailable.
- Public repository safety scanning remains mandatory.
