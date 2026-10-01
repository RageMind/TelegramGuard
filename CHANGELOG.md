# Changelog

All notable TelegramGuard changes are recorded here.

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
