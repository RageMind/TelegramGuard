# Public Release Checklist

TelegramGuard is intended to be safe to publish as source code.

Before switching repository visibility to **Public**:

- [ ] `python scripts/public_safety_scan.py .` passes.
- [ ] CI lint, type-check and tests pass.
- [ ] CodeQL completes or any platform limitation is documented.
- [ ] No runtime `.env`, SQLite database, log, key, certificate or backup is committed.
- [ ] No real VPS IP, hostname, Telegram admin ID, bot token or SSH key is committed.
- [ ] README uses only documentation ranges such as `203.0.113.0/24`.
- [ ] Firewall write mode remains opt-in.
- [ ] Generic shell execution remains absent.
- [ ] Security reporting instructions are present.
- [ ] QyAi attribution is present in README, NOTICE and packaged service descriptions.

Repository-level metadata to set when publishing:

- Description: `Telegram-first control plane for private VPS administration — whitelist, SSH visibility, service controls and audit by QyAi.`
- Homepage: `https://qyai.ru`
- Topics: `telegram`, `vps`, `security`, `ssh`, `nftables`, `systemd`, `qyai`
- License: Apache-2.0
- Default branch: `main`

Public release should expose source code only. Deployment secrets remain local to the operator.

QyAi • https://qyai.ru
