# Contributing

TelegramGuard is a QyAi security project. Changes should preserve least privilege and safe defaults.

## Before opening a pull request

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
ruff check .
mypy src
pytest
python scripts/public_safety_scan.py .
```

## Rules for security-sensitive changes

- Never add arbitrary shell execution.
- Never use `shell=True`.
- Never authorize by Telegram username.
- Never make firewall write mode the default.
- Never silently create or replace the host firewall.
- Never commit real deployment data.
- New privileged helper actions require:
  - a dedicated action name;
  - strict argument validation;
  - an explicit subprocess argv;
  - output limits;
  - tests;
  - documentation of the risk and confirmation behavior.

## Commit hygiene

Use small commits with descriptive messages. Example:

```text
feat: add confirmed service restart action
fix: reject multicast whitelist addresses
docs: clarify nftables integration
```

## Branding

Reasonable attribution to TelegramGuard and QyAi should remain intact as required by LICENSE and NOTICE.

QyAi • https://qyai.ru
