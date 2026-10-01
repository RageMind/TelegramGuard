#!/usr/bin/env bash
set -euo pipefail

PURGE=0
if [[ "${1:-}" == "--purge" ]]; then
  PURGE=1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./packaging/uninstall.sh [--purge]" >&2
  exit 1
fi

systemctl disable --now telegram-guard.service 2>/dev/null || true
systemctl disable --now telegram-guard-helper.service 2>/dev/null || true

rm -f /etc/systemd/system/telegram-guard.service
rm -f /etc/systemd/system/telegram-guard-helper.service
systemctl daemon-reload

rm -rf /opt/telegram-guard

if [[ "${PURGE}" -eq 1 ]]; then
  rm -rf /etc/telegram-guard
  rm -rf /var/lib/telegram-guard
  rm -rf /var/lib/telegram-guard-helper
  userdel telegram-guard 2>/dev/null || true
  groupdel telegram-guard 2>/dev/null || true
  echo "TelegramGuard removed with local configuration/state."
else
  echo "TelegramGuard binaries removed. Configuration and state were preserved."
  echo "Use --purge only if you intentionally want to delete them."
fi

echo "QyAi • https://qyai.ru"
