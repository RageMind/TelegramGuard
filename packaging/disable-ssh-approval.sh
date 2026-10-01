#!/usr/bin/env bash
set -euo pipefail

PAM_FILE="/etc/pam.d/sshd"
BOT_ENV="/etc/telegram-guard/bot.env"
PAM_BEGIN="# BEGIN TELEGRAMGUARD SSH APPROVAL"
PAM_END="# END TELEGRAMGUARD SSH APPROVAL"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

if [[ -f "${PAM_FILE}" ]] && grep -Fq "${PAM_BEGIN}" "${PAM_FILE}"; then
  temp="$(mktemp)"
  awk -v begin="${PAM_BEGIN}" -v end="${PAM_END}" '
    $0 == begin { skip = 1; next }
    $0 == end { skip = 0; next }
    !skip { print }
  ' "${PAM_FILE}" >"${temp}"
  chmod --reference="${PAM_FILE}" "${temp}"
  chown --reference="${PAM_FILE}" "${temp}"
  mv "${temp}" "${PAM_FILE}"
fi

if [[ -f "${BOT_ENV}" ]]; then
  if grep -q '^SSH_APPROVAL_ENABLED=' "${BOT_ENV}"; then
    sed -i 's/^SSH_APPROVAL_ENABLED=.*/SSH_APPROVAL_ENABLED=false/' "${BOT_ENV}"
  else
    echo 'SSH_APPROVAL_ENABLED=false' >>"${BOT_ENV}"
  fi
fi

systemctl restart telegram-guard.service 2>/dev/null || true

echo "TelegramGuard SSH approval is OFF."
echo "Firewall mode was not changed automatically."
