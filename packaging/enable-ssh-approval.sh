#!/usr/bin/env bash
set -euo pipefail

PAM_FILE="/etc/pam.d/sshd"
BOT_ENV="/etc/telegram-guard/bot.env"
PAM_BACKUP="/etc/telegram-guard/sshd.pam.before-telegramguard"
PAM_BEGIN="# BEGIN TELEGRAMGUARD SSH APPROVAL"
PAM_END="# END TELEGRAMGUARD SSH APPROVAL"
PAM_COMMAND="account required pam_exec.so quiet /opt/telegram-guard/venv/bin/telegram-guard-pam"
SOCKET="/run/telegram-guard-bot/approval.sock"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

for path in "${PAM_FILE}" "${BOT_ENV}" /opt/telegram-guard/venv/bin/telegram-guard-pam; do
  if [[ ! -e "${path}" ]]; then
    echo "Required path is missing: ${path}" >&2
    exit 1
  fi
done

SSHD_BIN=""
for candidate in /usr/sbin/sshd /usr/bin/sshd; do
  if [[ -x "${candidate}" ]]; then
    SSHD_BIN="${candidate}"
    break
  fi
done
if [[ -z "${SSHD_BIN}" ]]; then
  echo "sshd is unavailable." >&2
  exit 1
fi

if ! "${SSHD_BIN}" -T 2>/dev/null | grep -qi '^usepam yes$'; then
  echo "OpenSSH UsePAM must already be enabled. No SSH config was changed." >&2
  exit 1
fi

if ! find /lib /usr/lib -type f -path '*/security/pam_exec.so' -print -quit 2>/dev/null | grep -q .; then
  echo "pam_exec.so is unavailable." >&2
  exit 1
fi

set_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "${BOT_ENV}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${BOT_ENV}"
  else
    printf '%s=%s\n' "${key}" "${value}" >>"${BOT_ENV}"
  fi
}

if [[ ! -f "${PAM_BACKUP}" ]]; then
  cp --preserve=mode,ownership,timestamps "${PAM_FILE}" "${PAM_BACKUP}"
  chmod 0600 "${PAM_BACKUP}"
fi

set_env SSH_APPROVAL_ENABLED true
set_env SSH_APPROVAL_SOCKET "${SOCKET}"

systemctl restart telegram-guard.service
for _ in $(seq 1 20); do
  if [[ -S "${SOCKET}" ]]; then
    break
  fi
  sleep 0.25
done

if [[ ! -S "${SOCKET}" ]]; then
  set_env SSH_APPROVAL_ENABLED false
  systemctl restart telegram-guard.service || true
  echo "Approval socket did not become ready; PAM was not changed." >&2
  exit 1
fi

if ! grep -Fq "${PAM_BEGIN}" "${PAM_FILE}"; then
  {
    printf '\n%s\n' "${PAM_BEGIN}"
    printf '%s\n' "${PAM_COMMAND}"
    printf '%s\n' "${PAM_END}"
  } >>"${PAM_FILE}"
fi

install -m 0700 \
  "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/disable-ssh-approval.sh" \
  /usr/local/sbin/telegram-guard-ssh-approval-off

if [[ -x /usr/local/sbin/telegram-guard-firewall-off ]]; then
  /usr/local/sbin/telegram-guard-firewall-off
else
  nft delete table inet telegram_guard 2>/dev/null || true
  if [[ -f /etc/telegram-guard/helper.env ]]; then
    sed -i 's/^FIREWALL_MODE=.*/FIREWALL_MODE=observe/' \
      /etc/telegram-guard/helper.env
    systemctl restart telegram-guard-helper.service
  fi
fi

echo "TelegramGuard SSH approval is ACTIVE."
echo "Primary SSH authentication still happens in OpenSSH."
echo "After successful authentication, PAM waits for Telegram approval."
echo "Timeout or TelegramGuard failure denies the login."
echo "Emergency local recovery:"
echo "  /usr/local/sbin/telegram-guard-ssh-approval-off"
