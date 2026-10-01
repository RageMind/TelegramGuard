#!/usr/bin/env bash
set -euo pipefail

PAM_FILE="/etc/pam.d/sshd"
BOT_ENV="/etc/telegram-guard/bot.env"
PAM_BACKUP="/etc/telegram-guard/sshd.pam.before-telegramguard"
PAM_BEGIN="# BEGIN TELEGRAMGUARD SSH APPROVAL"
PAM_END="# END TELEGRAMGUARD SSH APPROVAL"
PAM_COMMAND="account required pam_exec.so quiet /opt/telegram-guard/venv/bin/telegram-guard-pam"
SOCKET="/run/telegram-guard-bot/approval.sock"
RECOVERY="/usr/local/sbin/telegram-guard-ssh-approval-off"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

install -m 0700   "${SCRIPT_DIR}/disable-ssh-approval.sh"   "${RECOVERY}"

TX_DIR="$(mktemp -d /tmp/telegramguard-ssh-approval.XXXXXX)"
cp --preserve=mode,ownership,timestamps "${PAM_FILE}" "${TX_DIR}/sshd.pam"
cp --preserve=mode,ownership,timestamps "${BOT_ENV}" "${TX_DIR}/bot.env"

rollback() {
  local rc=$?
  trap - ERR
  set +e

  cp --preserve=mode,ownership,timestamps "${TX_DIR}/sshd.pam" "${PAM_FILE}"
  cp --preserve=mode,ownership,timestamps "${TX_DIR}/bot.env" "${BOT_ENV}"
  systemctl restart telegram-guard.service >/dev/null 2>&1 || true

  rm -rf "${TX_DIR}"
  echo "TelegramGuard SSH approval activation rolled back." >&2
  exit "${rc}"
}
trap rollback ERR

cleanup() {
  rm -rf "${TX_DIR}"
}
trap cleanup EXIT

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
  echo "Approval socket did not become ready." >&2
  false
fi

if ! grep -Fq "${PAM_BEGIN}" "${PAM_FILE}"; then
  {
    printf '\n%s\n' "${PAM_BEGIN}"
    printf '%s\n' "${PAM_COMMAND}"
    printf '%s\n' "${PAM_END}"
  } >>"${PAM_FILE}"
fi

if [[ -x /usr/local/sbin/telegram-guard-firewall-off ]]; then
  /usr/local/sbin/telegram-guard-firewall-off
else
  nft delete table inet telegram_guard 2>/dev/null || true
  if [[ -f /etc/telegram-guard/helper.env ]]; then
    if grep -q '^FIREWALL_MODE=' /etc/telegram-guard/helper.env; then
      sed -i 's/^FIREWALL_MODE=.*/FIREWALL_MODE=observe/'         /etc/telegram-guard/helper.env
    else
      echo 'FIREWALL_MODE=observe' >>/etc/telegram-guard/helper.env
    fi
    systemctl restart telegram-guard-helper.service
  fi
fi

if ! systemctl is-active --quiet telegram-guard.service; then
  echo "TelegramGuard bot is not active after SSH approval activation." >&2
  false
fi

if [[ ! -S "${SOCKET}" ]]; then
  echo "Approval socket disappeared after activation." >&2
  false
fi

trap - ERR
rm -rf "${TX_DIR}"
trap - EXIT

echo "TelegramGuard SSH approval is ACTIVE."
echo "Primary SSH authentication still happens in OpenSSH."
echo "After successful authentication, PAM waits for Telegram approval."
echo "Timeout or TelegramGuard failure denies the login."
echo "Emergency local recovery:"
echo "  ${RECOVERY}"
