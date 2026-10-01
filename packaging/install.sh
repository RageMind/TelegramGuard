#!/usr/bin/env bash
set -euo pipefail

PROJECT="TelegramGuard"
SERVICE_USER="telegram-guard"
INSTALL_ROOT="/opt/telegram-guard"
CONFIG_ROOT="/etc/telegram-guard"
STATE_ROOT="/var/lib/telegram-guard"
BOT_ENV="${CONFIG_ROOT}/bot.env"
HELPER_ENV="${CONFIG_ROOT}/helper.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./packaging/install.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "== QyAi • ${PROJECT} installer =="

for command in python3 nft systemctl; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "${command} is required" >&2
    exit 1
  fi
done

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required")
PY

if ! getent group "${SERVICE_USER}" >/dev/null; then
  groupadd --system "${SERVICE_USER}"
fi
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_USER}" --home-dir "${STATE_ROOT}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -o root -g root -m 0755 "${INSTALL_ROOT}"
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_ROOT}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 "${STATE_ROOT}"

if [[ ! -d "${INSTALL_ROOT}/venv" ]]; then
  python3 -m venv "${INSTALL_ROOT}/venv"
fi
"${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade pip
"${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade "${ROOT_DIR}"

install -m 0644 "${ROOT_DIR}/packaging/systemd/telegram-guard.service" /etc/systemd/system/telegram-guard.service
install -m 0644 "${ROOT_DIR}/packaging/systemd/telegram-guard-helper.service" /etc/systemd/system/telegram-guard-helper.service
install -m 0640 -o root -g "${SERVICE_USER}" "${ROOT_DIR}/packaging/config/bot.env.example" "${CONFIG_ROOT}/bot.env.example"
install -m 0600 -o root -g root "${ROOT_DIR}/packaging/config/helper.env.example" "${CONFIG_ROOT}/helper.env.example"

if [[ ! -s "${BOT_ENV}" ]]; then
  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_ADMIN_IDS:-}" ]]; then
    TG_TOKEN="${TELEGRAM_BOT_TOKEN}"
    TG_ADMIN="${TELEGRAM_ADMIN_IDS}"
  elif [[ -t 0 ]]; then
    echo
    read -rsp "Telegram BOT TOKEN: " TG_TOKEN
    echo
    read -rp "Numeric Telegram USER ID: " TG_ADMIN
  else
    TG_TOKEN=""
    TG_ADMIN=""
  fi

  if [[ -n "${TG_TOKEN}" && -n "${TG_ADMIN}" ]]; then
    if [[ "${TG_TOKEN}" != *:* || ! "${TG_ADMIN}" =~ ^[0-9,]+$ ]]; then
      echo "Invalid Telegram bot token or admin ID." >&2
      exit 1
    fi
    cat >"${BOT_ENV}" <<EOF
TELEGRAM_BOT_TOKEN=${TG_TOKEN}
TELEGRAM_ADMIN_IDS=${TG_ADMIN}
TELEGRAM_POLL_TIMEOUT=25
RATE_LIMIT_PER_MINUTE=20
STATE_DB=${STATE_ROOT}/state.sqlite3
HELPER_SOCKET=/run/telegram-guard/helper.sock
EOF
    chown root:"${SERVICE_USER}" "${BOT_ENV}"
    chmod 0640 "${BOT_ENV}"
    unset TG_TOKEN TG_ADMIN
  fi
fi

if [[ ! -s "${HELPER_ENV}" ]]; then
  cp "${CONFIG_ROOT}/helper.env.example" "${HELPER_ENV}"
  chown root:root "${HELPER_ENV}"
  chmod 0600 "${HELPER_ENV}"
fi

BOT_READY=0
if [[ -s "${BOT_ENV}" ]] && grep -q '^TELEGRAM_BOT_TOKEN=.' "${BOT_ENV}" && grep -Eq '^TELEGRAM_ADMIN_IDS=[0-9]' "${BOT_ENV}"; then
  BOT_READY=1
fi

if [[ "${BOT_READY}" -eq 1 && -n "${SSH_CONNECTION:-}" ]]; then
  python3 "${ROOT_DIR}/scripts/enable-managed-firewall.py" --helper-env "${HELPER_ENV}" --state "${STATE_ROOT}/firewall.json"
else
  sed -i 's/^FIREWALL_MODE=.*/FIREWALL_MODE=observe/' "${HELPER_ENV}"
fi

cat >/usr/local/sbin/telegram-guard-firewall-off <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
nft delete table inet telegram_guard 2>/dev/null || true
if [[ -f /etc/telegram-guard/helper.env ]]; then
  sed -i 's/^FIREWALL_MODE=.*/FIREWALL_MODE=observe/' /etc/telegram-guard/helper.env
fi
systemctl restart telegram-guard-helper.service 2>/dev/null || true
echo "TelegramGuard managed SSH whitelist disabled."
EOF
chmod 0700 /usr/local/sbin/telegram-guard-firewall-off

systemctl daemon-reload

if [[ "${BOT_READY}" -eq 1 ]]; then
  systemctl enable telegram-guard-helper.service telegram-guard.service >/dev/null
  systemctl restart telegram-guard-helper.service
  systemctl restart telegram-guard.service
  sleep 2

  systemctl is-active --quiet telegram-guard-helper.service || {
    echo "Helper failed to start. Rolling firewall back to observe mode." >&2
    /usr/local/sbin/telegram-guard-firewall-off || true
    exit 1
  }
  systemctl is-active --quiet telegram-guard.service || {
    echo "Bot failed to start. Check: journalctl -u telegram-guard -n 100" >&2
    exit 1
  }
fi

echo
echo "TelegramGuard installed."
if [[ "${BOT_READY}" -eq 1 ]]; then
  echo "Bot: RUNNING"
else
  echo "Bot: NOT CONFIGURED"
fi

if grep -q '^FIREWALL_MODE=nft$' "${HELPER_ENV}"; then
  echo "SSH whitelist: ACTIVE"
  echo "Current SSH client is pinned as the bootstrap address."
  echo "Emergency recovery: /usr/local/sbin/telegram-guard-firewall-off"
else
  echo "SSH whitelist: OBSERVE MODE"
fi

echo "QyAi • https://qyai.ru"
