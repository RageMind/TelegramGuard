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

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required" >&2
  exit 1
fi

NEED_PACKAGES=0
command -v python3 >/dev/null 2>&1 || NEED_PACKAGES=1
command -v nft >/dev/null 2>&1 || NEED_PACKAGES=1

if [[ "${NEED_PACKAGES}" -eq 1 ]] || ! python3 -m venv --help >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3 python3-venv nftables ca-certificates
  else
    echo "Missing Python 3/venv or nftables. Install them and rerun." >&2
    exit 1
  fi
fi

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
fi
chown root:root "${HELPER_ENV}"
chmod 0600 "${HELPER_ENV}"

if [[ -s "${BOT_ENV}" ]]; then
  chown root:"${SERVICE_USER}" "${BOT_ENV}"
  chmod 0640 "${BOT_ENV}"
fi

BOT_READY=0
if [[ -s "${BOT_ENV}" ]] && grep -q '^TELEGRAM_BOT_TOKEN=.' "${BOT_ENV}" && grep -Eq '^TELEGRAM_ADMIN_IDS=[0-9]' "${BOT_ENV}"; then
  BOT_READY=1
fi

EXISTING_MANAGED=0
if grep -q '^FIREWALL_MODE=nft
cat >/usr/local/sbin/telegram-guard-firewall-off <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ENV_FILE=/etc/telegram-guard/helper.env
NFT_FAMILY=inet
NFT_TABLE=telegram_guard

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

nft delete table "${NFT_FAMILY}" "${NFT_TABLE}" 2>/dev/null || true

if [[ -f "${ENV_FILE}" ]]; then
  if grep -q '^FIREWALL_MODE=' "${ENV_FILE}"; then
    sed -i 's/^FIREWALL_MODE=.*/FIREWALL_MODE=observe/' "${ENV_FILE}"
  else
    echo 'FIREWALL_MODE=observe' >>"${ENV_FILE}"
  fi
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
    journalctl -u telegram-guard-helper.service -n 40 --no-pager >&2 || true
    exit 1
  }
  systemctl is-active --quiet telegram-guard.service || {
    echo "Bot failed to start. Bootstrap SSH access remains preserved." >&2
    journalctl -u telegram-guard.service -n 40 --no-pager >&2 || true
    exit 1
  }
fi

echo
VERSION=$("${INSTALL_ROOT}/venv/bin/python" -c 'from telegram_guard import __version__; print(__version__)' 2>/dev/null || printf 'unknown')
echo "TelegramGuard ${VERSION} installed."
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
 "${HELPER_ENV}" && [[ -s "${STATE_ROOT}/firewall.json" ]]; then
  EXISTING_MANAGED=1
fi

if [[ "${BOT_READY}" -eq 1 && -n "${SSH_CONNECTION:-}" ]]; then
  python3 "${ROOT_DIR}/scripts/enable-managed-firewall.py"     --helper-env "${HELPER_ENV}"     --state "${STATE_ROOT}/firewall.json"
elif [[ "${EXISTING_MANAGED}" -eq 1 ]]; then
  echo "Existing managed SSH whitelist detected; preserving it."
else
  if grep -q '^FIREWALL_MODE=' "${HELPER_ENV}"; then
    sed -i 's/^FIREWALL_MODE=.*/FIREWALL_MODE=observe/' "${HELPER_ENV}"
  else
    echo 'FIREWALL_MODE=observe' >>"${HELPER_ENV}"
  fi
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
