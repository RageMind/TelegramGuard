#!/usr/bin/env bash
set -euo pipefail

PROJECT="TelegramGuard"
SERVICE_USER="telegram-guard"
INSTALL_ROOT="/opt/telegram-guard"
CONFIG_ROOT="/etc/telegram-guard"
STATE_ROOT="/var/lib/telegram-guard"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./packaging/install.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== QyAi • ${PROJECT} installer =="

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required")
PY

if ! getent group "${SERVICE_USER}" >/dev/null; then
  groupadd --system "${SERVICE_USER}"
fi

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd     --system     --gid "${SERVICE_USER}"     --home-dir "${STATE_ROOT}"     --shell /usr/sbin/nologin     "${SERVICE_USER}"
fi

install -d -o root -g root -m 0755 "${INSTALL_ROOT}"
install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_ROOT}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 "${STATE_ROOT}"

if [[ ! -d "${INSTALL_ROOT}/venv" ]]; then
  if ! python3 -m venv "${INSTALL_ROOT}/venv"; then
    echo "Failed to create venv. Install the distro python3-venv package and retry." >&2
    exit 1
  fi
fi

"${INSTALL_ROOT}/venv/bin/python" -m pip install --upgrade pip
"${INSTALL_ROOT}/venv/bin/python" -m pip install "${ROOT_DIR}"

install -m 0644   "${ROOT_DIR}/packaging/systemd/telegram-guard.service"   /etc/systemd/system/telegram-guard.service
install -m 0644   "${ROOT_DIR}/packaging/systemd/telegram-guard-helper.service"   /etc/systemd/system/telegram-guard-helper.service

install -m 0640 -o root -g "${SERVICE_USER}"   "${ROOT_DIR}/packaging/config/bot.env.example"   "${CONFIG_ROOT}/bot.env.example"
install -m 0600 -o root -g root   "${ROOT_DIR}/packaging/config/helper.env.example"   "${CONFIG_ROOT}/helper.env.example"

systemctl daemon-reload

cat <<EOF

Installed TelegramGuard using Python ${PYTHON_VERSION}.

Nothing has been started.
No SSH configuration was changed.
No firewall rule was changed.

Next:
  1. Copy and edit:
       ${CONFIG_ROOT}/bot.env.example -> ${CONFIG_ROOT}/bot.env
       ${CONFIG_ROOT}/helper.env.example -> ${CONFIG_ROOT}/helper.env
  2. Keep FIREWALL_MODE=observe for the first start.
  3. Read docs/INSTALL.md.
  4. Start helper, then bot:
       systemctl enable --now telegram-guard-helper
       systemctl enable --now telegram-guard

QyAi • https://qyai.ru
EOF
