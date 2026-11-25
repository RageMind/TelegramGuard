#!/usr/bin/env bash
# Run from an active SSH connection, locally as root. Never expose RDP without
# the independent gate; do not enable password SSH or alter other services.
set -Eeuo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $EUID == 0 && -n "${SSH_CONNECTION:-}" ]] || { echo "Run from root SSH session"; exit 1; }
[[ -s /etc/telegram-guard/bot.env && -s /etc/telegram-guard/helper.env ]] || { echo "Install TelegramGuard first"; exit 1; }
systemctl is-active --quiet telegram-guard.service
# Block RDP before package installation or a helper restart.
install -m 0755 packaging/rdp-gate.sh /usr/local/sbin/telegram-guard-rdp-gate
cat >/etc/systemd/system/telegram-guard-rdp-gate.service <<'UNIT'
[Unit]
Description=TelegramGuard fail-closed RDP gate
After=local-fs.target nftables.service
Before=xrdp.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/telegram-guard-rdp-gate
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable telegram-guard-rdp-gate.service
systemctl restart telegram-guard-rdp-gate.service
systemctl stop xrdp.service 2>/dev/null || true
systemctl mask xrdp.service
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xfce4 xfce4-terminal xrdp xorgxrdp dbus-x11
# In observe mode, seed the active SSH source first to avoid lockout.
if ! grep -qx FIREWALL_MODE=nft /etc/telegram-guard/helper.env; then
    python3 scripts/enable-managed-firewall.py
fi
cp -p /etc/telegram-guard/helper.env /etc/telegram-guard/helper.env.before-rdp
sed -i '/^RDP_WHITELIST_ENABLED=/d' /etc/telegram-guard/helper.env
printf '\nRDP_WHITELIST_ENABLED=true\n' >>/etc/telegram-guard/helper.env
bash packaging/install.sh
systemctl is-active --quiet telegram-guard-helper.service
nft list chain inet telegram_guard ssh_guard | grep -F 'tcp dport 3389' >/dev/null
id desktop >/dev/null 2>&1 || useradd -m -s /bin/bash desktop
passwd desktop </dev/tty
# Non-privileged GUI session.
printf 'startxfce4\n' >/home/desktop/.xsession
chown desktop:desktop /home/desktop/.xsession
chmod 700 /home/desktop/.xsession
adduser xrdp ssl-cert
sed -i '0,/^port=.*$/s//port=3389/' /etc/xrdp/xrdp.ini
grep -qx port=3389 /etc/xrdp/xrdp.ini
sed -i 's/^AllowRootLogin=.*/AllowRootLogin=false/' /etc/xrdp/sesman.ini
grep -qx AllowRootLogin=false /etc/xrdp/sesman.ini
install -d /etc/systemd/system/xrdp.service.d
cat >/etc/systemd/system/xrdp.service.d/telegram-guard.conf <<'UNIT'
[Unit]
Requires=telegram-guard-rdp-gate.service
After=telegram-guard-rdp-gate.service telegram-guard-helper.service
UNIT
systemctl daemon-reload
systemctl unmask xrdp.service
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    ufw allow 3389/tcp
fi
systemctl enable --now xrdp.service
systemctl is-active --quiet xrdp.service
ss -ltn '( sport = :3389 )'
echo 'RDP ready: TCP 3389; username desktop; authorize IP in TelegramGuard.'
echo 'No VPN needed. Provider firewall must allow TCP 3389.'
