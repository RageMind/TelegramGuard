#!/usr/bin/env bash
# Enable strict SSH + RDP login approval while retaining the shared IP gate.
# Run in SSH; keep that connection open and verify a SECOND SSH and RDP login.
set -Eeuo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ $EUID == 0 && -n "${SSH_CONNECTION:-}" ]] || { echo "Run from root SSH"; exit 1; }
[[ ! -e /etc/telegram-guard/strict-access ]] || { echo "Strict mode already enabled; no changes"; exit 1; }
for s in telegram-guard telegram-guard-helper telegram-guard-rdp-gate xrdp xrdp-sesman; do
    systemctl is-active --quiet "$s"
done
grep -qx FIREWALL_MODE=nft /etc/telegram-guard/helper.env
grep -qx RDP_WHITELIST_ENABLED=true /etc/telegram-guard/helper.env
nft list table inet telegram_guard_rdp_gate >/dev/null
nft list chain inet telegram_guard ssh_guard | grep -F 'tcp dport 3389 drop' >/dev/null
/usr/sbin/sshd -T | grep -qx 'usepam yes'
for f in /etc/pam.d/sshd /etc/pam.d/xrdp-sesman /etc/xrdp/xrdp.ini /etc/telegram-guard/bot.env; do
    [[ -f "$f" && ! -L "$f" ]]
done
# Verify Python changes in a disposable environment before modifying production.
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
(umask 022; python3 -m venv "$TEST_DIR/venv"; "$TEST_DIR/venv/bin/pip" install -q ".[dev]"; "$TEST_DIR/venv/bin/python" -m pytest -q)
bash packaging/install.sh
systemctl is-active --quiet telegram-guard
systemctl is-active --quiet telegram-guard-helper
# Save only config files, never expose the token or change existing firewall grants.
BACKUP="$(mktemp -d /etc/telegram-guard/strict-backup.XXXXXX)"
cp -p /etc/pam.d/sshd "$BACKUP/sshd"
cp -p /etc/pam.d/xrdp-sesman "$BACKUP/xrdp-sesman"
cp -p /etc/xrdp/xrdp.ini "$BACKUP/xrdp.ini"
cp -p /etc/telegram-guard/bot.env "$BACKUP/bot.env"
cat >"$BACKUP/rollback.sh" <<'ROLLBACK'
#!/bin/bash
set -e
B="$(dirname "$0")"
cp -p "$B/sshd" /etc/pam.d/sshd
cp -p "$B/xrdp-sesman" /etc/pam.d/xrdp-sesman
cp -p "$B/xrdp.ini" /etc/xrdp/xrdp.ini
cp -p "$B/bot.env" /etc/telegram-guard/bot.env
rm -f /etc/telegram-guard/strict-access
systemctl restart telegram-guard.service
systemctl restart xrdp.service
echo "Previous login policy restored; IP whitelist unchanged."
ROLLBACK
chmod 700 "$BACKUP/rollback.sh"
UNIT="telegram-guard-strict-rollback-$(date +%s)"
systemd-run --unit="$UNIT" --on-active=10min "$BACKUP/rollback.sh"
trap 'rc=$?; trap - ERR; "$BACKUP/rollback.sh" || true; systemctl stop "$UNIT.timer" || true; exit "$rc"' ERR
touch /etc/telegram-guard/strict-access
sed -i '/^STRICT_LOGIN_APPROVAL=/d; /^SSH_APPROVAL_ENABLED=/d' /etc/telegram-guard/bot.env
printf '\nSTRICT_LOGIN_APPROVAL=true\nSSH_APPROVAL_ENABLED=true\n' >>/etc/telegram-guard/bot.env
systemctl restart telegram-guard.service
for _ in $(seq 1 40); do
    [[ -S /run/telegram-guard-bot/approval.sock ]] && break
    sleep .25
done
[[ -S /run/telegram-guard-bot/approval.sock ]]
systemctl is-active --quiet telegram-guard
# Account checks occur after primary authentication. Preserve the original
# service-specific PAM stack and avoid duplicate managed lines.
python3 - <<'PY'
from pathlib import Path
for service, begin, end, option in [
    ("sshd", "# BEGIN TELEGRAMGUARD SSH APPROVAL", "# END TELEGRAMGUARD SSH APPROVAL", ""),
    ("xrdp-sesman", "# BEGIN TELEGRAMGUARD RDP APPROVAL", "# END TELEGRAMGUARD RDP APPROVAL", " seteuid"),
]:
    path = Path("/etc/pam.d") / service
    old = path.read_text()
    if old.count(begin) != old.count(end) or old.count(begin) > 1:
        raise RuntimeError("Invalid previous PAM block")
    if begin in old:
        before, rest = old.split(begin, 1)
        old = before + rest.split(end, 1)[1]
    if "telegram-guard-pam" in old:
        raise RuntimeError("Unmanaged approval hook exists; inspect manually")
    path.write_text(old.rstrip() + "\n\n" + begin + "\n"
                    + "account required pam_exec.so quiet" + option
                    + " /opt/telegram-guard/venv/bin/telegram-guard-pam\n"
                    + end + "\n")
# Only local Xorg sessions. Remove the optional VNC/RDP proxy connection types
# that can use a different authentication path.
p = Path("/etc/xrdp/xrdp.ini")
import re
sections = re.split(r"(?m)(?=^\s*\[[^\n\]]+\]\s*$)", p.read_text())
kept = []
for section in sections:
    match = re.match(r"\s*\[([^\]]+)\]", section)
    if match and match.group(1).casefold() in {"xvnc", "vnc-any", "neutrinordp-any"}:
        continue
    kept.append(section)
result = "".join(kept)
if not re.search(r"(?mi)^\[Xorg\]\s*$", result):
    raise RuntimeError("Xorg profile missing")
p.write_text(result)
PY
/usr/sbin/sshd -t
systemctl restart xrdp.service
systemctl is-active --quiet xrdp
nft list chain inet telegram_guard ssh_guard | grep -F 'tcp dport 3389 drop' >/dev/null
trap - ERR
echo "Trial strict mode active. Existing SSH session should remain open."
echo "Test a NEW SSH login and a NEW RDP login, both approved and denied."
echo "If both work, commit the policy before ten minutes:"
echo "  systemctl stop $UNIT.timer"
echo "Emergency rollback from existing SSH or provider console:"
echo "  $BACKUP/rollback.sh"
echo "If not confirmed, old login policy is restored in ten minutes."
