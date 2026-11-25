#!/bin/bash
# Dedicated fail-closed RDP input gate. Bit 0x40000000 is reserved for this gate.
set -Eeuo pipefail
{
    if nft list table inet telegram_guard_rdp_gate >/dev/null 2>&1; then
        echo 'delete table inet telegram_guard_rdp_gate'
    fi
    cat <<'NFT'
table inet telegram_guard_rdp_gate {
    chain clear_auth {
        type filter hook input priority -151; policy accept;
        tcp dport 3389 meta mark set meta mark & 0xbfffffff
    }
    chain require_auth {
        type filter hook input priority -149; policy accept;
        tcp dport 3389 meta mark & 0x40000000 == 0 drop
        tcp dport 3389 meta mark set meta mark & 0xbfffffff
    }
}
NFT
} | nft -f -
