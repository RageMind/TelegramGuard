from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from telegram_guard.config import HelperConfig
from telegram_guard.firewall import NftWhitelist


def config_for(tmp_path: Path) -> HelperConfig:
    return HelperConfig(
        socket_path="/run/telegram-guard/helper.sock",
        socket_group="telegram-guard",
        allowed_user="telegram-guard",
        firewall_mode="nft",
        firewall_state=str(tmp_path / "firewall.json"),
        ssh_port=22,
        nft_family="inet",
        nft_table="telegram_guard",
        nft_ipv4_set="trusted_ipv4",
        nft_ipv6_set="trusted_ipv6",
        managed_services=("ssh.service",),
        ssh_journal_unit="ssh.service",
    )


def controller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> NftWhitelist:
    monkeypatch.setattr(
        "telegram_guard.firewall._resolve_nft",
        lambda: "/usr/bin/true",
    )
    instance = NftWhitelist(config_for(tmp_path))
    monkeypatch.setattr(
        instance,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "", ""),
    )
    monkeypatch.setattr(instance, "_run_script", lambda script: None)
    return instance


def test_snapshot_marks_bootstrap_as_protected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    firewall = controller(tmp_path, monkeypatch)
    firewall._save_entries(
        {
            "203.0.113.42": {
                "expires_at": None,
                "source": "bootstrap",
            }
        }
    )

    snapshot = firewall.snapshot()
    entry = snapshot["entries"][0]
    assert entry["ip"] == "203.0.113.42"
    assert entry["permanent"] is True
    assert entry["protected"] is True


def test_bootstrap_entry_cannot_be_revoked_remotely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    firewall = controller(tmp_path, monkeypatch)
    firewall._save_entries(
        {
            "203.0.113.42": {
                "expires_at": None,
                "source": "bootstrap",
            }
        }
    )

    with pytest.raises(PermissionError):
        firewall.revoke("203.0.113.42")


def test_extend_preserves_entry_and_increases_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    firewall = controller(tmp_path, monkeypatch)
    original_expiry = int(time.time()) + 600
    firewall._save_entries(
        {
            "203.0.113.42": {
                "expires_at": original_expiry,
                "source": "telegram",
            }
        }
    )

    result = firewall.extend("203.0.113.42", 3600)
    entries = firewall._load_entries()

    assert int(entries["203.0.113.42"]["expires_at"]) >= original_expiry + 3600
    assert int(result["remaining_seconds"]) > 3600


def test_ruleset_only_filters_configured_ssh_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    firewall = controller(tmp_path, monkeypatch)
    ruleset = firewall._ruleset(
        {
            "203.0.113.42": {
                "expires_at": None,
                "source": "bootstrap",
            }
        }
    )

    assert "tcp dport 22" in ruleset
    assert "@trusted_ipv4 accept" in ruleset
    assert "reject with tcp reset" in ruleset


def test_apply_entries_replaces_existing_table_in_single_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    firewall = controller(tmp_path, monkeypatch)
    scripts: list[str] = []
    monkeypatch.setattr(firewall, "_run_script", scripts.append)

    entries = {
        "203.0.113.42": {
            "expires_at": None,
            "source": "bootstrap",
        }
    }
    firewall._apply_entries(entries)

    assert len(scripts) == 1
    assert scripts[0].startswith("delete table inet telegram_guard\n")
    assert "table inet telegram_guard" in scripts[0]
    assert firewall._load_entries() == entries


def test_make_permanent_converts_temporary_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    firewall = controller(tmp_path, monkeypatch)
    firewall._save_entries(
        {
            "203.0.113.42": {
                "expires_at": int(time.time()) + 600,
                "source": "telegram",
                "added_at": int(time.time()),
            }
        }
    )

    result = firewall.make_permanent("203.0.113.42")
    entries = firewall._load_entries()

    assert result["permanent"] is True
    assert entries["203.0.113.42"]["expires_at"] is None
    assert entries["203.0.113.42"]["source"] == "telegram-permanent"
