#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}

BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".xz",
    ".whl",
}

FORBIDDEN_SUFFIXES = {
    ".sqlite",
    ".sqlite3",
    ".db",
    ".log",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}

TOKEN_PATTERNS = [
    ("telegram bot token", re.compile(r"\b\d{6,12}:" + r"[A-Za-z0-9_-]{30,}\b")),
    ("github token", re.compile(r"\bgh" + r"[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github fine-grained token", re.compile(r"\bgithub_" + r"pat_[A-Za-z0-9_]{20,}\b")),
    ("openai-style key", re.compile(r"\bsk-" + r"[A-Za-z0-9_-]{20,}\b")),
    ("groq-style key", re.compile(r"\bgsk_" + r"[A-Za-z0-9]{20,}\b")),
    ("huggingface token", re.compile(r"\bhf_" + r"[A-Za-z0-9]{20,}\b")),
    ("slack token", re.compile(r"\bxox" + r"[baprs]-[A-Za-z0-9-]{20,}\b")),
]

PRIVATE_KEY_MARKERS = [
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN RSA " + "PRIVATE KEY-----",
    "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
    "-----BEGIN EC " + "PRIVATE KEY-----",
]

IPV4_RE = re.compile(
    r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)

ALLOWED_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
]

SAFE_SPECIAL_IPS = {
    ipaddress.ip_address(".".join(("0", "0", "0", "0"))),
    ipaddress.ip_address("255.255.255.255"),
}


def _is_env_example(path: Path) -> bool:
    return path.name == ".env.example" or path.name.endswith(".env.example")


def _forbidden_filename(path: Path) -> str | None:
    name = path.name.lower()
    if name == ".env" or (name.startswith(".env.") and not _is_env_example(path)):
        return "runtime environment file"
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return f"forbidden runtime/secret file suffix {path.suffix}"
    if name in {"id_rsa", "id_ed25519", "authorized_keys"}:
        return "SSH credential material"
    return None


def _real_public_ipv4(text: str) -> list[str]:
    found: list[str] = []
    for raw in IPV4_RE.findall(text):
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv4Address):
            continue
        if address in SAFE_SPECIAL_IPS:
            continue
        if any(address in network for network in ALLOWED_NETWORKS):
            continue
        found.append(str(address))
    return sorted(set(found))


def scan_file(path: Path, root: Path) -> list[str]:
    findings: list[str] = []
    relative = path.relative_to(root)

    filename_problem = _forbidden_filename(path)
    if filename_problem:
        findings.append(f"{relative}: {filename_problem}")
        return findings

    if path.suffix.lower() in BINARY_SUFFIXES:
        return findings

    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return findings

    for label, pattern in TOKEN_PATTERNS:
        if pattern.search(text):
            findings.append(f"{relative}: possible {label}")

    for marker in PRIVATE_KEY_MARKERS:
        if marker in text:
            findings.append(f"{relative}: private key block marker")

    for address in _real_public_ipv4(text):
        findings.append(f"{relative}: non-documentation IPv4 address {address}")

    if re.search(r"TELEGRAM_ADMIN_IDS\s*=\s*[0-9]", text):
        findings.append(f"{relative}: concrete Telegram admin ID assignment")

    return findings


def scan_path(root: Path) -> list[str]:
    root = root.resolve()
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        findings.extend(scan_file(path, root))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reject deployment-specific secrets and identity data before publishing."
    )
    parser.add_argument("path", nargs="?", default=".")
    args = parser.parse_args()

    root = Path(args.path)
    findings = scan_path(root)

    if findings:
        print("Public safety scan FAILED:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    print("Public safety scan passed: no known deployment secrets or real public IPv4 addresses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
