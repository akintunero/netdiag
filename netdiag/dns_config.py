from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DnsResolverInfo:
    source: str
    nameservers: tuple[str, ...]
    search_domains: tuple[str, ...]
    notes: tuple[str, ...]


def read_dns_config() -> list[DnsResolverInfo]:
    system = platform.system().lower()
    if system == "darwin":
        return _dns_config_macos()
    if system == "linux":
        return _dns_config_linux()
    return [_dns_config_resolv_conf()]


def _dns_config_macos() -> list[DnsResolverInfo]:
    entries: list[DnsResolverInfo] = []
    proc = subprocess.run(
        ["scutil", "--dns"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        blocks = re.split(r"\nresolver #\d+", proc.stdout)
        for i, block in enumerate(blocks):
            if "nameserver" not in block.lower():
                continue
            ns = re.findall(r"nameserver\[\d+\] : ([^\s]+)", block)
            domains = re.findall(r"search domain\[\d+\] : ([^\s]+)", block)
            if ns or domains:
                entries.append(
                    DnsResolverInfo(
                        source=f"resolver #{i}",
                        nameservers=tuple(ns),
                        search_domains=tuple(domains),
                        notes=(),
                    )
                )
    if not entries:
        entries.append(_dns_config_resolv_conf())
    return entries


def _dns_config_linux() -> list[DnsResolverInfo]:
    entries: list[DnsResolverInfo] = []
    if shutil.which("resolvectl"):
        proc = subprocess.run(
            ["resolvectl", "status"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            current_link = "global"
            ns: list[str] = []
            domains: list[str] = []
            notes: list[str] = []
            for line in proc.stdout.splitlines():
                if line.startswith("Link "):
                    if ns or domains:
                        entries.append(
                            DnsResolverInfo(
                                source=current_link,
                                nameservers=tuple(ns),
                                search_domains=tuple(domains),
                                notes=tuple(notes),
                            )
                        )
                    current_link = line.strip()
                    ns, domains, notes = [], [], []
                elif "DNS Servers:" in line:
                    ns.extend(s.strip() for s in line.split(":", 1)[-1].split())
                elif "DNS Domain:" in line:
                    domains.append(line.split(":", 1)[-1].strip())
            if ns or domains:
                entries.append(
                    DnsResolverInfo(
                        source=current_link,
                        nameservers=tuple(ns),
                        search_domains=tuple(domains),
                        notes=tuple(notes),
                    )
                )
            if entries:
                return entries
    entries.append(_dns_config_resolv_conf())
    return entries


def _dns_config_resolv_conf() -> DnsResolverInfo:
    path = Path("/etc/resolv.conf")
    ns: list[str] = []
    domains: list[str] = []
    notes: list[str] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                ns.append(line.split()[1])
            elif line.startswith("search"):
                domains.extend(line.split()[1:])
            elif line.startswith("domain"):
                domains.append(line.split()[1])
    else:
        notes.append("/etc/resolv.conf not found")
    return DnsResolverInfo(
        source="resolv.conf",
        nameservers=tuple(ns),
        search_domains=tuple(domains),
        notes=tuple(notes),
    )
