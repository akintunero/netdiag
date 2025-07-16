from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Address, IPv6Address

from netdiag.models import AsnRecord, BgpRecord, is_public_ip

_CYMru_TXT_RE = re.compile(r'"(\d+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^"]+)"')
_CYMru_WHOIS_RE = re.compile(
    r"^(\d+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*(.+)$",
    re.MULTILINE,
)


def _cymru_dns_name(addr: str) -> str:
    if ":" in addr:
        ip = IPv6Address(addr)
        nibbles = "".join(f"{b:04x}" for b in ip.packed)
        reversed_nibbles = ".".join(reversed(nibbles))
        return f"{reversed_nibbles}.origin6.asn.cymru.com"
    octets = str(IPv4Address(addr)).split(".")
    return f"{'.'.join(reversed(octets))}.origin.asn.cymru.com"


def _parse_cymru_line(line: str) -> AsnRecord | None:
    match = _CYMru_TXT_RE.search(line) or _CYMru_WHOIS_RE.search(line.strip())
    if not match:
        return None
    asn_raw, prefix, country, registry, allocated, *rest = match.groups()
    name = rest[0].strip() if rest else None
    try:
        asn = int(asn_raw)
    except ValueError:
        asn = None
    return AsnRecord(
        asn=asn,
        prefix=prefix.strip(),
        country=country.strip(),
        registry=registry.strip(),
        allocated=allocated.strip(),
        name=name,
    )


def lookup_as_name_cymru(asn: int, timeout: float = 4.0) -> str | None:
    qname = f"AS{asn}.asn.cymru.com"
    if not shutil.which("dig"):
        return None
    try:
        proc = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", qname, "TXT"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        line = proc.stdout.strip().strip('"')
        # "15169 | US | arin | 1990-04-08 | GOOGLE - Google LLC"
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 5:
            return parts[4]
    except (subprocess.TimeoutExpired, OSError):
        return None
    return None


def lookup_asn_cymru_dns(addr: str, timeout: float = 5.0) -> AsnRecord | None:
    if not is_public_ip(addr):
        return None
    qname = _cymru_dns_name(addr)
    if shutil.which("dig"):
        try:
            proc = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1", qname, "TXT"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return _parse_cymru_line(proc.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass
    return lookup_asn_cymru_whois(addr, timeout=timeout)


def lookup_asn_cymru_whois(addr: str, timeout: float = 8.0) -> AsnRecord | None:
    if not is_public_ip(addr):
        return None
    if not shutil.which("whois"):
        return None
    try:
        proc = subprocess.run(
            ["whois", "-h", "whois.cymru.com", "-v", addr],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            return None
        for line in proc.stdout.splitlines():
            if line.startswith("AS") or "|" not in line:
                continue
            record = _parse_cymru_line(line)
            if record:
                return record
    except (subprocess.TimeoutExpired, OSError):
        return None
    return None


def lookup_bgp_ripe(addr: str, timeout: float = 6.0) -> BgpRecord | None:
    if not is_public_ip(addr):
        return None
    url = f"https://stat.ripe.net/data/network-info/data.json?resource={addr}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "netdiag/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    data = payload.get("data") or {}
    asns = data.get("asns") or []
    prefixes = data.get("prefixes") or []
    asn = int(asns[0]) if asns else None
    prefix = prefixes[0] if prefixes else None
    return BgpRecord(
        asn=asn,
        prefix=prefix,
        name=None,
        country=None,
        rir=None,
        description=None,
    )


def lookup_bgp_bgpview(addr: str, timeout: float = 6.0) -> BgpRecord | None:
    if not is_public_ip(addr):
        return None
    url = f"https://api.bgpview.io/ip/{addr}"
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "netdiag/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    ip_data = (payload.get("data") or {}).get("ip") or {}
    prefix = ip_data.get("prefix")
    rir = ip_data.get("rir_allocation", {}).get("rir_name")
    country = ip_data.get("rir_allocation", {}).get("country_code")
    desc = ip_data.get("description")

    prefixes = (payload.get("data") or {}).get("prefixes") or []
    asn = None
    name = None
    if prefixes:
        first = prefixes[0]
        asn_info = first.get("asn") or {}
        asn = asn_info.get("asn")
        name = asn_info.get("name") or asn_info.get("description")
        if not prefix:
            prefix = first.get("prefix")

    return BgpRecord(
        asn=int(asn) if asn is not None else None,
        prefix=prefix,
        name=name,
        country=country,
        rir=rir,
        description=desc,
    )


def reverse_dns(addr: str, timeout: float = 3.0) -> str | None:
    if not is_public_ip(addr):
        return None
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(addr)
        return host
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _fill_asn_name(asn: AsnRecord | None, bgp: BgpRecord | None) -> AsnRecord | None:
    if asn is None:
        return None
    if asn.name:
        return asn
    name = (bgp.name if bgp else None) or (lookup_as_name_cymru(asn.asn) if asn.asn else None)
    if not name:
        return asn
    return AsnRecord(
        asn=asn.asn,
        prefix=asn.prefix,
        country=asn.country,
        registry=asn.registry,
        allocated=asn.allocated,
        name=name,
    )


def enrich_address(
    addr: str,
    *,
    use_bgp_api: bool = True,
    timeout: float = 6.0,
) -> tuple[AsnRecord | None, BgpRecord | None, str | None]:
    asn = lookup_asn_cymru_dns(addr, timeout=timeout)
    bgp: BgpRecord | None = None
    if use_bgp_api:
        bgp = lookup_bgp_bgpview(addr, timeout=timeout) or lookup_bgp_ripe(addr, timeout=timeout)
    asn = _fill_asn_name(asn, bgp)
    rdns = reverse_dns(addr, timeout=min(timeout, 3.0))
    return asn, bgp, rdns


def enrich_addresses_parallel(
    addresses: list[str],
    *,
    workers: int = 8,
    use_bgp_api: bool = True,
    timeout: float = 6.0,
) -> dict[str, tuple[AsnRecord | None, BgpRecord | None, str | None]]:
    unique = sorted({a for a in addresses if a and is_public_ip(a)})
    results: dict[str, tuple[AsnRecord | None, BgpRecord | None, str | None]] = {}
    if not unique:
        return results

    with ThreadPoolExecutor(max_workers=min(workers, len(unique))) as pool:
        futures = {
            pool.submit(enrich_address, addr, use_bgp_api=use_bgp_api, timeout=timeout): addr
            for addr in unique
        }
        for future in as_completed(futures):
            addr = futures[future]
            try:
                results[addr] = future.result()
            except Exception:
                results[addr] = (None, None, None)
    return results
