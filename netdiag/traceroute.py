from __future__ import annotations

import re
import shutil
import subprocess
import sys
from collections.abc import Iterator

from netdiag.enrichment import enrich_addresses_parallel
from netdiag.models import EnrichedHop, Hop, is_public_ip

# macOS / BSD: " 1  host (1.2.3.4)  12.345 ms"
# Linux:       " 1  host (1.2.3.4)  12.345 ms  13.456 ms"
_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"(?:"
    r"(\S+)\s+\(([^)]+)\)"  # hostname (ip)
    r"|"
    r"(\S+)"  # bare token: * or ip or host
    r")"
    r"(.*)$"
)
_RTT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms")
_STAR_RE = re.compile(r"\*")


def _resolve_traceroute_binary(ipv6: bool) -> list[str]:
    candidates = []
    if ipv6:
        candidates.extend(["traceroute6", "traceroute"])
    else:
        candidates.append("traceroute")
    for name in candidates:
        path = shutil.which(name)
        if path:
            return [path]
    raise FileNotFoundError(
        "traceroute not found on PATH. Install traceroute (macOS: built-in; Linux: traceroute or iputils-tracepath)."
    )


def parse_traceroute_line(line: str) -> Hop | None:
    line = line.strip()
    if not line or line.startswith("traceroute") or line.startswith("Tracing"):
        return None

    match = _HOP_RE.match(line)
    if not match:
        return None

    index = int(match.group(1))
    hostname = match.group(2)
    ip_paren = match.group(3)
    bare = match.group(4)
    tail = match.group(5) or ""

    address: str | None = None
    host: str | None = hostname

    if ip_paren:
        address = ip_paren
    elif bare and bare != "*":
        if _looks_like_ip(bare):
            address = bare
            host = None
        else:
            host = bare
            address = None
    else:
        host = None
        address = None

    rtts: list[float] = []
    for rtt_match in _RTT_RE.finditer(tail):
        rtts.append(float(rtt_match.group(1)))

    if address is None and host and _looks_like_ip(host):
        address = host
        host = None

    return Hop(index=index, hostname=host, address=address, rtt_ms=rtts)


def parse_traceroute_output(text: str) -> list[Hop]:
    hops: list[Hop] = []
    for line in text.splitlines():
        hop = parse_traceroute_line(line)
        if hop is not None:
            hops.append(hop)
    return hops


def _looks_like_ip(token: str) -> bool:
    if token.count(".") == 3:
        parts = token.split(".")
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return ":" in token


def run_traceroute(
    target: str,
    *,
    max_hops: int = 30,
    probes: int = 3,
    timeout_sec: int = 5,
    ipv6: bool = False,
) -> list[Hop]:
    binary = _resolve_traceroute_binary(ipv6)[0]
    cmd = [binary, "-m", str(max_hops), "-q", str(probes), "-w", str(timeout_sec), target]

    # Linux iputils traceroute uses -n for numeric; macOS ignores unknown flags.
    if sys.platform.startswith("linux"):
        cmd = [binary, "-n", "-m", str(max_hops), "-q", str(probes), "-w", str(timeout_sec), target]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    output = proc.stdout or proc.stderr or ""
    if proc.returncode not in (0, 1) and not output.strip():
        raise RuntimeError(f"traceroute failed (exit {proc.returncode}): {proc.stderr.strip()}")

    hops: list[Hop] = []
    for line in output.splitlines():
        hop = parse_traceroute_line(line)
        if hop:
            hops.append(hop)
    return hops


def trace_and_enrich(
    target: str,
    *,
    max_hops: int = 30,
    probes: int = 3,
    timeout_sec: int = 5,
    ipv6: bool = False,
    use_bgp_api: bool = True,
    enrich_timeout: float = 6.0,
    workers: int = 8,
) -> list[EnrichedHop]:
    hops = run_traceroute(
        target,
        max_hops=max_hops,
        probes=probes,
        timeout_sec=timeout_sec,
        ipv6=ipv6,
    )
    addresses = [h.address for h in hops if h.address]
    enrichment = enrich_addresses_parallel(
        [a for a in addresses if a],
        workers=workers,
        use_bgp_api=use_bgp_api,
        timeout=enrich_timeout,
    )

    enriched: list[EnrichedHop] = []
    for hop in hops:
        addr = hop.address
        asn, bgp, rdns = (None, None, None)
        if addr and addr in enrichment:
            asn, bgp, rdns = enrichment[addr]
        elif addr and is_public_ip(addr):
            asn, bgp, rdns = enrichment.get(addr, (None, None, None))
        enriched.append(EnrichedHop(hop=hop, asn=asn, bgp=bgp, reverse_dns=rdns))
    return enriched


def iter_trace_stream(target: str, **kwargs: object) -> Iterator[EnrichedHop]:
    """Run trace then yield enriched hops (batch enrichment after trace)."""
    result = trace_and_enrich(target, **kwargs)  # type: ignore[arg-type]
    yield from result
