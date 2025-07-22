from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from netdiag.tools import tcp_probe

MAX_PORTS = 500

# Common TCP services for quick checks (not a full nmap top-1000)
COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    27017,
)


@dataclass(frozen=True)
class PortScanResult:
    port: int
    open: bool
    latency_ms: float | None
    error: str | None


def parse_ports_spec(spec: str) -> list[int]:
    """Parse '22,80,443' or '8000-8010' (inclusive)."""
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return _dedupe_sorted(ports)


def _dedupe_sorted(ports: list[int]) -> list[int]:
    seen: set[int] = set()
    ordered: list[int] = []
    for p in sorted(ports):
        if p < 1 or p > 65535:
            raise ValueError(f"port out of range: {p}")
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def resolve_port_list(
    *,
    ports_arg: str | None = None,
    common: bool = False,
    range_spec: str | None = None,
) -> list[int]:
    if sum(bool(x) for x in (ports_arg, common, range_spec)) != 1:
        raise ValueError("specify exactly one of: port list, --common, or --range")

    if common:
        return list(COMMON_PORTS)
    if ports_arg:
        return parse_ports_spec(ports_arg)
    assert range_spec is not None
    return parse_ports_spec(range_spec)


def scan_tcp_ports(
    host: str,
    ports: list[int],
    *,
    timeout: float = 2.0,
    workers: int = 32,
) -> list[PortScanResult]:
    if len(ports) > MAX_PORTS:
        raise ValueError(f"at most {MAX_PORTS} ports per scan (got {len(ports)})")

    results: list[PortScanResult] = []

    def probe(port: int) -> PortScanResult:
        ok, ms, err = tcp_probe(host, port, timeout=timeout)
        return PortScanResult(port=port, open=ok, latency_ms=ms, error=err)

    workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe, p): p for p in ports}
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r.port)
