from __future__ import annotations

import shutil
import socket
import subprocess
import time

from netdiag.latency_probe import run_ping_latency
from netdiag.stats import LatencyStats

# Backward-compatible alias
PingStats = LatencyStats


def run_ping(
    target: str,
    count: int = 4,
    timeout_sec: int = 5,
    *,
    interval_sec: float | None = None,
) -> LatencyStats:
    return run_ping_latency(
        target,
        count=count,
        interval_sec=interval_sec,
        timeout_sec=timeout_sec,
    )


def resolve_dns(name: str, record_type: str = "A") -> list[str]:
    record_type = record_type.upper()
    if shutil.which("dig"):
        try:
            proc = subprocess.run(
                ["dig", "+short", name, record_type],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"dig timed out for {name!r}") from exc
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip() and not ln.startswith(";")]
        return lines

    if record_type in ("A", "AAAA"):
        family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
        results: list[str] = []
        try:
            infos = socket.getaddrinfo(name, None, family=family, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise RuntimeError(f"DNS lookup failed for {name!r}: {exc}") from exc
        for res in infos:
            ip = res[4][0]
            if ip not in results:
                results.append(ip)
        return results

    raise RuntimeError(f"Record type {record_type} requires `dig` on PATH.")


def tcp_probe(host: str, port: int, timeout: float = 5.0) -> tuple[bool, float | None, str | None]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - start) * 1000
            return True, elapsed, None
    except OSError as exc:
        return False, None, str(exc)
