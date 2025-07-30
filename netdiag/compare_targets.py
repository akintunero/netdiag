from __future__ import annotations

from dataclasses import dataclass

from netdiag.stats import LatencyStats, format_latency_summary
from netdiag.tools import resolve_dns, run_ping


@dataclass(frozen=True)
class TargetSnapshot:
    target: str
    dns_a: tuple[str, ...]
    ping: LatencyStats


@dataclass(frozen=True)
class CompareReport:
    left: TargetSnapshot
    right: TargetSnapshot


def compare_hosts(
    left: str,
    right: str,
    *,
    ping_count: int = 5,
) -> CompareReport:
    def snapshot(target: str) -> TargetSnapshot:
        try:
            dns_a = tuple(resolve_dns(target, "A"))
        except RuntimeError:
            dns_a = ()
        ping = run_ping(target, count=ping_count)
        return TargetSnapshot(target=target, dns_a=dns_a, ping=ping)

    return CompareReport(left=snapshot(left), right=snapshot(right))
