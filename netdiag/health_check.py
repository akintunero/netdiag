from __future__ import annotations

from dataclasses import dataclass

from netdiag.http_probe import http_probe
from netdiag.ipcalc import reverse_dns
from netdiag.stats import format_latency_summary
from netdiag.targets import literal_dns_step, parse_literal_ip
from netdiag.tools import resolve_dns, run_ping, tcp_probe


@dataclass(frozen=True)
class CheckStep:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class HealthReport:
    target: str
    steps: tuple[CheckStep, ...]

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)


def run_health_check(
    target: str,
    *,
    dns_type: str = "A",
    ping_count: int = 3,
    port: int | None = None,
    url: str | None = None,
) -> HealthReport:
    steps: list[CheckStep] = []
    resolved_ip: str | None = None

    literal = literal_dns_step(target, dns_type)
    if literal is not None:
        if literal.resolved_ip:
            resolved_ip = literal.resolved_ip
        steps.append(CheckStep(name=f"DNS {dns_type}", ok=literal.ok, detail=literal.detail))
    else:
        try:
            records = resolve_dns(target, dns_type)
            if records:
                resolved_ip = records[0]
                steps.append(
                    CheckStep(
                        name=f"DNS {dns_type}",
                        ok=True,
                        detail=", ".join(records[:5]) + (" …" if len(records) > 5 else ""),
                    )
                )
            else:
                steps.append(CheckStep(name=f"DNS {dns_type}", ok=False, detail="no records"))
        except RuntimeError as exc:
            steps.append(CheckStep(name=f"DNS {dns_type}", ok=False, detail=str(exc)))

    ping = run_ping(target, count=ping_count)
    ping_ok = ping.received > 0
    if ping.avg_ms is not None:
        rtt = format_latency_summary(ping)
    else:
        rtt = "no RTT"
    steps.append(
        CheckStep(
            name="Ping",
            ok=ping_ok,
            detail=f"{ping.received}/{ping.sent} replies, {ping.loss_pct:.0f}% loss, {rtt}",
        )
    )

    if port is not None:
        open_ok, ms, err = tcp_probe(target, port)
        detail = f"open {ms:.1f} ms" if open_ok and ms is not None else (err or "closed")
        steps.append(CheckStep(name=f"TCP {port}", ok=open_ok, detail=detail))

    if url:
        probe = http_probe(url)
        status = str(probe.status) if probe.status is not None else "-"
        detail = f"HTTP {status} in {probe.elapsed_ms:.0f} ms"
        if probe.error:
            detail += f" ({probe.error})"
        steps.append(CheckStep(name="HTTP", ok=probe.ok, detail=detail))

    ptr_ip = resolved_ip or parse_literal_ip(target)
    if ptr_ip and dns_type in ("A", "AAAA"):
        ptr, err = reverse_dns(ptr_ip)
        if ptr:
            steps.append(CheckStep(name="PTR", ok=True, detail=ptr))
        elif err:
            steps.append(CheckStep(name="PTR", ok=False, detail=err))

    return HealthReport(target=target, steps=tuple(steps))
