from __future__ import annotations

from dataclasses import dataclass

from netdiag.dns_all import lookup_all_records
from netdiag.dns_tools import dns_compare, summarize_dns_compare
from netdiag.health_check import CheckStep, HealthReport
from netdiag.http_extras import check_security_headers, follow_redirects
from netdiag.http_probe import http_timing, tls_inspect
from netdiag.presets import get_preset
from netdiag.vpn_diag import VpnDiagnostic
from netdiag.stats import format_latency_summary, format_ms
from netdiag.targets import (
    https_url_for_target,
    literal_dns_step,
    parse_literal_ip,
    parse_probe_host,
    should_skip_dns_compare,
)
from netdiag.tools import resolve_dns, run_ping, tcp_probe
from netdiag.traceroute import trace_and_enrich


@dataclass(frozen=True)
class OncallReport:
    target: str
    preset: str
    health: HealthReport
    extra_steps: tuple[CheckStep, ...]
    trace_hops: int | None
    tls_days_remaining: int | None

    @property
    def steps(self) -> tuple[CheckStep, ...]:
        return self.health.steps + self.extra_steps

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)


def run_preset_check(
    target: str,
    preset_name: str,
    *,
    url: str | None = None,
    corp_host: str | None = None,
) -> OncallReport:
    preset = get_preset(preset_name)
    steps: list[CheckStep] = []
    resolved_ip: str | None = None

    for dns_type in preset.dns_types:
        literal = literal_dns_step(target, dns_type)
        if literal is not None:
            if literal.resolved_ip and resolved_ip is None:
                resolved_ip = literal.resolved_ip
            steps.append(CheckStep(name=f"DNS {dns_type}", ok=literal.ok, detail=literal.detail))
            continue
        try:
            records = resolve_dns(target, dns_type)
            if records:
                if resolved_ip is None:
                    resolved_ip = records[0]
                steps.append(
                    CheckStep(
                        name=f"DNS {dns_type}",
                        ok=True,
                        detail=", ".join(records[:5]),
                    )
                )
            else:
                steps.append(CheckStep(name=f"DNS {dns_type}", ok=False, detail="no records"))
        except RuntimeError as exc:
            steps.append(CheckStep(name=f"DNS {dns_type}", ok=False, detail=str(exc)))

    ping = run_ping(target, count=preset.ping_count)
    rtt = format_latency_summary(ping) if ping.avg_ms is not None else "no RTT"
    steps.append(
        CheckStep(
            name="Ping",
            ok=ping.received > 0,
            detail=f"{ping.received}/{ping.sent}, {ping.loss_pct:.0f}% loss, {rtt}",
        )
    )

    for port in preset.ports:
        open_ok, ms, err = tcp_probe(target, port)
        detail = f"open {ms:.1f} ms" if open_ok and ms is not None else (err or "closed")
        steps.append(CheckStep(name=f"TCP {port}", ok=open_ok, detail=detail))

    tls_days: int | None = None
    if preset.tls_check:
        host, tls_port = parse_probe_host(target)
        tls = tls_inspect(host, port=tls_port or 443, timeout=5.0)
        if tls.error:
            steps.append(CheckStep(name="TLS", ok=False, detail=tls.error))
        else:
            tls_days = tls.days_remaining
            ok = tls.days_remaining is None or tls.days_remaining > 7
            steps.append(
                CheckStep(
                    name="TLS",
                    ok=ok,
                    detail=f"expires in {tls.days_remaining} days" if tls.days_remaining is not None else "ok",
                )
            )

    probe_url = url
    if preset.http_timing and not probe_url:
        probe_url = https_url_for_target(target)
    if probe_url and preset.http_timing:
        timing = http_timing(probe_url, timeout=10.0)
        detail = f"total {timing.total_ms:.0f} ms"
        if timing.dns_ms is not None:
            detail += f" (dns {timing.dns_ms:.0f}, tcp {timing.connect_ms or 0:.0f}, tls {timing.tls_ms or 0:.0f})"
        if timing.error:
            detail += f" - {timing.error}"
        steps.append(CheckStep(name="HTTP timing", ok=timing.ok, detail=detail))

        redirect_chain = None
        if preset.redirect_check and not parse_literal_ip(target):
            redirect_chain = follow_redirects(probe_url)
            n = len(redirect_chain.hops)
            detail = f"{n} hop(s), final {redirect_chain.final_url or '-'}"
            if redirect_chain.error:
                detail += f" - {redirect_chain.error}"
            steps.append(
                CheckStep(
                    name="Redirects",
                    ok=redirect_chain.error is None and n > 0,
                    detail=detail,
                )
            )
        elif preset.redirect_check and parse_literal_ip(target):
            steps.append(
                CheckStep(
                    name="Redirects",
                    ok=True,
                    detail="skipped (literal IP target)",
                )
            )

        if preset.headers_check and not parse_literal_ip(target):
            headers_url = probe_url
            if redirect_chain and redirect_chain.final_url:
                headers_url = redirect_chain.final_url
            sec = check_security_headers(headers_url)
            missing = [h.name for h in sec.headers if not h.present]
            if sec.error:
                detail = sec.error
                headers_ok = False
            elif not missing:
                detail = "all present"
                headers_ok = True
            else:
                detail = f"missing: {', '.join(missing)}"
                headers_ok = False
            steps.append(
                CheckStep(
                    name="Security headers",
                    ok=headers_ok,
                    detail=detail,
                )
            )
        elif preset.headers_check and parse_literal_ip(target):
            steps.append(
                CheckStep(
                    name="Security headers",
                    ok=True,
                    detail="skipped (literal IP target)",
                )
            )

    if preset.dns_all:
        if parse_literal_ip(target):
            steps.append(
                CheckStep(name="DNS all", ok=True, detail="skipped (literal IP target)"),
            )
        else:
            try:
                dall = lookup_all_records(target)
                found = sum(1 for s in dall.sets if s.records)
                steps.append(
                    CheckStep(
                        name="DNS all",
                        ok=found > 0,
                        detail=f"{found}/{len(dall.sets)} record types have answers",
                    )
                )
            except RuntimeError as exc:
                steps.append(CheckStep(name="DNS all", ok=False, detail=str(exc)))

    extra: list[CheckStep] = []
    trace_count: int | None = None

    if preset.dns_compare:
        if should_skip_dns_compare(target) and not corp_host:
            extra.append(
                CheckStep(
                    name="DNS resolvers",
                    ok=True,
                    detail="skipped (literal IP; use --corp for resolver compare)",
                ),
            )
        else:
            compare_name = corp_host or target
            try:
                results = dns_compare(compare_name, "A")
                ok, detail = summarize_dns_compare(results)
                extra.append(CheckStep(name="DNS resolvers", ok=ok, detail=detail))
            except RuntimeError as exc:
                extra.append(CheckStep(name="DNS resolvers", ok=False, detail=str(exc)))

    for pub in preset.public_ping_targets:
        p = run_ping(pub, count=3)
        extra.append(
            CheckStep(
                name=f"Path check {pub}",
                ok=p.received > 0,
                detail=f"avg {format_ms(p.avg_ms)} ms",
            )
        )

    if preset.trace_max_hops:
        try:
            hops = trace_and_enrich(target, max_hops=preset.trace_max_hops, probes=1, use_bgp_api=False)
            trace_count = len(hops)
            last = hops[-1].hop.address if hops else None
            extra.append(
                CheckStep(
                    name="Trace",
                    ok=bool(hops),
                    detail=f"{trace_count} hops, last {last or '-'}",
                )
            )
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            extra.append(CheckStep(name="Trace", ok=False, detail=str(exc)))

    health = HealthReport(target=target, steps=tuple(steps))
    return OncallReport(
        target=target,
        preset=preset.name,
        health=health,
        extra_steps=tuple(extra),
        trace_hops=trace_count,
        tls_days_remaining=tls_days,
    )


def format_oncall_report(report: OncallReport, vpn: VpnDiagnostic | None = None) -> str:
    lines = [
        f"# netdiag on-call: {report.target}",
        f"preset: {report.preset}",
        "",
    ]
    if vpn is not None:
        lines.append("## VPN context")
        if vpn.split_tunnel_hint:
            lines.append(f"- Note: {vpn.split_tunnel_hint}")
        for step in vpn.steps:
            mark = "PASS" if step.ok else "FAIL"
            lines.append(f"- [{mark}] {step.name}: {step.detail}")
        lines.append("")
    lines.append("## Service checks")
    for step in report.steps:
        mark = "PASS" if step.ok else "FAIL"
        lines.append(f"- [{mark}] {step.name}: {step.detail}")
    lines.append("")
    overall = report.ok and (vpn is None or all(s.ok for s in vpn.steps))
    lines.append(f"Overall: {'PASS' if overall else 'FAIL'}")
    return "\n".join(lines)
