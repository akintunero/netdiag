from __future__ import annotations

import sys
from typing import TextIO

from netdiag.health_check import HealthReport
from netdiag.dns_tools import DnsCompareResult
from netdiag.http_probe import HttpProbeResult, HttpTimingResult, TlsCertInfo
from netdiag.speed import SpeedResult, SpeedTestReport
from netdiag.ipcalc import SubnetInfo
from netdiag.models import AsnRecord, BgpRecord, EnrichedHop
from netdiag.stats import LatencyStats, format_latency_summary


def _avg_rtt_ms(rtts: list[float]) -> str:
    if not rtts:
        return "-"
    return f"{sum(rtts) / len(rtts):.1f} ms"


def _provider_label(asn: AsnRecord | None, bgp: BgpRecord | None) -> str:
    if asn and asn.name:
        base = f"AS{asn.asn} {asn.name}" if asn.asn else asn.name
    elif bgp and bgp.name:
        base = f"AS{bgp.asn} {bgp.name}" if bgp.asn else bgp.name
    elif asn and asn.asn:
        base = f"AS{asn.asn}"
    elif bgp and bgp.asn:
        base = f"AS{bgp.asn}"
    else:
        return "-"
    return base


def _prefix_label(asn: AsnRecord | None, bgp: BgpRecord | None) -> str:
    prefix = None
    if bgp and bgp.prefix:
        prefix = bgp.prefix
    elif asn and asn.prefix:
        prefix = asn.prefix
    return prefix or "-"


def print_trace_table(hops: list[EnrichedHop], *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    headers = ("#", "Address", "Hostname", "RTT (avg)", "ASN / Provider", "BGP Prefix", "Country")
    widths = (4, 18, 28, 10, 32, 20, 6)
    row_fmt = " ".join(f"{{:{w}}}" for w in widths)

    out.write(row_fmt.format(*headers) + "\n")
    out.write("-" * (sum(widths) + len(widths) - 1) + "\n")

    for item in hops:
        hop = item.hop
        addr = hop.address or "*"
        host = hop.hostname or item.reverse_dns or "-"
        if hop.hostname and item.reverse_dns and hop.hostname != item.reverse_dns:
            host = f"{hop.hostname}"

        provider = _provider_label(item.asn, item.bgp)
        prefix = _prefix_label(item.asn, item.bgp)
        country = "-"
        if item.asn and item.asn.country:
            country = item.asn.country
        elif item.bgp and item.bgp.country:
            country = item.bgp.country

        out.write(
            row_fmt.format(
                hop.index,
                addr[:18],
                (host[:26] + "..") if len(host) > 28 else host,
                _avg_rtt_ms(hop.rtt_ms),
                (provider[:30] + "..") if len(provider) > 32 else provider,
                (prefix[:18] + "..") if len(prefix) > 20 else prefix,
                country,
            )
            + "\n"
        )


def print_ip_intel(
    addr: str,
    asn: AsnRecord | None,
    bgp: BgpRecord | None,
    rdns: str | None,
    *,
    stream: TextIO | None = None,
) -> None:
    out = stream or sys.stdout
    out.write(f"IP:          {addr}\n")
    if rdns:
        out.write(f"PTR:         {rdns}\n")
    if asn:
        out.write(f"ASN:         {asn.asn or '-'}\n")
        out.write(f"Prefix:      {asn.prefix or '-'}\n")
        out.write(f"Registry:    {asn.registry or '-'}\n")
        out.write(f"Allocated:   {asn.allocated or '-'}\n")
        out.write(f"Provider:    {asn.name or '-'}\n")
        out.write(f"Country:     {asn.country or '-'}\n")
    if bgp:
        out.write("--- BGP (RIPEstat / BGPView) ---\n")
        out.write(f"BGP ASN:     {bgp.asn or '-'}\n")
        out.write(f"BGP Prefix:  {bgp.prefix or '-'}\n")
        if bgp.name:
            out.write(f"BGP Name:    {bgp.name}\n")
        if bgp.rir:
            out.write(f"RIR:         {bgp.rir}\n")
        if bgp.description:
            out.write(f"Description: {bgp.description}\n")
    if not asn and not bgp:
        out.write("No public ASN/BGP data (private, bogon, or lookup failed).\n")


def print_vpn_diagnostic(diag, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write("VPN diagnostic\n\n")
    if diag.split_tunnel_hint:
        out.write(f"Note: {diag.split_tunnel_hint}\n\n")
    if diag.vpn_interfaces:
        out.write("Tunnel interfaces:\n")
        for iface in diag.vpn_interfaces:
            addrs = ", ".join(iface.addresses) or "-"
            out.write(f"  {iface.name}  {addrs}\n")
        out.write("\n")
    if diag.default_routes:
        out.write("Default routes:\n")
        for r in diag.default_routes:
            out.write(f"  {r.destination} via {r.gateway or '-'} dev {r.interface or '-'}\n")
        out.write("\n")
    if diag.tunnel_routes:
        out.write(f"Private/tunnel routes: {len(diag.tunnel_routes)} entries\n\n")
    if diag.dns_resolvers:
        out.write("DNS configuration:\n")
        for res in diag.dns_resolvers:
            out.write(f"  [{res.source}] {', '.join(res.nameservers) or '-'}\n")
        out.write("\n")
    for step in diag.steps:
        mark = "ok" if step.ok else "FAIL"
        out.write(f"  [{mark:4}] {step.name:<28} {step.detail}\n")
    out.write(f"\nOverall: {'PASS' if all(s.ok for s in diag.steps) else 'FAIL'}\n")


def print_oncall_report(report, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"On-call check: {report.target} (preset={report.preset})\n\n")
    for step in report.steps:
        mark = "ok" if step.ok else "FAIL"
        out.write(f"  [{mark:4}] {step.name:<20} {step.detail}\n")
    out.write(f"\nOverall: {'PASS' if report.ok else 'FAIL'}\n")


def print_compare_report(report, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    for label, snap in (("A", report.left), ("B", report.right)):
        out.write(f"{label}: {snap.target}\n")
        out.write(f"  DNS A: {', '.join(snap.dns_a) or '-'}\n")
        if snap.ping.avg_ms is not None:
            out.write(f"  Ping:  {format_latency_summary(snap.ping)}\n")
        else:
            out.write("  Ping:  no replies\n")
        out.write("\n")


def print_health_report(report: HealthReport, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"Health check: {report.target}\n")
    for step in report.steps:
        mark = "ok" if step.ok else "FAIL"
        out.write(f"  [{mark:4}] {step.name:<12} {step.detail}\n")
    out.write(f"\nOverall: {'PASS' if report.ok else 'FAIL'}\n")


def print_subnet(info: SubnetInfo, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"CIDR:        {info.cidr}\n")
    out.write(f"Version:     IPv{info.version}\n")
    out.write(f"Network:     {info.network}\n")
    if info.broadcast:
        out.write(f"Broadcast:   {info.broadcast}\n")
    out.write(f"Netmask:     {info.netmask}\n")
    if info.hostmask:
        out.write(f"Host mask:   {info.hostmask}\n")
    if info.first_host:
        out.write(f"Host range:  {info.first_host} – {info.last_host}\n")
    out.write(f"Addresses:   {info.num_addresses}\n")
    if info.num_hosts is not None:
        out.write(f"Usable hosts:{info.num_hosts}\n")
    out.write(f"Private:     {info.is_private}\n")
    out.write(f"Global:      {info.is_global}\n")


def print_http_timing(result: HttpTimingResult, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"URL:         {result.url}\n")
    out.write(f"Method:      {result.method}\n")
    if result.status is not None:
        out.write(f"Status:      {result.status}\n")
    out.write(f"Total:       {result.total_ms:.1f} ms\n")
    if result.dns_ms is not None:
        out.write(f"  DNS:       {result.dns_ms:.1f} ms\n")
    if result.connect_ms is not None:
        out.write(f"  TCP:       {result.connect_ms:.1f} ms\n")
    if result.tls_ms is not None:
        out.write(f"  TLS:       {result.tls_ms:.1f} ms\n")
    if result.request_ms is not None:
        out.write(f"  Request:   {result.request_ms:.1f} ms\n")
    if result.error:
        out.write(f"Error:       {result.error}\n")
    out.write(f"Result:      {'OK' if result.ok else 'FAIL'}\n")


def print_speed_result(result: SpeedResult, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"Mode:        {result.mode}\n")
    out.write(f"Target:      {result.target}\n")
    if result.error:
        out.write(f"Error:       {result.error}\n")
        return
    out.write(f"Duration:    {result.elapsed_sec:.2f} s\n")
    if result.bytes_downloaded:
        out.write(f"Downloaded:  {result.bytes_downloaded:,} bytes\n")
    if result.megabits_per_sec is not None:
        out.write(f"Throughput:  {result.megabits_per_sec:.2f} Mbps\n")


def _print_speed_probe(label: str, probe, *, out: TextIO) -> None:
    out.write(f"{label} target:   {probe.target}\n")
    if probe.error:
        out.write(f"{label} error:    {probe.error}\n")
        return
    streams = f" ({probe.parallel} streams)" if probe.parallel > 1 else ""
    out.write(f"{label} duration: {probe.elapsed_sec:.2f} s{streams}\n")
    out.write(f"{label} bytes:    {probe.bytes_transferred:,}\n")
    if probe.megabits_per_sec is not None:
        out.write(f"{label} speed:    {probe.megabits_per_sec:.2f} Mbps\n")


def print_speed_test_report(report: SpeedTestReport, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"Provider:    {report.provider}\n")
    if report.download:
        _print_speed_probe("Download", report.download, out=out)
    if report.upload:
        out.write("\n")
        _print_speed_probe("Upload", report.upload, out=out)


def print_dns_compare(results: list[DnsCompareResult], name: str, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"DNS compare: {name}\n\n")
    for r in results:
        server = r.server or "resolver default"
        out.write(f"  {r.resolver:<12} @{server}\n")
        if r.error:
            out.write(f"    error: {r.error}\n")
        elif r.records:
            for rec in r.records:
                out.write(f"    {rec}\n")
        else:
            out.write("    (no records)\n")
        out.write("\n")


def print_http_result(result: HttpProbeResult, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"URL:         {result.url}\n")
    out.write(f"Method:      {result.method}\n")
    if result.status is not None:
        out.write(f"Status:      {result.status}\n")
    out.write(f"Time:        {result.elapsed_ms:.1f} ms\n")
    if result.final_url and result.final_url != result.url:
        out.write(f"Final URL:   {result.final_url}\n")
    if result.server:
        out.write(f"Server:      {result.server}\n")
    if result.content_type:
        out.write(f"Content-Type:{result.content_type}\n")
    if result.content_length:
        out.write(f"Length:      {result.content_length}\n")
    if result.error:
        out.write(f"Error:       {result.error}\n")
    out.write(f"Result:      {'OK' if result.ok else 'FAIL'}\n")


def print_tls_info(info: TlsCertInfo, *, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    out.write(f"Host:        {info.host}:{info.port}\n")
    if info.error:
        out.write(f"Error:       {info.error}\n")
        return
    if info.protocol:
        out.write(f"TLS:         {info.protocol}\n")
    if info.cipher:
        out.write(f"Cipher:      {info.cipher[0]} {info.cipher[1]} ({info.cipher[2]} bits)\n")
    if info.subject:
        out.write(f"Subject:     {info.subject}\n")
    if info.issuer:
        out.write(f"Issuer:      {info.issuer}\n")
    if info.not_before:
        out.write(f"Valid from:  {info.not_before.isoformat()}\n")
    if info.not_after:
        out.write(f"Valid until: {info.not_after.isoformat()}\n")
    if info.days_remaining is not None:
        out.write(f"Days left:   {info.days_remaining}\n")
    if info.sans:
        out.write(f"SANs:        {', '.join(info.sans[:8])}")
        if len(info.sans) > 8:
            out.write(f" (+{len(info.sans) - 8} more)")
        out.write("\n")


def _fmt_ms(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "-"


def print_latency_stats(
    stats: LatencyStats,
    *,
    stream: TextIO | None = None,
    show_samples: bool = False,
) -> None:
    out = stream or sys.stdout
    label = "PING" if stats.probe == "icmp" else "TCP"
    out.write(f"{label} {stats.target} ({stats.probe})\n")
    out.write(
        f"  packets: {stats.received}/{stats.sent} received, {stats.loss_pct:.0f}% loss\n"
    )
    if stats.avg_ms is not None:
        out.write(f"  rtt:     {format_latency_summary(stats)}\n")
    if stats.p50_ms is not None:
        out.write(
            f"  percentiles: p50 {_fmt_ms(stats.p50_ms)}  "
            f"p95 {_fmt_ms(stats.p95_ms)}  p99 {_fmt_ms(stats.p99_ms)} ms\n"
        )
    if stats.stddev_ms is not None and stats.jitter_ms is not None:
        out.write(
            f"  jitter:  stddev {_fmt_ms(stats.stddev_ms)} ms, "
            f"RFC3550 IAJ {_fmt_ms(stats.jitter_ms)} ms\n"
        )
    if show_samples and stats.samples_ms:
        out.write("  samples:\n")
        for i, ms in enumerate(stats.samples_ms, 1):
            out.write(f"    {i:3}  {ms:.2f} ms\n")
