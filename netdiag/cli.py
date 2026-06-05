from __future__ import annotations

import argparse
import shutil
import sys

from netdiag import __version__
from netdiag.banner import print_banner
from netdiag.info import print_info
from netdiag.json_out import emit_json
from netdiag.completion import bash_completion, zsh_completion
from netdiag.config import CONFIG_PATH, load_config
from netdiag.doctor import run_doctor
from netdiag.exit_codes import EX_ERROR, EX_FAIL, EX_OK
from netdiag.compare_targets import compare_hosts
from netdiag.display import (
    print_compare_report,
    print_dns_compare,
    print_health_report,
    print_http_result,
    print_http_timing,
    print_ip_intel,
    print_latency_stats,
    print_oncall_report,
    print_speed_result,
    print_speed_test_report,
    print_subnet,
    print_tls_info,
    print_trace_table,
    print_vpn_diagnostic,
)
from netdiag.dns_config import read_dns_config
from netdiag.dns_all import lookup_all_records
from netdiag.http_extras import (
    check_security_headers,
    follow_redirects,
    run_mtr,
)
from netdiag.oncall import format_oncall_report, run_preset_check
from netdiag.presets import PRESETS, get_preset
from netdiag.vpn_diag import run_vpn_diagnostic
from netdiag.dns_tools import dns_compare, dns_trace, dns_compare_is_consistent, parse_trace_hops
from netdiag.enrichment import enrich_address, lookup_asn_cymru_dns
from netdiag.health_check import run_health_check
from netdiag.host_info import (
    list_all_listeners,
    list_connections,
    list_interfaces,
    list_routes,
    listeners_on_port,
)
from netdiag.http_probe import http_probe, http_timing, parse_host_port, tls_inspect
from netdiag.ipcalc import address_properties, describe_subnet, reverse_dns
from netdiag.latency_probe import run_tcp_latency
from netdiag.port_scan import resolve_port_list, scan_tcp_ports
from netdiag.serialize import enriched_hop_dict, health_report_dict
from netdiag.speed import run_speed_test, speed_download, speed_iperf
from netdiag.tools import resolve_dns, run_ping, tcp_probe
from netdiag.traceroute import trace_and_enrich


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")


def _build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="netdiag",
        description=(
            "Network troubleshooting CLI for on-call and VPN debugging. "
            "Primary workflow: netdiag oncall HOST --json"
        ),
        epilog="Exit codes and stability: docs/CLI_CONTRACT.md · Pre-flight: netdiag doctor",
    )
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    root.add_argument(
        "--info",
        action="store_true",
        help="Show version, developer, repository, and runtime details",
    )
    root.add_argument(
        "--json",
        action="store_true",
        help="With --info: machine-readable JSON output",
    )

    sub = root.add_subparsers(dest="command", required=False)

    trace = sub.add_parser("trace", help="Traceroute to target with hop ASN/BGP enrichment")
    trace.add_argument("target", help="Hostname or IP")
    trace.add_argument("-m", "--max-hops", type=int, default=30, metavar="N")
    trace.add_argument("-q", "--probes", type=int, default=3, metavar="N", help="Probes per hop")
    trace.add_argument("-w", "--wait", type=int, default=5, metavar="SEC", help="Per-probe timeout")
    trace.add_argument("-6", action="store_true", dest="ipv6", help="Use IPv6 traceroute")
    trace.add_argument(
        "--no-bgp-api",
        action="store_true",
        help="Skip BGPView/RIPEstat HTTP lookups (Cymru DNS/WHOIS only)",
    )
    trace.add_argument("--workers", type=int, default=8, help="Parallel enrichment workers")

    whois = sub.add_parser("whois", help="ASN and BGP info for an IP address")
    whois.add_argument("address", help="IPv4 or IPv6 address")
    whois.add_argument(
        "--no-bgp-api",
        action="store_true",
        help="Skip BGPView/RIPEstat HTTP lookups",
    )

    ping = sub.add_parser("ping", help="ICMP echo check with RTT and jitter stats")
    ping.add_argument("target", help="Hostname or IP")
    ping.add_argument("-c", "--count", type=int, default=4, metavar="N")
    ping.add_argument(
        "-i",
        "--interval",
        type=float,
        default=None,
        metavar="SEC",
        help="Seconds between probes (requires root on some systems)",
    )
    ping.add_argument(
        "--stats",
        action="store_true",
        help="Print per-sample RTTs and full percentile summary",
    )

    latency = sub.add_parser(
        "latency",
        help="TCP connect latency distribution (RTT, jitter, percentiles)",
    )
    latency.add_argument("host", help="Hostname or IP")
    latency.add_argument("-p", "--port", type=int, default=443, metavar="PORT")
    latency.add_argument("-n", "--count", type=int, default=20, metavar="N")
    latency.add_argument(
        "-i",
        "--interval",
        type=float,
        default=0.2,
        metavar="SEC",
        help="Delay between probes",
    )
    latency.add_argument("--timeout", type=float, default=5.0, metavar="SEC")
    latency.add_argument(
        "--stats",
        action="store_true",
        help="Print each connect sample",
    )

    dns = sub.add_parser("dns", help="DNS lookup (requires dig for non A/AAAA)")
    dns.add_argument("name", help="Hostname")
    dns.add_argument(
        "-t",
        "--type",
        default="A",
        metavar="TYPE",
        help="Record type (A, AAAA, MX, NS, TXT, CNAME, ...)",
    )

    port = sub.add_parser("port", help="TCP connect probe (single port)")
    port.add_argument("host", help="Hostname or IP")
    port.add_argument("port", type=int, metavar="PORT")
    port.add_argument("--timeout", type=float, default=5.0, metavar="SEC")

    ports = sub.add_parser("ports", help="Scan multiple TCP ports for open services")
    ports.add_argument("host", help="Hostname or IP")
    ports_group = ports.add_mutually_exclusive_group(required=True)
    ports_group.add_argument(
        "port_list",
        nargs="?",
        metavar="PORTS",
        help="Comma-separated ports and/or ranges (e.g. 22,80,8000-8010)",
    )
    ports_group.add_argument(
        "--common",
        action="store_true",
        help=f"Scan {24} common service ports",
    )
    ports_group.add_argument(
        "--range",
        metavar="RANGE",
        help="Inclusive range (e.g. 1-1024); max 500 ports per scan",
    )
    ports.add_argument("--timeout", type=float, default=2.0, metavar="SEC")
    ports.add_argument("--workers", type=int, default=32, metavar="N")
    ports.add_argument(
        "--all",
        action="store_true",
        help="Show closed/filtered ports too (default: open only)",
    )

    check = sub.add_parser("check", help="Multi-step reachability check (DNS, ping, optional TCP/HTTP)")
    check.add_argument("target", help="Hostname or IP")
    check.add_argument("-c", "--count", type=int, default=3, metavar="N", help="Ping count")
    check.add_argument("-p", "--port", type=int, metavar="PORT", help="Also probe TCP port")
    check.add_argument("--url", metavar="URL", help="Also probe HTTP(S) URL")
    check.add_argument(
        "-t",
        "--type",
        default="A",
        dest="dns_type",
        metavar="TYPE",
        help="DNS record type for resolution (default A)",
    )
    check.add_argument(
        "--preset",
        choices=tuple(PRESETS.keys()),
        metavar="NAME",
        help="Run a preset bundle: web, api, vpn, oncall (overrides manual flags)",
    )
    check.add_argument(
        "--corp",
        metavar="HOST",
        help="Corporate hostname (for vpn preset or DNS compare)",
    )

    oncall = sub.add_parser(
        "oncall",
        help="SRE on-call diagnostic bundle (DNS, ping, ports, TLS, trace, …)",
    )
    oncall.add_argument("target", help="Service hostname or IP")
    oncall.add_argument(
        "--preset",
        default="oncall",
        choices=tuple(PRESETS.keys()),
        help="Check preset (default: oncall)",
    )
    oncall.add_argument("--url", metavar="URL", help="Override HTTPS URL for timing probe")
    oncall.add_argument("--corp", metavar="HOST", help="Corporate host for DNS compare")
    oncall.add_argument(
        "--vpn",
        action="store_true",
        help="Include VPN diagnostic section (tunnel, routes, DNS drift)",
    )

    vpn = sub.add_parser(
        "vpn",
        help="Corporate VPN debugging: tunnel ifaces, routes, DNS drift, reachability",
    )
    vpn.add_argument(
        "--corp",
        metavar="HOST",
        help="Internal hostname to test (DNS + TCP 443 + ping)",
    )
    vpn.add_argument(
        "--dns-name",
        default="google.com",
        metavar="NAME",
        help="Public name for DNS leak / resolver compare",
    )

    compare = sub.add_parser(
        "compare",
        help="Compare DNS and ping between two targets (baseline vs current)",
    )
    compare.add_argument("left", help="First hostname (e.g. baseline)")
    compare.add_argument("right", help="Second hostname (e.g. over VPN)")
    compare.add_argument("-c", "--count", type=int, default=5, metavar="N", help="Ping count")

    report = sub.add_parser("report", help="Write a markdown on-call report to stdout or file")
    report.add_argument("target", help="Service hostname")
    report.add_argument(
        "--preset",
        default="oncall",
        choices=tuple(PRESETS.keys()),
        help="Report preset",
    )
    report.add_argument("-o", "--output", metavar="FILE", help="Write report to file")
    report.add_argument("--url", metavar="URL", help="HTTPS URL for timing section")
    report.add_argument("--corp", metavar="HOST", help="Corporate host for DNS compare")
    report.add_argument(
        "--vpn",
        action="store_true",
        help="Prepend VPN diagnostic section to report",
    )

    presets_cmd = sub.add_parser("presets", help="List on-call / check presets")

    redirects = sub.add_parser("redirects", help="Follow HTTP redirect chain")
    redirects.add_argument("url", help="URL or hostname")
    redirects.add_argument("--max", type=int, default=10, metavar="N")
    redirects.add_argument("--timeout", type=float, default=10.0, metavar="SEC")

    headers = sub.add_parser("headers", help="Check common HTTP security headers")
    headers.add_argument("url", help="URL or hostname")
    headers.add_argument("--timeout", type=float, default=10.0, metavar="SEC")

    mtr = sub.add_parser("mtr", help="Path quality (mtr if installed, else traceroute snapshot)")
    mtr.add_argument("target", help="Hostname or IP")
    mtr.add_argument("-c", "--count", type=int, default=10, metavar="N")
    mtr.add_argument("--timeout", type=float, default=30.0, metavar="SEC")

    dnsall = sub.add_parser("dns-all", help="Summarize common DNS record types (requires dig)")
    dnsall.add_argument("name", help="Hostname")

    dnsconfig = sub.add_parser("dns-config", help="Show active DNS resolver configuration")

    http = sub.add_parser("http", help="HTTP(S) request probe (status and timing)")
    http.add_argument("url", help="URL or hostname (https assumed if no scheme)")
    http.add_argument(
        "-X",
        "--method",
        default="HEAD",
        choices=("HEAD", "GET"),
        help="HTTP method",
    )
    http.add_argument("--timeout", type=float, default=10.0, metavar="SEC")
    http.add_argument(
        "--timing",
        action="store_true",
        help="Show phased timing (DNS, TCP, TLS, request)",
    )

    tls = sub.add_parser("tls", help="TLS certificate and handshake info")
    tls.add_argument("host", help="Hostname or host:port")
    tls.add_argument("-p", "--port", type=int, default=443, metavar="PORT")
    tls.add_argument("--timeout", type=float, default=5.0, metavar="SEC")
    tls.add_argument("--sni", metavar="NAME", help="TLS SNI hostname (default: host)")

    ptr = sub.add_parser("ptr", help="Reverse DNS (PTR) lookup for an IP")
    ptr.add_argument("address", help="IPv4 or IPv6 address")
    ptr.add_argument("--timeout", type=float, default=5.0, metavar="SEC")

    subnet = sub.add_parser("subnet", help="CIDR / IP subnet calculator")
    subnet.add_argument("cidr", help="Network in CIDR notation (e.g. 10.0.0.0/24)")

    ipcmd = sub.add_parser("ip", help="IP address properties (RFC special-use flags)")
    ipcmd.add_argument("address", help="IPv4 or IPv6 address")

    route = sub.add_parser("route", help="Show system routing table")
    route.add_argument(
        "--default-only",
        action="store_true",
        help="Only show default routes",
    )

    ifaces = sub.add_parser("ifaces", help="List local interfaces and addresses")
    ifaces.add_argument(
        "-4",
        action="store_true",
        dest="ipv4_only",
        help="Show IPv4 only",
    )
    ifaces.add_argument(
        "-6",
        action="store_true",
        dest="ipv6_only",
        help="Show IPv6 only",
    )

    listen = sub.add_parser("listen", help="Show local processes listening on a TCP port")
    listen.add_argument("port", type=int, metavar="PORT")

    dnstrace = sub.add_parser("dns-trace", help="DNS delegation trace (dig +trace)")
    dnstrace.add_argument("name", help="Hostname")
    dnstrace.add_argument(
        "-t",
        "--type",
        default="A",
        metavar="TYPE",
        help="Record type to resolve at end of trace",
    )

    dnscompare = sub.add_parser("dns-compare", help="Compare DNS answers across resolvers")
    dnscompare.add_argument("name", help="Hostname")
    dnscompare.add_argument(
        "-t",
        "--type",
        default="A",
        metavar="TYPE",
        help="Record type (default A)",
    )
    dnscompare.add_argument(
        "--corp",
        metavar="HOST",
        help="Also compare DNS for a corporate/internal hostname",
    )

    local_ports = sub.add_parser("local-ports", help="All TCP ports listening on this host")
    connections = sub.add_parser("connections", help="Established TCP/UDP connections")
    connections.add_argument(
        "-n",
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Max rows to show",
    )

    speed = sub.add_parser(
        "speed",
        help="Throughput test (default: Cloudflare CDN, fast.com-style; or URL / iperf3)",
    )
    speed.add_argument(
        "target",
        nargs="?",
        metavar="IP|HOST",
        help="Optional endpoint IP (e.g. 1.1.1.1) or provider name (cloudflare)",
    )
    speed_group = speed.add_mutually_exclusive_group()
    speed_group.add_argument("--url", metavar="URL", help="Download URL for Mbps estimate")
    speed_group.add_argument("--iperf", metavar="HOST", help="iperf3 server hostname")
    speed.add_argument(
        "--upload",
        action="store_true",
        help="Also run upload test (Cloudflare mode only)",
    )
    speed.add_argument(
        "--parallel",
        type=int,
        default=4,
        metavar="N",
        help="Parallel download streams (default mode, default 4)",
    )
    speed.add_argument(
        "--bytes",
        type=int,
        default=20_000_000,
        metavar="N",
        help="Total download bytes for default mode",
    )
    speed.add_argument(
        "--upload-bytes",
        type=int,
        default=2_000_000,
        metavar="N",
        help="Upload payload size for default mode",
    )
    speed.add_argument(
        "--single-stream",
        action="store_true",
        help="One download stream instead of parallel",
    )
    speed.add_argument("-t", "--time", type=int, default=5, metavar="SEC", help="iperf3 duration")
    speed.add_argument("-p", "--port", type=int, default=5201, metavar="PORT", help="iperf3 port")
    speed.add_argument("--timeout", type=float, default=60.0, metavar="SEC")

    doctor = sub.add_parser(
        "doctor",
        help="Verify required system tools for runbooks (exit 2 if required tools missing)",
    )

    completion = sub.add_parser("completion", help="Print shell completion script")
    completion.add_argument(
        "shell",
        choices=("bash", "zsh"),
        help="Shell completion format",
    )

    for parser in (
        trace,
        whois,
        ping,
        latency,
        dns,
        port,
        ports,
        check,
        http,
        tls,
        ptr,
        subnet,
        ipcmd,
        route,
        ifaces,
        listen,
        dnstrace,
        dnscompare,
        local_ports,
        connections,
        speed,
        oncall,
        vpn,
        compare,
        report,
        presets_cmd,
        redirects,
        headers,
        mtr,
        dnsall,
        dnsconfig,
        doctor,
        completion,
    ):
        _add_json_flag(parser)

    return root


def _load_config_safe():
    try:
        return load_config()
    except (ValueError, OSError) as exc:
        raise ValueError(f"invalid config at {CONFIG_PATH}: {exc}") from exc


def _corp_host(args: argparse.Namespace) -> str | None:
    corp = getattr(args, "corp", None)
    if corp:
        return corp
    return _load_config_safe().corp_host


def _oncall_preset(args: argparse.Namespace) -> str:
    preset = getattr(args, "preset", "oncall")
    cfg = _load_config_safe()
    if preset == "oncall" and cfg.oncall_preset:
        preset = cfg.oncall_preset
    get_preset(preset)
    return preset


def _cmd_trace(args: argparse.Namespace) -> int:
    try:
        hops = trace_and_enrich(
            args.target,
            max_hops=args.max_hops,
            probes=args.probes,
            timeout_sec=args.wait,
            ipv6=args.ipv6,
            use_bgp_api=not args.no_bgp_api,
            workers=args.workers,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not hops:
        print("No hops parsed from traceroute output.", file=sys.stderr)
        return 1

    if args.json:
        emit_json({"target": args.target, "hops": [enriched_hop_dict(h) for h in hops]})
        return 0

    print(f"Traceroute to {args.target}\n")
    print_trace_table(hops)
    return 0


def _cmd_whois(args: argparse.Namespace) -> int:
    asn, bgp, rdns = enrich_address(args.address, use_bgp_api=not args.no_bgp_api)
    if asn is None:
        asn = lookup_asn_cymru_dns(args.address)
    if args.json:
        emit_json(
            {
                "address": args.address,
                "ptr": rdns,
                "asn": asn,
                "bgp": bgp,
            }
        )
        return 0
    print_ip_intel(args.address, asn, bgp, rdns)
    return 0


def _cmd_ping(args: argparse.Namespace) -> int:
    stats = run_ping(args.target, count=args.count, interval_sec=args.interval)
    if args.json:
        emit_json(stats)
        return 0 if stats.received > 0 else 1
    print_latency_stats(stats, show_samples=args.stats)
    return 0 if stats.received > 0 else 1


def _cmd_latency(args: argparse.Namespace) -> int:
    stats = run_tcp_latency(
        args.host,
        args.port,
        count=args.count,
        interval_sec=args.interval,
        timeout=args.timeout,
    )
    if args.json:
        emit_json(stats)
        return 0 if stats.received > 0 else 1
    print_latency_stats(stats, show_samples=args.stats)
    return 0 if stats.received > 0 else 1


def _cmd_dns(args: argparse.Namespace) -> int:
    try:
        answers = resolve_dns(args.name, args.type)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not answers:
        if args.json:
            emit_json({"name": args.name, "type": args.type, "records": []})
        else:
            print(f"No {args.type} records for {args.name}")
        return 1
    if args.json:
        emit_json({"name": args.name, "type": args.type, "records": answers})
        return 0
    for ans in answers:
        print(ans)
    return 0


def _cmd_port(args: argparse.Namespace) -> int:
    ok, ms, err = tcp_probe(args.host, args.port, timeout=args.timeout)
    payload = {
        "host": args.host,
        "port": args.port,
        "open": ok,
        "latency_ms": ms,
        "error": err,
    }
    if args.json:
        emit_json(payload)
        return 0 if ok else 1
    if ok:
        print(f"{args.host}:{args.port} open ({ms:.1f} ms)")
        return 0
    print(f"{args.host}:{args.port} closed/filtered: {err}", file=sys.stderr)
    return 1


def _cmd_ports(args: argparse.Namespace) -> int:
    try:
        port_nums = resolve_port_list(
            ports_arg=args.port_list,
            common=args.common,
            range_spec=args.range,
        )
        results = scan_tcp_ports(
            args.host,
            port_nums,
            timeout=args.timeout,
            workers=args.workers,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    open_ports = [r for r in results if r.open]
    if args.json:
        emit_json(
            {
                "host": args.host,
                "scanned": len(port_nums),
                "open_count": len(open_ports),
                "results": results,
            }
        )
        return 0 if open_ports else 1

    print(f"TCP port scan: {args.host} ({len(port_nums)} ports)\n")

    if not open_ports and not args.all:
        print("No open ports found.")
        return 1

    for r in results:
        if r.open:
            ms = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
            print(f"  {r.port:5}  open   ({ms})")
        elif args.all:
            err = r.error or "closed"
            print(f"  {r.port:5}  closed ({err})")

    print(f"\nOpen: {len(open_ports)} / {len(results)}")
    return 0 if open_ports else 1


def _cmd_check(args: argparse.Namespace) -> int:
    if args.preset:
        try:
            preset_name = (
                _oncall_preset(args) if args.preset == "oncall" else get_preset(args.preset).name
            )
        except ValueError as exc:
            if args.json:
                emit_json({"error": str(exc), "target": args.target})
            else:
                print(f"Error: {exc}", file=sys.stderr)
            return EX_ERROR
        oc = run_preset_check(
            args.target,
            preset_name,
            url=args.url,
            corp_host=_corp_host(args),
        )
        if args.json:
            emit_json(
                {
                    "target": oc.target,
                    "preset": oc.preset,
                    "ok": oc.ok,
                    "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail} for s in oc.steps],
                }
            )
            return 0 if oc.ok else 1
        print_oncall_report(oc)
        return 0 if oc.ok else 1

    report = run_health_check(
        args.target,
        dns_type=args.dns_type,
        ping_count=args.count,
        port=args.port,
        url=args.url,
    )
    if args.json:
        emit_json(health_report_dict(report))
        return 0 if report.ok else 1
    print_health_report(report)
    return 0 if report.ok else 1


def _cmd_http(args: argparse.Namespace) -> int:
    if args.timing:
        result = http_timing(args.url, method=args.method, timeout=args.timeout)
        if args.json:
            emit_json(result)
            return 0 if result.ok else 1
        print_http_timing(result)
        return 0 if result.ok else 1
    result = http_probe(args.url, method=args.method, timeout=args.timeout)
    if args.json:
        emit_json(result)
        return 0 if result.ok else 1
    print_http_result(result)
    return 0 if result.ok else 1


def _cmd_tls(args: argparse.Namespace) -> int:
    try:
        host, port = parse_host_port(args.host, args.port)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EX_ERROR
    info = tls_inspect(host, port=port, timeout=args.timeout, sni=args.sni)
    if args.json:
        emit_json(info)
        return EX_OK if not info.error else EX_FAIL
    print_tls_info(info)
    return EX_OK if not info.error else EX_FAIL


def _cmd_ptr(args: argparse.Namespace) -> int:
    hostname, err = reverse_dns(args.address, timeout=args.timeout)
    if hostname:
        print(hostname)
        return 0
    print(f"error: {err or 'no PTR record'}", file=sys.stderr)
    return 1


def _cmd_subnet(args: argparse.Namespace) -> int:
    try:
        info = describe_subnet(args.cidr)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print_subnet(info)
    return 0


def _cmd_ip(args: argparse.Namespace) -> int:
    try:
        props = address_properties(args.address)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for key, val in props.items():
        print(f"{key:14} {val}")
    return 0


def _cmd_route(args: argparse.Namespace) -> int:
    routes = list_routes()
    if args.default_only:
        routes = [r for r in routes if r.destination in ("default", "0.0.0.0/0", "::/0")]
    if not routes:
        print("No routes found (or netstat/ip unavailable).", file=sys.stderr)
        return 1
    print(f"{'Destination':<20} {'Gateway':<18} {'Iface':<10} {'Flags'}")
    print("-" * 60)
    for r in routes:
        gw = r.gateway or "-"
        iface = r.interface or "-"
        flags = r.flags or "-"
        print(f"{r.destination:<20} {gw:<18} {iface:<10} {flags}")
    return 0


def _cmd_ifaces(args: argparse.Namespace) -> int:
    addrs = list_interfaces()
    if args.ipv4_only:
        addrs = [a for a in addrs if a.family == "IPv4"]
    elif args.ipv6_only:
        addrs = [a for a in addrs if a.family == "IPv6"]
    if not addrs:
        print("No interfaces found.", file=sys.stderr)
        return 1
    print(f"{'Interface':<12} {'Family':<6} {'Address':<40} {'Prefix'}")
    print("-" * 70)
    for a in addrs:
        prefix = str(a.prefixlen) if a.prefixlen is not None else "-"
        print(f"{a.name:<12} {a.family:<6} {a.address:<40} {prefix}")
    return 0


def _cmd_listen(args: argparse.Namespace) -> int:
    rows = listeners_on_port(args.port)
    if args.json:
        emit_json({"port": args.port, "listeners": rows})
        return 0 if rows else 1
    if not rows:
        print(f"No listeners on TCP port {args.port}")
        return 1
    for row in rows:
        pid = row.pid or "-"
        user = row.user or "-"
        print(f"{row.command}  pid={pid}  user={user}  {row.bind}")
    if rows and rows[0].command == "?" and not shutil.which("lsof"):
        print("\n(install lsof for process names; showing netstat bind lines only)", file=sys.stderr)
    return 0


def _cmd_dns_trace(args: argparse.Namespace) -> int:
    try:
        lines = dns_trace(args.name, args.type)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    hops = parse_trace_hops(lines)
    if args.json:
        emit_json({"name": args.name, "type": args.type, "hops": hops, "lines": lines})
        return 0
    print(f"DNS trace: {args.name} ({args.type})\n")
    for line in lines:
        print(line)
    if hops:
        print(f"\nDelegation steps: {len(hops)}")
    return 0


def _cmd_dns_compare(args: argparse.Namespace) -> int:
    try:
        results = dns_compare(args.name, args.type)
        corp_results = dns_compare(args.corp, args.type) if args.corp else None
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        payload: dict[str, object] = {
            "name": args.name,
            "type": args.type,
            "resolvers": results,
        }
        if corp_results is not None:
            payload["corp"] = {"host": args.corp, "resolvers": corp_results}
        emit_json(payload)
        code = 0 if dns_compare_is_consistent(results) else 1
        if corp_results is not None and code == 0:
            code = 0 if dns_compare_is_consistent(corp_results) else 1
        return code
    print_dns_compare(results, args.name)
    if corp_results is not None:
        print_dns_compare(corp_results, args.corp)
    code = 0 if dns_compare_is_consistent(results) else 1
    if corp_results is not None and code == 0:
        code = 0 if dns_compare_is_consistent(corp_results) else 1
    return code


def _cmd_local_ports(args: argparse.Namespace) -> int:
    rows = list_all_listeners()
    if args.json:
        emit_json({"listeners": rows})
        return 0 if rows else 1
    if not rows:
        print("No listening TCP ports found.", file=sys.stderr)
        return 1
    print(f"{'Command':<14} {'PID':<8} {'User':<12} {'Bind'}")
    print("-" * 60)
    for row in rows:
        print(
            f"{row.command:<14} {(row.pid or '-'):<8} {(row.user or '-'):<12} {row.bind}"
        )
    print(f"\nTotal: {len(rows)} listeners")
    if rows and rows[0].command == "?" and not shutil.which("lsof"):
        print("(install lsof for process names; showing netstat bind lines only)", file=sys.stderr)
    return 0


def _cmd_connections(args: argparse.Namespace) -> int:
    rows = list_connections()[: args.limit]
    if args.json:
        emit_json({"connections": rows, "shown": len(rows)})
        return 0 if rows else 1
    if not rows:
        print("No established connections found.", file=sys.stderr)
        return 1
    print(f"{'Proto':<6} {'Local':<24} {'Remote':<24} {'State':<12} {'Process'}")
    print("-" * 90)
    for row in rows:
        proc = "-"
        if row.command:
            proc = row.command
            if row.pid:
                proc = f"{row.command} [{row.pid}]"
        print(
            f"{row.proto:<6} {row.local:<24} {row.remote:<24} {row.state:<12} {proc}"
        )
    if rows and not rows[0].command and not shutil.which("lsof"):
        print("\n(install lsof for process names)", file=sys.stderr)
    if len(rows) == args.limit:
        print(f"\n(showing first {args.limit}; use --limit to change)")
    return 0


def _cmd_speed(args: argparse.Namespace) -> int:
    if args.url:
        result = speed_download(args.url, timeout=args.timeout)
        if args.json:
            emit_json(result)
            return 0 if not result.error else 1
        print_speed_result(result)
        return 0 if not result.error else 1
    if args.iperf:
        result = speed_iperf(
            args.iperf,
            port=args.port,
            duration_sec=args.time,
            timeout=args.timeout,
        )
        if args.json:
            emit_json(result)
            return 0 if not result.error else 1
        print_speed_result(result)
        return 0 if not result.error else 1
    try:
        report = run_speed_test(
            args.target,
            upload=args.upload,
            parallel=1 if args.single_stream else args.parallel,
            download_bytes=args.bytes,
            upload_bytes=args.upload_bytes,
            timeout=args.timeout,
        )
    except ValueError as exc:
        if args.json:
            emit_json({"error": str(exc)})
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2
    failed = False
    if report.download and report.download.error:
        failed = True
    if report.upload and report.upload.error:
        failed = True
    if args.json:
        emit_json(report)
        return 0 if not failed else 1
    print_speed_test_report(report)
    return 0 if not failed else 1


def _vpn_section(args: argparse.Namespace):
    if not getattr(args, "vpn", False):
        return None
    return run_vpn_diagnostic(corp_host=_corp_host(args))


def _cmd_oncall(args: argparse.Namespace) -> int:
    vpn = _vpn_section(args)
    try:
        oc = run_preset_check(
            args.target,
            _oncall_preset(args),
            url=args.url,
            corp_host=_corp_host(args),
        )
    except ValueError as exc:
        if args.json:
            emit_json({"error": str(exc), "target": args.target})
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return EX_ERROR
    overall_ok = oc.ok and (vpn is None or all(s.ok for s in vpn.steps))
    if args.json:
        payload: dict = {
            "target": oc.target,
            "preset": oc.preset,
            "ok": overall_ok,
            "trace_hops": oc.trace_hops,
            "tls_days_remaining": oc.tls_days_remaining,
            "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail} for s in oc.steps],
        }
        if vpn is not None:
            payload["vpn"] = vpn
        emit_json(payload)
        return EX_OK if overall_ok else EX_FAIL
    print_oncall_report(oc, vpn=vpn)
    return EX_OK if overall_ok else EX_FAIL


def _cmd_vpn(args: argparse.Namespace) -> int:
    try:
        diag = run_vpn_diagnostic(corp_host=_corp_host(args), public_dns_name=args.dns_name)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        emit_json(diag)
        return 0 if all(s.ok for s in diag.steps) else 1
    print_vpn_diagnostic(diag)
    return 0 if all(s.ok for s in diag.steps) else 1


def _cmd_compare(args: argparse.Namespace) -> int:
    report = compare_hosts(args.left, args.right, ping_count=args.count)
    if args.json:
        emit_json(report)
        return 0
    print_compare_report(report)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    vpn = _vpn_section(args)
    oc = run_preset_check(
        args.target,
        _oncall_preset(args),
        url=args.url,
        corp_host=_corp_host(args),
    )
    text = format_oncall_report(oc, vpn=vpn)
    overall_ok = oc.ok and (vpn is None or all(s.ok for s in vpn.steps))
    if args.json:
        payload: dict = {
            "target": oc.target,
            "preset": oc.preset,
            "ok": overall_ok,
            "markdown": text,
            "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail} for s in oc.steps],
        }
        if vpn is not None:
            payload["vpn"] = vpn
        emit_json(payload)
        return 0 if overall_ok else 1
    if args.output:
        from pathlib import Path

        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text)
    return 0 if overall_ok else 1


def _cmd_presets(args: argparse.Namespace) -> int:
    rows = [
        {"name": p.name, "description": p.description, "ping_count": p.ping_count, "ports": list(p.ports)}
        for p in PRESETS.values()
    ]
    if args.json:
        emit_json({"presets": rows})
        return 0
    for p in PRESETS.values():
        ports = ",".join(str(x) for x in p.ports) or "-"
        print(f"{p.name:<8}  ports={ports:<12}  {p.description}")
    return 0


def _cmd_redirects(args: argparse.Namespace) -> int:
    chain = follow_redirects(args.url, max_hops=args.max, timeout=args.timeout)
    if args.json:
        emit_json(chain)
        return 0 if chain.error is None else 1
    print(f"Redirect chain from {chain.start_url}\n")
    for i, hop in enumerate(chain.hops, 1):
        loc = f" -> {hop.location}" if hop.location else ""
        print(f"  {i}. {hop.status}  {hop.url}{loc}")
    if chain.final_url:
        print(f"\nFinal: {chain.final_url}")
    if chain.error:
        print(f"Error: {chain.error}", file=sys.stderr)
        return 1
    return 0


def _cmd_headers(args: argparse.Namespace) -> int:
    report = check_security_headers(args.url, timeout=args.timeout)
    if args.json:
        emit_json(report)
        return 0 if report.error is None else 1
    print(f"Security headers: {report.url}\n")
    if report.status is not None:
        print(f"HTTP status: {report.status}\n")
    for h in report.headers:
        mark = "ok" if h.present else "MISSING"
        val = (h.value[:60] + "…") if h.value and len(h.value) > 60 else (h.value or "-")
        print(f"  [{mark:7}] {h.name}: {val}")
    if report.error:
        print(f"\nError: {report.error}", file=sys.stderr)
        return 1
    missing = [h.name for h in report.headers if not h.present]
    return 0 if not missing else 1


def _cmd_mtr(args: argparse.Namespace) -> int:
    report = run_mtr(args.target, count=args.count, timeout=args.timeout)
    if args.json:
        emit_json(report)
        return 0 if not report.error else 1
    print(f"MTR {args.target} (mode={report.mode})\n")
    if report.error:
        print(f"error: {report.error}", file=sys.stderr)
        return 1
    print(f"{'#':<4} {'Host':<22} {'Loss%':<8} {'Avg':<10} {'Best':<10} {'Worst'}")
    print("-" * 60)
    for h in report.hops:
        print(
            f"{h.hop:<4} {(h.host or '-'):<22} "
            f"{(f'{h.loss_pct:.1f}' if h.loss_pct is not None else '-'):<8} "
            f"{(f'{h.avg_ms:.1f}' if h.avg_ms is not None else '-'):<10} "
            f"{(f'{h.best_ms:.1f}' if h.best_ms is not None else '-'):<10} "
            f"{f'{h.worst_ms:.1f}' if h.worst_ms is not None else '-'}"
        )
    return 0


def _cmd_dns_all(args: argparse.Namespace) -> int:
    try:
        report = lookup_all_records(args.name)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        emit_json(report)
        return 0
    print(f"DNS records: {args.name}\n")
    for s in report.sets:
        print(f"  {s.record_type}:")
        if s.error:
            print(f"    error: {s.error}")
        elif s.records:
            for r in s.records:
                print(f"    {r}")
        else:
            print("    (none)")
    return 0


def _cmd_dns_config(args: argparse.Namespace) -> int:
    entries = read_dns_config()
    if args.json:
        emit_json({"resolvers": entries})
        return 0 if entries else 1
    if not entries:
        print("No DNS configuration found.", file=sys.stderr)
        return 1
    for entry in entries:
        print(f"[{entry.source}]")
        if entry.nameservers:
            print(f"  nameservers: {', '.join(entry.nameservers)}")
        if entry.search_domains:
            print(f"  search:      {', '.join(entry.search_domains)}")
        for note in entry.notes:
            print(f"  note:        {note}")
        print()
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = run_doctor()
    if args.json:
        emit_json(
            {
                "platform": report.platform,
                "ok": report.ok_for_runbooks,
                "config_path": str(CONFIG_PATH),
                "tools": [
                    {
                        "binary": t.requirement.binary,
                        "label": t.requirement.label,
                        "category": t.requirement.category,
                        "found": t.found,
                        "path": t.path,
                        "commands": list(t.requirement.commands),
                        "install_hint": t.requirement.install_hint,
                    }
                    for t in report.tools
                ],
            }
        )
        return EX_OK if report.ok_for_runbooks else EX_ERROR

    print(f"netdiag doctor ({report.platform})\n")
    if CONFIG_PATH.is_file():
        print(f"Config: {CONFIG_PATH}\n")
    for tool in report.tools:
        mark = "ok" if tool.found else "MISSING"
        path = tool.path or "-"
        print(f"  [{mark:7}] {tool.requirement.label:<12} {path}")
        print(f"           {tool.requirement.category:<12} used by: {', '.join(tool.requirement.commands)}")
        if not tool.found:
            print(f"           install: {tool.requirement.install_hint}")
    print()
    if report.ok_for_runbooks:
        print("Ready for runbooks (required tools present).")
        print("Primary workflow: netdiag oncall <HOST> --json")
        return EX_OK
    print("Not ready: install required tools before production runbooks.", file=sys.stderr)
    return EX_ERROR


def _cmd_completion(args: argparse.Namespace) -> int:
    if args.shell == "bash":
        print(bash_completion())
    else:
        print(zsh_completion())
    return EX_OK


def main(argv: list[str] | None = None) -> int:
    try:
        return _main_impl(argv)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EX_ERROR
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return EX_ERROR


def _main_impl(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.info:
        if args.json:
            from netdiag.info import info_dict

            emit_json(info_dict())
        else:
            print_info()
        return EX_OK
    if not args.command:
        print_banner(stream=sys.stderr)
        parser.print_help(sys.stderr)
        return EX_ERROR
    handlers = {
        "trace": _cmd_trace,
        "whois": _cmd_whois,
        "ping": _cmd_ping,
        "latency": _cmd_latency,
        "dns": _cmd_dns,
        "port": _cmd_port,
        "ports": _cmd_ports,
        "check": _cmd_check,
        "http": _cmd_http,
        "tls": _cmd_tls,
        "ptr": _cmd_ptr,
        "subnet": _cmd_subnet,
        "ip": _cmd_ip,
        "route": _cmd_route,
        "ifaces": _cmd_ifaces,
        "listen": _cmd_listen,
        "dns-trace": _cmd_dns_trace,
        "dns-compare": _cmd_dns_compare,
        "local-ports": _cmd_local_ports,
        "connections": _cmd_connections,
        "speed": _cmd_speed,
        "oncall": _cmd_oncall,
        "vpn": _cmd_vpn,
        "compare": _cmd_compare,
        "report": _cmd_report,
        "dns-config": _cmd_dns_config,
        "presets": _cmd_presets,
        "redirects": _cmd_redirects,
        "headers": _cmd_headers,
        "mtr": _cmd_mtr,
        "dns-all": _cmd_dns_all,
        "doctor": _cmd_doctor,
        "completion": _cmd_completion,
    }
    try:
        code = handlers[args.command](args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EX_ERROR
    if code not in (EX_OK, EX_FAIL, EX_ERROR):
        return EX_ERROR
    return code


if __name__ == "__main__":
    raise SystemExit(main())
