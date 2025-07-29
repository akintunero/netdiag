from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_network

from netdiag.dns_config import DnsResolverInfo, read_dns_config
from netdiag.dns_tools import DnsCompareResult, dns_compare
from netdiag.health_check import CheckStep
from netdiag.host_info import InterfaceAddr, RouteEntry, list_interfaces, list_routes
from netdiag.stats import format_ms
from netdiag.tools import run_ping, tcp_probe

VPN_IFACE_RE = re.compile(r"^(utun\d+|tun\d+|wg\d+|ppp\d+|ipsec\d+|nordlynx|tailscale)", re.I)

def _is_private_route_destination(dest: str) -> bool:
    try:
        return ip_network(dest, strict=False).is_private
    except ValueError:
        return dest.startswith(("10.", "192.168.", "172."))



@dataclass(frozen=True)
class VpnInterface:
    name: str
    addresses: tuple[str, ...]
    state: str | None


@dataclass(frozen=True)
class VpnDiagnostic:
    vpn_interfaces: tuple[VpnInterface, ...]
    default_routes: tuple[RouteEntry, ...]
    tunnel_routes: tuple[RouteEntry, ...]
    dns_resolvers: tuple[DnsResolverInfo, ...]
    dns_compare_public: tuple[DnsCompareResult, ...]
    dns_compare_corp: tuple[DnsCompareResult, ...] | None
    steps: tuple[CheckStep, ...]
    split_tunnel_hint: str | None


def _vpn_interfaces() -> list[VpnInterface]:
    by_name: dict[str, list[str]] = {}
    state: dict[str, str | None] = {}
    for addr in list_interfaces():
        if VPN_IFACE_RE.match(addr.name):
            by_name.setdefault(addr.name, []).append(f"{addr.address}/{addr.prefixlen or '?'}")
            state[addr.name] = addr.state
    return [
        VpnInterface(name=n, addresses=tuple(addrs), state=state.get(n))
        for n, addrs in sorted(by_name.items())
    ]


def _classify_routes(routes: list[RouteEntry]) -> tuple[list[RouteEntry], list[RouteEntry], list[RouteEntry]]:
    defaults: list[RouteEntry] = []
    tunnel: list[RouteEntry] = []
    for r in routes:
        if r.destination in ("default", "0.0.0.0/0", "::/0", "0.0.0.0", "::"):
            defaults.append(r)
        elif r.interface and VPN_IFACE_RE.match(r.interface):
            tunnel.append(r)
        elif _is_private_route_destination(r.destination):
            tunnel.append(r)
    return defaults, tunnel, routes


def run_vpn_diagnostic(
    *,
    corp_host: str | None = None,
    public_dns_name: str = "google.com",
) -> VpnDiagnostic:
    steps: list[CheckStep] = []
    vpn_ifaces = _vpn_interfaces()
    steps.append(
        CheckStep(
            name="VPN interfaces",
            ok=bool(vpn_ifaces),
            detail=", ".join(i.name for i in vpn_ifaces) if vpn_ifaces else "none detected (utun/tun/wg/ppp)",
        )
    )

    routes = list_routes()
    defaults, tunnel_routes, _ = _classify_routes(routes)
    steps.append(
        CheckStep(
            name="Default routes",
            ok=bool(defaults),
            detail="; ".join(
                f"{r.destination} via {r.gateway or '-'} dev {r.interface or '-'}" for r in defaults
            )
            or "none",
        )
    )

    split_hint: str | None = None
    if len(defaults) > 1:
        split_hint = "Multiple default routes - likely split tunnel or policy routing"
    elif vpn_ifaces and not tunnel_routes:
        split_hint = "VPN interface up but few RFC1918/tunnel routes - may be full tunnel or host-only routes"
    elif not vpn_ifaces:
        split_hint = "No VPN tunnel interface detected"

    resolvers = read_dns_config()
    all_ns = [ns for r in resolvers for ns in r.nameservers]
    steps.append(
        CheckStep(
            name="DNS resolvers",
            ok=bool(all_ns),
            detail=", ".join(all_ns[:6]) + (" …" if len(all_ns) > 6 else "") if all_ns else "none found",
        )
    )

    dns_public = dns_compare(public_dns_name, "A")
    public_sets = {tuple(r.records) for r in dns_public if r.records}
    dns_drift = len(public_sets) > 1
    steps.append(
        CheckStep(
            name=f"DNS compare ({public_dns_name})",
            ok=not dns_drift,
            detail="resolver mismatch" if dns_drift else "all resolvers agree",
        )
    )

    dns_corp: tuple[DnsCompareResult, ...] | None = None
    if corp_host:
        dns_corp = tuple(dns_compare(corp_host, "A"))
        corp_sets = {tuple(r.records) for r in dns_corp if r.records}
        if not corp_sets:
            corp_detail = "no records"
            corp_ok = False
        elif len(corp_sets) > 1:
            corp_detail = "resolver mismatch"
            corp_ok = False
        else:
            corp_detail = ", ".join(next(iter(corp_sets)))
            corp_ok = True
        steps.append(
            CheckStep(
                name=f"DNS compare ({corp_host})",
                ok=corp_ok,
                detail=corp_detail,
            )
        )

    for target in ("1.1.1.1", "8.8.8.8"):
        ping = run_ping(target, count=3)
        steps.append(
            CheckStep(
                name=f"Public {target}",
                ok=ping.received > 0,
                detail=f"{ping.received}/{ping.sent} ok, avg {format_ms(p.avg_ms)} ms",
            )
        )

    if corp_host:
        ok, ms, err = tcp_probe(corp_host, 443, timeout=5.0)
        steps.append(
            CheckStep(
                name="Corp HTTPS",
                ok=ok,
                detail=f"{corp_host}:443 open {ms:.0f}ms" if ok and ms else f"{corp_host}:443 {err or 'closed'}",
            )
        )
        corp_ping = run_ping(corp_host, count=3)
        steps.append(
            CheckStep(
                name="Corp ICMP",
                ok=corp_ping.received > 0,
                detail=f"{corp_ping.received}/{corp_ping.sent} replies (may be blocked by policy)",
            )
        )

    return VpnDiagnostic(
        vpn_interfaces=tuple(vpn_ifaces),
        default_routes=tuple(defaults),
        tunnel_routes=tuple(tunnel_routes),
        dns_resolvers=tuple(resolvers),
        dns_compare_public=tuple(dns_public),
        dns_compare_corp=tuple(dns_corp) if dns_corp else None,
        steps=tuple(steps),
        split_tunnel_hint=split_hint,
    )
