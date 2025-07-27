from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckPreset:
    name: str
    description: str
    ping_count: int
    dns_types: tuple[str, ...]
    ports: tuple[int, ...]
    trace_max_hops: int | None
    tls_check: bool
    http_timing: bool
    dns_compare: bool
    public_ping_targets: tuple[str, ...]
    redirect_check: bool
    headers_check: bool
    dns_all: bool


PRESETS: dict[str, CheckPreset] = {
    "web": CheckPreset(
        name="web",
        description="Public web service: DNS, HTTP/HTTPS ports, TLS, HTTP timing",
        ping_count=5,
        dns_types=("A", "AAAA"),
        ports=(80, 443),
        trace_max_hops=None,
        tls_check=True,
        http_timing=True,
        dns_compare=False,
        public_ping_targets=(),
        redirect_check=True,
        headers_check=True,
        dns_all=False,
    ),
    "api": CheckPreset(
        name="api",
        description="API endpoint: DNS, 443, TLS expiry, short path trace",
        ping_count=5,
        dns_types=("A",),
        ports=(443,),
        trace_max_hops=12,
        tls_check=True,
        http_timing=True,
        dns_compare=False,
        public_ping_targets=(),
        redirect_check=False,
        headers_check=False,
        dns_all=False,
    ),
    "vpn": CheckPreset(
        name="vpn",
        description="VPN path: resolver drift, tunnel iface, corp + public reachability",
        ping_count=4,
        dns_types=("A",),
        ports=(443,),
        trace_max_hops=8,
        tls_check=False,
        http_timing=False,
        dns_compare=True,
        public_ping_targets=("1.1.1.1", "8.8.8.8"),
        redirect_check=False,
        headers_check=False,
        dns_all=False,
    ),
    "oncall": CheckPreset(
        name="oncall",
        description="SRE on-call bundle: DNS, ping, ports, TLS, HTTP timing, trace, DNS compare",
        ping_count=10,
        dns_types=("A", "AAAA"),
        ports=(443, 80),
        trace_max_hops=18,
        tls_check=True,
        http_timing=True,
        dns_compare=True,
        public_ping_targets=("1.1.1.1",),
        redirect_check=True,
        headers_check=True,
        dns_all=True,
    ),
}


def get_preset(name: str) -> CheckPreset:
    key = name.lower()
    if key not in PRESETS:
        valid = ", ".join(sorted(PRESETS))
        raise ValueError(f"unknown preset {name!r}; choose: {valid}")
    return PRESETS[key]
