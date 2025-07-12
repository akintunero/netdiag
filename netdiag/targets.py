from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address


@dataclass(frozen=True)
class LiteralDnsStep:
    ok: bool
    detail: str
    resolved_ip: str | None = None


def parse_literal_ip(target: str) -> str | None:
    try:
        return str(ip_address(target.strip()))
    except ValueError:
        return None


def is_literal_ip(target: str) -> bool:
    return parse_literal_ip(target) is not None


def literal_dns_step(target: str, record_type: str) -> LiteralDnsStep | None:
    """When target is already an IP, forward DNS for that RR type is not applicable."""
    ip = parse_literal_ip(target)
    if ip is None:
        return None
    record_type = record_type.upper()
    if record_type == "A":
        if ":" in ip:
            return LiteralDnsStep(True, "N/A (target is IPv6)", None)
        return LiteralDnsStep(True, f"{ip} (literal IPv4)", ip)
    if record_type == "AAAA":
        if ":" not in ip:
            return LiteralDnsStep(True, "N/A (target is IPv4)", None)
        return LiteralDnsStep(True, f"{ip} (literal IPv6)", ip)
    return LiteralDnsStep(True, f"skipped for literal IP ({ip})", ip)


def should_skip_dns_compare(target: str) -> bool:
    return is_literal_ip(target)


def parse_probe_host(target: str) -> tuple[str, int | None]:
    """Host for TCP/TLS probes; supports bracketed IPv6 and host:port."""
    raw = target.strip().split("/")[0]
    if raw.startswith("[") and "]" in raw:
        host, _, rest = raw[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    ip = parse_literal_ip(raw)
    if ip is not None:
        return ip, None
    if raw.count(":") == 1:
        host, port_s = raw.rsplit(":", 1)
        if port_s.isdigit():
            return host, int(port_s)
    return raw.split(":")[0], None


def https_url_for_target(target: str) -> str:
    host, port = parse_probe_host(target)
    if port and port != 443:
        if ":" in host and not host.startswith("["):
            return f"https://[{host}]:{port}/"
        return f"https://{host}:{port}/"
    if ":" in host and not host.startswith("["):
        return f"https://[{host}]/"
    return f"https://{host}/"
