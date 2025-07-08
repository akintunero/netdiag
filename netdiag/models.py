from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address


@dataclass(frozen=True)
class Hop:
    index: int
    hostname: str | None
    address: str | None
    rtt_ms: list[float] = field(default_factory=list)

    @property
    def timed_out(self) -> bool:
        return self.address is None


@dataclass(frozen=True)
class AsnRecord:
    asn: int | None
    prefix: str | None
    country: str | None
    registry: str | None
    allocated: str | None
    name: str | None


@dataclass(frozen=True)
class BgpRecord:
    asn: int | None
    prefix: str | None
    name: str | None
    country: str | None
    rir: str | None
    description: str | None


@dataclass(frozen=True)
class EnrichedHop:
    hop: Hop
    asn: AsnRecord | None
    bgp: BgpRecord | None
    reverse_dns: str | None


def is_public_ip(addr: str) -> bool:
    try:
        if ":" in addr:
            ip = IPv6Address(addr)
        else:
            ip = IPv4Address(addr)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
