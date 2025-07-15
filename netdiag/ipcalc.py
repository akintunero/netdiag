from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network


@dataclass(frozen=True)
class SubnetInfo:
    cidr: str
    version: int
    network: str
    broadcast: str | None
    netmask: str
    hostmask: str | None
    first_host: str | None
    last_host: str | None
    num_addresses: int
    num_hosts: int | None
    is_private: bool
    is_global: bool


def describe_subnet(cidr: str) -> SubnetInfo:
    network = ip_network(cidr.strip(), strict=False)
    version = network.version
    broadcast = str(network.broadcast_address) if version == 4 else None
    hostmask = None
    if version == 4 and network.prefixlen < 32:
        hostmask = str(IPv4Address(int(network.hostmask)))

    first_host: str | None = None
    last_host: str | None = None
    num_hosts: int | None = None
    if network.num_addresses > 2 and version == 4:
        first_host = str(network.network_address + 1)
        last_host = str(network.broadcast_address - 1)
        num_hosts = network.num_addresses - 2
    elif network.num_addresses > 1 and version == 6:
        first_host = str(network.network_address + 1)
        last_host = str(network.broadcast_address)
        num_hosts = network.num_addresses - 2

    return SubnetInfo(
        cidr=str(network),
        version=version,
        network=str(network.network_address),
        broadcast=broadcast,
        netmask=str(network.netmask),
        hostmask=hostmask,
        first_host=first_host,
        last_host=last_host,
        num_addresses=network.num_addresses,
        num_hosts=num_hosts,
        is_private=network.is_private,
        is_global=network.is_global,
    )


def reverse_dns(addr: str, timeout: float = 5.0) -> tuple[str | None, str | None]:
    try:
        ip_address(addr)
    except ValueError as exc:
        return None, str(exc)

    import socket

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(addr)
        return host, None
    except socket.herror as exc:
        return None, str(exc)
    except OSError as exc:
        return None, str(exc)
    finally:
        socket.setdefaulttimeout(old_timeout)


def address_properties(addr: str) -> dict[str, str | bool | int]:
    ip = ip_address(addr.strip())
    props: dict[str, str | bool | int] = {
        "address": str(ip),
        "version": ip.version,
        "is_private": ip.is_private,
        "is_global": ip.is_global,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
    }
    if isinstance(ip, IPv4Address):
        props["reverse_bits"] = int(ip)
    elif isinstance(ip, IPv6Address):
        props["scope_id"] = ip.scope_id or "-"
    return props
