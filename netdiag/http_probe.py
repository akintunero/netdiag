from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address

from netdiag.ssl_ctx import create_verified_context, urlopen_verified
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request


@dataclass(frozen=True)
class HttpTimingResult:
    url: str
    host: str
    port: int
    method: str
    status: int | None
    ok: bool
    dns_ms: float | None
    connect_ms: float | None
    tls_ms: float | None
    request_ms: float | None
    total_ms: float
    error: str | None


@dataclass(frozen=True)
class HttpProbeResult:
    url: str
    method: str
    status: int | None
    ok: bool
    elapsed_ms: float
    final_url: str | None
    server: str | None
    content_type: str | None
    content_length: str | None
    error: str | None


@dataclass(frozen=True)
class TlsCertInfo:
    host: str
    port: int
    subject: str | None
    issuer: str | None
    sans: tuple[str, ...]
    not_before: datetime | None
    not_after: datetime | None
    days_remaining: int | None
    protocol: str | None
    cipher: tuple[str, str, int] | None
    error: str | None


def _normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = f"https://{url}"
    return url


def _http_path(parsed) -> str:
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def _tcp_connect_first(addrs: list[tuple], *, timeout: float) -> socket.socket:
    """Connect using getaddrinfo() result; IPv6 sockaddrs are 4-tuples."""
    family, socktype, _proto, _canon, sockaddr = addrs[0]
    if len(sockaddr) == 2:
        return socket.create_connection(sockaddr, timeout=timeout)
    sock = socket.socket(family, socktype)
    sock.settimeout(timeout)
    sock.connect(sockaddr)
    return sock


def http_timing(
    url: str,
    *,
    method: str = "HEAD",
    timeout: float = 10.0,
) -> HttpTimingResult:
    url = _normalize_url(url)
    method = method.upper()
    if method not in ("HEAD", "GET"):
        method = "HEAD"

    parsed = urlparse(url)
    host = parsed.hostname or ""
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = _http_path(parsed)

    dns_ms = connect_ms = tls_ms = request_ms = None
    total_start = time.monotonic()

    try:
        t_dns = time.monotonic()
        addrs = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        dns_ms = (time.monotonic() - t_dns) * 1000
        if not addrs:
            raise OSError(f"no addresses for {host!r}")

        sock: socket.socket | None = None
        try:
            t_connect = time.monotonic()
            raw = _tcp_connect_first(addrs, timeout=timeout)
            connect_ms = (time.monotonic() - t_connect) * 1000

            sock = raw
            if use_tls:
                t_tls = time.monotonic()
                ctx = create_verified_context()
                sock = ctx.wrap_socket(raw, server_hostname=host)
                tls_ms = (time.monotonic() - t_tls) * 1000

            payload = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            t_req = time.monotonic()
            sock.sendall(payload.encode("ascii"))
            response = sock.recv(4096)
            request_ms = (time.monotonic() - t_req) * 1000
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        status = None
        if response:
            first = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            parts = first.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])

        total_ms = (time.monotonic() - total_start) * 1000
        ok = status is not None and 200 <= status < 400
        return HttpTimingResult(
            url=url,
            host=host,
            port=port,
            method=method,
            status=status,
            ok=ok,
            dns_ms=dns_ms,
            connect_ms=connect_ms,
            tls_ms=tls_ms,
            request_ms=request_ms,
            total_ms=total_ms,
            error=None,
        )
    except OSError as exc:
        total_ms = (time.monotonic() - total_start) * 1000
        return HttpTimingResult(
            url=url,
            host=host,
            port=port,
            method=method,
            status=None,
            ok=False,
            dns_ms=dns_ms,
            connect_ms=connect_ms,
            tls_ms=tls_ms,
            request_ms=request_ms,
            total_ms=total_ms,
            error=str(exc),
        )


def http_probe(
    url: str,
    *,
    method: str = "HEAD",
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> HttpProbeResult:
    url = _normalize_url(url)
    method = method.upper()
    if method not in ("HEAD", "GET"):
        method = "HEAD"

    req = Request(url, method=method, headers={"User-Agent": "netdiag/0.1"})
    start = time.monotonic()
    try:
        with urlopen_verified(req, timeout=timeout) as resp:
            elapsed = (time.monotonic() - start) * 1000
            headers = resp.headers
            return HttpProbeResult(
                url=url,
                method=method,
                status=resp.status,
                ok=200 <= resp.status < 400,
                elapsed_ms=elapsed,
                final_url=resp.geturl(),
                server=headers.get("Server"),
                content_type=headers.get("Content-Type"),
                content_length=headers.get("Content-Length"),
                error=None,
            )
    except HTTPError as exc:
        elapsed = (time.monotonic() - start) * 1000
        headers = exc.headers
        return HttpProbeResult(
            url=url,
            method=method,
            status=exc.code,
            ok=False,
            elapsed_ms=elapsed,
            final_url=exc.url,
            server=headers.get("Server") if headers else None,
            content_type=headers.get("Content-Type") if headers else None,
            content_length=headers.get("Content-Length") if headers else None,
            error=str(exc.reason),
        )
    except URLError as exc:
        elapsed = (time.monotonic() - start) * 1000
        return HttpProbeResult(
            url=url,
            method=method,
            status=None,
            ok=False,
            elapsed_ms=elapsed,
            final_url=None,
            server=None,
            content_type=None,
            content_length=None,
            error=str(exc.reason),
        )


def _cert_datetime(value: str | tuple[str, ...]) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _dn_tuple(name: tuple[tuple[tuple[str, str], ...], ...] | None) -> str | None:
    """Format ssl.getpeercert() subject/issuer (nested RDN sequences)."""
    if not name:
        return None
    parts: list[str] = []
    try:
        for rdn in name:
            for key, val in rdn:
                if key in ("commonName", "organizationName", "countryName"):
                    parts.append(f"{key}={val}")
    except (ValueError, TypeError):
        return None
    return ", ".join(parts) if parts else None


def tls_inspect(host: str, port: int = 443, timeout: float = 5.0, sni: str | None = None) -> TlsCertInfo:
    server_name = sni or host
    ctx = create_verified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                sans: list[str] = []
                for typ, val in cert.get("subjectAltName", ()):
                    if typ == "DNS":
                        sans.append(val)
                not_after = _cert_datetime(cert.get("notAfter", ""))
                days = None
                if not_after:
                    days = (not_after - datetime.now(timezone.utc)).days
                return TlsCertInfo(
                    host=host,
                    port=port,
                    subject=_dn_tuple(cert.get("subject")),
                    issuer=_dn_tuple(cert.get("issuer")),
                    sans=tuple(sans),
                    not_before=_cert_datetime(cert.get("notBefore", "")),
                    not_after=not_after,
                    days_remaining=days,
                    protocol=protocol,
                    cipher=cipher,
                    error=None,
                )
    except OSError as exc:
        return TlsCertInfo(
            host=host,
            port=port,
            subject=None,
            issuer=None,
            sans=(),
            not_before=None,
            not_after=None,
            days_remaining=None,
            protocol=None,
            cipher=None,
            error=str(exc),
        )


def parse_host_port(target: str, default_port: int) -> tuple[str, int]:
    target = target.strip()
    try:
        return str(ip_address(target)), default_port
    except ValueError:
        pass
    if target.startswith("[") and "]" in target:
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if ":" in target and target.count(":") == 1:
        host, port_s = target.rsplit(":", 1)
        if port_s.isdigit():
            return host, int(port_s)
    parsed = urlparse(target if "://" in target else f"//{target}")
    if parsed.hostname:
        return parsed.hostname, parsed.port or default_port
    return target, default_port
