from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from netdiag.ssl_ctx import create_verified_context


@dataclass(frozen=True)
class SpeedEndpoint:
    provider: str
    connect_host: str
    tls_sni: str
    port: int = 443
    requested: str | None = None


@dataclass(frozen=True)
class SpeedProbeResult:
    mode: str
    target: str
    bytes_transferred: int
    elapsed_sec: float
    megabits_per_sec: float | None
    parallel: int
    error: str | None


@dataclass(frozen=True)
class SpeedResult:
    mode: str
    target: str
    bytes_downloaded: int
    elapsed_sec: float
    megabits_per_sec: float | None
    error: str | None
    upload_mbps: float | None = None
    provider: str | None = None
    parallel: int = 1


@dataclass(frozen=True)
class SpeedTestReport:
    provider: str
    endpoint: SpeedEndpoint
    download: SpeedProbeResult | None
    upload: SpeedProbeResult | None


# Cloudflare speed test (same CDN approach as fast.com-style consumer tests)
_CLOUDFLARE = SpeedEndpoint("cloudflare", "speed.cloudflare.com", "speed.cloudflare.com")

# Cloudflare public DNS - not the speed CDN; map to speed.cloudflare.com edge IPs
_CLOUDFLARE_DNS_RESOLVER_IPS: frozenset[str] = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::111",
        "2606:4700:4700::1001",
    }
)

_PROVIDER_BY_NAME: dict[str, SpeedEndpoint] = {"cloudflare": _CLOUDFLARE}


def _cloudflare_speed_edge_ips() -> list[str]:
    infos = socket.getaddrinfo(
        _CLOUDFLARE.connect_host,
        443,
        type=socket.SOCK_STREAM,
    )
    seen: set[str] = set()
    ordered: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _pick_edge_ip(edges: list[str], *, prefer_ipv4: bool) -> str | None:
    if not edges:
        return None
    if prefer_ipv4:
        for ip in edges:
            if ":" not in ip:
                return ip
    for ip in edges:
        if ":" in ip:
            return ip
    return edges[0]


def _endpoint_target_label(endpoint: SpeedEndpoint) -> str:
    base = f"{endpoint.connect_host} ({endpoint.tls_sni})"
    if endpoint.requested and endpoint.requested != endpoint.connect_host:
        return (
            f"{base} - requested {endpoint.requested}; "
            "using speed.cloudflare.com CDN edge (1.1.1.1 is DNS-only)"
        )
    return base


def resolve_speed_endpoint(target: str | None) -> SpeedEndpoint:
    if target is None:
        return _CLOUDFLARE
    t = target.strip().lower()
    if t in _PROVIDER_BY_NAME:
        return _PROVIDER_BY_NAME[t]
    try:
        ip = str(ip_address(t))
    except ValueError:
        ip = None
    if ip:
        if ip in _CLOUDFLARE_DNS_RESOLVER_IPS:
            edges = _cloudflare_speed_edge_ips()
            edge = _pick_edge_ip(edges, prefer_ipv4=":" not in ip)
            if edge is None:
                raise ValueError("could not resolve speed.cloudflare.com edge addresses")
            return SpeedEndpoint(
                "cloudflare",
                edge,
                _CLOUDFLARE.tls_sni,
                requested=ip,
            )
        edges = _cloudflare_speed_edge_ips()
        if ip in edges:
            return SpeedEndpoint("cloudflare", ip, _CLOUDFLARE.tls_sni, requested=ip)
        raise ValueError(
            f"{target!r} has no built-in speed endpoint. "
            "Use `netdiag speed` (CDN), a speed.cloudflare.com edge IP, --url, or --iperf."
        )
    try:
        infos = socket.getaddrinfo(t, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {target!r}: {exc}") from exc
    edges = _cloudflare_speed_edge_ips()
    for info in infos:
        resolved = info[4][0]
        if resolved in edges:
            return SpeedEndpoint(
                "cloudflare",
                resolved,
                _CLOUDFLARE.tls_sni,
                requested=t,
            )
        if resolved in _CLOUDFLARE_DNS_RESOLVER_IPS:
            edge = _pick_edge_ip(edges, prefer_ipv4=info[0] == socket.AF_INET)
            if edge is None:
                raise ValueError("could not resolve speed.cloudflare.com edge addresses")
            return SpeedEndpoint(
                "cloudflare",
                edge,
                _CLOUDFLARE.tls_sni,
                requested=resolved,
            )
    raise ValueError(
        f"{target!r} has no built-in speed endpoint. "
        "Use `netdiag speed` (CDN), --url, or --iperf."
    )


def _mbps(byte_count: int, elapsed_sec: float) -> float | None:
    if elapsed_sec <= 0 or byte_count <= 0:
        return None
    return (byte_count * 8) / elapsed_sec / 1_000_000


def _http_body_from_response(method: str, data: bytes) -> tuple[int, str | None]:
    if b"\r\n\r\n" not in data:
        return 0, "incomplete HTTP response"
    header, body = data.split(b"\r\n\r\n", 1)
    status_line = header.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    parts = status_line.split()
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    if method == "GET" and code != 200:
        detail = body.decode("utf-8", errors="replace").strip() or status_line
        return 0, f"HTTP {code}: {detail}"
    if method == "POST" and code not in (200, 204):
        detail = body.decode("utf-8", errors="replace").strip() or status_line
        return 0, f"HTTP {code}: {detail}"
    return len(body), None


def _tls_http_request(
    endpoint: SpeedEndpoint,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    timeout: float = 30.0,
) -> tuple[int, float, str | None]:
    """Returns (payload_bytes, elapsed_seconds, error)."""
    ctx = create_verified_context()
    payload = b""
    if body:
        payload = body
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {endpoint.tls_sni}\r\n"
        f"User-Agent: netdiag/0.1\r\n"
        f"Connection: close\r\n"
    )
    if body:
        request += f"Content-Length: {len(body)}\r\n"
    request += "\r\n"
    request = request.encode("ascii") + payload

    start = time.monotonic()
    family = socket.AF_INET6 if ":" in endpoint.connect_host else socket.AF_INET
    with socket.create_connection((endpoint.connect_host, endpoint.port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=endpoint.tls_sni) as tls_sock:
            tls_sock.sendall(request)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = tls_sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
    elapsed = time.monotonic() - start
    data = b"".join(chunks)
    transferred, err = _http_body_from_response(method, data)
    return transferred, elapsed, err


def speed_download_endpoint(
    endpoint: SpeedEndpoint,
    *,
    bytes_count: int = 10_000_000,
    timeout: float = 30.0,
) -> SpeedProbeResult:
    path = f"/__down?{urlencode({'bytes': bytes_count})}"
    target = _endpoint_target_label(endpoint)
    try:
        transferred, elapsed, http_err = _tls_http_request(
            endpoint, "GET", path, timeout=timeout
        )
        err = http_err
        if err is None and transferred <= 0:
            err = "no data received"
        return SpeedProbeResult(
            mode="download",
            target=target,
            bytes_transferred=transferred,
            elapsed_sec=elapsed,
            megabits_per_sec=_mbps(transferred, elapsed) if err is None else None,
            parallel=1,
            error=err,
        )
    except OSError as exc:
        return SpeedProbeResult(
            mode="download",
            target=target,
            bytes_transferred=0,
            elapsed_sec=0.0,
            megabits_per_sec=None,
            parallel=1,
            error=str(exc),
        )


def _parallel_download_worker(
    endpoint: SpeedEndpoint,
    bytes_count: int,
    timeout: float,
) -> tuple[int, float, str | None]:
    result = speed_download_endpoint(endpoint, bytes_count=bytes_count, timeout=timeout)
    if result.error:
        return 0, 0.0, result.error
    return result.bytes_transferred, result.elapsed_sec, None


def speed_download_parallel(
    endpoint: SpeedEndpoint,
    *,
    total_bytes: int = 25_000_000,
    parallel: int = 4,
    timeout: float = 45.0,
) -> SpeedProbeResult:
    parallel = max(1, min(parallel, 8))
    per_stream = max(total_bytes // parallel, 1_000_000)
    target = _endpoint_target_label(endpoint)
    errors: list[str] = []
    total_transferred = 0
    wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = [
            pool.submit(_parallel_download_worker, endpoint, per_stream, timeout)
            for _ in range(parallel)
        ]
        for fut in as_completed(futures):
            n, _elapsed, err = fut.result()
            total_transferred += n
            if err:
                errors.append(err)
    wall_elapsed = time.monotonic() - wall_start
    err_msg = errors[0] if errors and total_transferred == 0 else None
    return SpeedProbeResult(
        mode="download",
        target=target,
        bytes_transferred=total_transferred,
        elapsed_sec=wall_elapsed,
        megabits_per_sec=_mbps(total_transferred, wall_elapsed),
        parallel=parallel,
        error=err_msg,
    )


def speed_upload_endpoint(
    endpoint: SpeedEndpoint,
    *,
    bytes_count: int = 2_000_000,
    timeout: float = 30.0,
) -> SpeedProbeResult:
    path = "/__up"
    target = _endpoint_target_label(endpoint)
    body = os.urandom(bytes_count)
    try:
        _received, elapsed, http_err = _tls_http_request(
            endpoint, "POST", path, body=body, timeout=timeout
        )
        sent = bytes_count
        return SpeedProbeResult(
            mode="upload",
            target=target,
            bytes_transferred=sent,
            elapsed_sec=elapsed,
            megabits_per_sec=_mbps(sent, elapsed) if http_err is None else None,
            parallel=1,
            error=http_err,
        )
    except OSError as exc:
        return SpeedProbeResult(
            mode="upload",
            target=target,
            bytes_transferred=0,
            elapsed_sec=0.0,
            megabits_per_sec=None,
            parallel=1,
            error=str(exc),
        )


def run_speed_test(
    target: str | None = None,
    *,
    upload: bool = False,
    parallel: int = 4,
    download_bytes: int = 20_000_000,
    upload_bytes: int = 2_000_000,
    timeout: float = 60.0,
) -> SpeedTestReport:
    endpoint = resolve_speed_endpoint(target)
    if parallel > 1:
        dl = speed_download_parallel(
            endpoint,
            total_bytes=download_bytes,
            parallel=parallel,
            timeout=timeout,
        )
    else:
        dl = speed_download_endpoint(endpoint, bytes_count=download_bytes, timeout=timeout)
    up = None
    if upload:
        up = speed_upload_endpoint(endpoint, bytes_count=upload_bytes, timeout=timeout)
    return SpeedTestReport(provider=endpoint.provider, endpoint=endpoint, download=dl, upload=up)


def speed_download(url: str, *, timeout: float = 30.0, max_bytes: int = 50_000_000) -> SpeedResult:
    req = Request(url, headers={"User-Agent": "netdiag/0.1"})
    start = time.monotonic()
    downloaded = 0
    try:
        with urlopen(req, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded >= max_bytes:
                    break
        elapsed = time.monotonic() - start
        mbps = _mbps(downloaded, elapsed)
        return SpeedResult(
            mode="download",
            target=url,
            bytes_downloaded=downloaded,
            elapsed_sec=elapsed,
            megabits_per_sec=mbps,
            error=None if mbps else "no data received",
        )
    except OSError as exc:
        elapsed = time.monotonic() - start
        return SpeedResult(
            mode="download",
            target=url,
            bytes_downloaded=downloaded,
            elapsed_sec=elapsed,
            megabits_per_sec=None,
            error=str(exc),
        )


def speed_iperf(
    host: str,
    *,
    port: int = 5201,
    duration_sec: int = 5,
    timeout: float = 30.0,
) -> SpeedResult:
    if not shutil.which("iperf3"):
        return SpeedResult(
            mode="iperf3",
            target=host,
            bytes_downloaded=0,
            elapsed_sec=0.0,
            megabits_per_sec=None,
            error="iperf3 not found on PATH",
        )
    cmd = [
        "iperf3",
        "-c",
        host,
        "-p",
        str(port),
        "-t",
        str(duration_sec),
        "-J",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        return SpeedResult(
            mode="iperf3",
            target=host,
            bytes_downloaded=0,
            elapsed_sec=float(duration_sec),
            megabits_per_sec=None,
            error=err,
        )
    try:
        data = json.loads(proc.stdout)
        end = data.get("end", {})
        sum_sent = end.get("sum_sent", {}) or end.get("sum_received", {})
        bps = sum_sent.get("bits_per_second")
        seconds = float(data.get("start", {}).get("test_start", {}).get("duration", duration_sec))
        if bps is None:
            return SpeedResult(
                mode="iperf3",
                target=host,
                bytes_downloaded=0,
                elapsed_sec=seconds,
                megabits_per_sec=None,
                error="could not parse iperf3 JSON output",
            )
        return SpeedResult(
            mode="iperf3",
            target=host,
            bytes_downloaded=0,
            elapsed_sec=seconds,
            megabits_per_sec=bps / 1_000_000,
            error=None,
        )
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        return SpeedResult(
            mode="iperf3",
            target=host,
            bytes_downloaded=0,
            elapsed_sec=float(duration_sec),
            megabits_per_sec=None,
            error=str(exc),
        )
