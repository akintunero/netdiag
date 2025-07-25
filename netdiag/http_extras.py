from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request

from netdiag.http_probe import _normalize_url
from netdiag.ssl_ctx import urlopen_verified

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass(frozen=True)
class RedirectHop:
    url: str
    status: int | None
    location: str | None


@dataclass(frozen=True)
class RedirectChain:
    start_url: str
    hops: tuple[RedirectHop, ...]
    final_url: str | None
    error: str | None


@dataclass(frozen=True)
class HeaderCheck:
    name: str
    present: bool
    value: str | None


@dataclass(frozen=True)
class SecurityHeadersReport:
    url: str
    status: int | None
    headers: tuple[HeaderCheck, ...]
    error: str | None


def follow_redirects(url: str, *, max_hops: int = 10, timeout: float = 10.0) -> RedirectChain:
    url = _normalize_url(url)
    hops: list[RedirectHop] = []
    current = url
    try:
        for _ in range(max_hops):
            req = Request(current, method="HEAD", headers={"User-Agent": "netdiag/0.1"})
            try:
                with urlopen_verified(req, timeout=timeout) as resp:
                    status = resp.status
                    location = resp.headers.get("Location")
                    hops.append(RedirectHop(url=current, status=status, location=location))
                    if status in (301, 302, 303, 307, 308) and location:
                        current = urljoin(current, location)
                        continue
                    return RedirectChain(start_url=url, hops=tuple(hops), final_url=resp.geturl(), error=None)
            except HTTPError as exc:
                location = exc.headers.get("Location") if exc.headers else None
                hops.append(RedirectHop(url=current, status=exc.code, location=location))
                if exc.code in (301, 302, 303, 307, 308) and location:
                    current = location
                    continue
                return RedirectChain(start_url=url, hops=tuple(hops), final_url=exc.url, error=str(exc.reason))
        return RedirectChain(
            start_url=url,
            hops=tuple(hops),
            final_url=current,
            error=f"exceeded {max_hops} redirects",
        )
    except URLError as exc:
        return RedirectChain(start_url=url, hops=tuple(hops), final_url=None, error=str(exc.reason))


def check_security_headers(url: str, *, timeout: float = 10.0) -> SecurityHeadersReport:
    url = _normalize_url(url)
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "netdiag/0.1"})
        with urlopen_verified(req, timeout=timeout) as resp:
            raw = {k.lower(): v for k, v in resp.headers.items()}
            checks = tuple(
                HeaderCheck(
                    name=name,
                    present=name in raw,
                    value=raw.get(name),
                )
                for name in SECURITY_HEADERS
            )
            return SecurityHeadersReport(url=url, status=resp.status, headers=checks, error=None)
    except HTTPError as exc:
        raw = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        checks = tuple(
            HeaderCheck(name=name, present=name in raw, value=raw.get(name))
            for name in SECURITY_HEADERS
        )
        return SecurityHeadersReport(url=url, status=exc.code, headers=checks, error=str(exc.reason))
    except URLError as exc:
        return SecurityHeadersReport(url=url, status=None, headers=(), error=str(exc.reason))


@dataclass(frozen=True)
class MtrHop:
    hop: int
    host: str | None
    loss_pct: float | None
    avg_ms: float | None
    best_ms: float | None
    worst_ms: float | None


@dataclass(frozen=True)
class MtrReport:
    target: str
    mode: str
    hops: tuple[MtrHop, ...]
    error: str | None


def run_mtr(target: str, *, count: int = 10, timeout: float = 30.0) -> MtrReport:
    import platform
    import shutil
    import subprocess

    if shutil.which("mtr"):
        cmd = ["mtr", "-r", "-c", str(count), "-n", target]
        if platform.system().lower() == "darwin":
            cmd = ["mtr", "--report", "-c", str(count), "-n", target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return _parse_mtr_report(target, proc.stdout)
        err = proc.stderr.strip() or "mtr failed"
        return MtrReport(target=target, mode="mtr", hops=(), error=err)

    return _mtr_fallback_ping(target, count=count)


def _parse_mtr_report(target: str, text: str) -> MtrReport:
    hops: list[MtrHop] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Start:") or line.startswith("HOST:"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            hop_n = int(parts[0].rstrip("."))
        except ValueError:
            continue
        host = parts[1] if parts[1] != "???" else None
        try:
            loss = float(parts[2].replace("%", ""))
            avg = float(parts[5])
            best = float(parts[3])
            worst = float(parts[6])
        except (ValueError, IndexError):
            continue
        hops.append(MtrHop(hop=hop_n, host=host, loss_pct=loss, avg_ms=avg, best_ms=best, worst_ms=worst))
    return MtrReport(target=target, mode="mtr", hops=tuple(hops), error=None if hops else "no hops parsed")


def _mtr_fallback_ping(target: str, *, count: int) -> MtrReport:
    from netdiag.traceroute import run_traceroute

    try:
        trace_hops = run_traceroute(target, max_hops=20, probes=count)
    except (FileNotFoundError, RuntimeError) as exc:
        return MtrReport(target=target, mode="ping-snapshot", hops=(), error=str(exc))

    rows: list[MtrHop] = []
    for th in trace_hops:
        rtts = th.rtt_ms
        avg = sum(rtts) / len(rtts) if rtts else None
        loss = 100.0 * (1 - len(rtts) / count) if count else None
        rows.append(
            MtrHop(
                hop=th.index,
                host=th.address or th.hostname,
                loss_pct=loss,
                avg_ms=avg,
                best_ms=min(rtts) if rtts else None,
                worst_ms=max(rtts) if rtts else None,
            )
        )
    return MtrReport(target=target, mode="traceroute-snapshot", hops=tuple(rows), error=None)
