from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("system", ""),
    ("cloudflare", "1.1.1.1"),
    ("google", "8.8.8.8"),
)


@dataclass(frozen=True)
class DnsCompareResult:
    resolver: str
    server: str | None
    records: tuple[str, ...]
    error: str | None


def _require_dig() -> str:
    path = shutil.which("dig")
    if not path:
        raise RuntimeError("`dig` is required on PATH for this command.")
    return path


def dns_trace(name: str, record_type: str = "A") -> list[str]:
    _require_dig()
    proc = subprocess.run(
        ["dig", "+trace", "+nodnssec", name, record_type.upper()],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    lines: list[str] = []
    for line in (proc.stdout + proc.stderr).splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        lines.append(line)
    return lines


def dns_compare(
    name: str,
    record_type: str = "A",
    *,
    resolvers: tuple[tuple[str, str], ...] | None = None,
) -> list[DnsCompareResult]:
    _require_dig()
    record_type = record_type.upper()
    targets = resolvers or DEFAULT_RESOLVERS
    results: list[DnsCompareResult] = []

    for label, server in targets:
        cmd = ["dig", "+short", name, record_type]
        if server:
            cmd[1:1] = [f"@{server}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode != 0 and proc.stderr.strip():
            results.append(
                DnsCompareResult(
                    resolver=label,
                    server=server or None,
                    records=(),
                    error=proc.stderr.strip().splitlines()[-1],
                )
            )
            continue
        records = tuple(
            ln.strip()
            for ln in proc.stdout.splitlines()
            if ln.strip() and not ln.startswith(";")
        )
        results.append(
            DnsCompareResult(
                resolver=label,
                server=server or None,
                records=records,
                error=None,
            )
        )
    return results


def summarize_dns_compare(results: list[DnsCompareResult]) -> tuple[bool, str]:
    errors = [r.error for r in results if r.error]
    answer_sets = {tuple(r.records) for r in results if r.records}
    if errors and not answer_sets:
        return False, errors[0]
    if len(answer_sets) <= 1:
        return True, "consistent"
    parts: list[str] = []
    for result in results:
        if not result.records:
            continue
        preview = ", ".join(result.records[:3])
        if len(result.records) > 3:
            preview += " …"
        parts.append(f"{result.resolver}={preview}")
    return False, "mismatch: " + "; ".join(parts)


def parse_trace_hops(lines: list[str]) -> list[dict[str, str]]:
    """Extract delegation steps from dig +trace output."""
    hops: list[dict[str, str]] = []
    hop_re = re.compile(r"^([^\s#]+)\.\s+\(\s*([\d.]+|[^\s]+)\s*\)", re.IGNORECASE)
    received_re = re.compile(r"from ([0-9a-fA-F.:]+)", re.IGNORECASE)
    for line in lines:
        if "Received" in line:
            m = received_re.search(line)
            if m:
                hops.append({"zone": "resolver", "server": m.group(1)})
            continue
        m = hop_re.search(line)
        if m:
            hops.append({"zone": m.group(1), "server": m.group(2)})
    return hops
