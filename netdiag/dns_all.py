from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

COMMON_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


@dataclass(frozen=True)
class DnsRecordSet:
    record_type: str
    records: tuple[str, ...]
    error: str | None


@dataclass(frozen=True)
class DnsAllReport:
    name: str
    sets: tuple[DnsRecordSet, ...]


def lookup_all_records(name: str, types: tuple[str, ...] = COMMON_TYPES) -> DnsAllReport:
    if not shutil.which("dig"):
        raise RuntimeError("`dig` is required on PATH for dns-all.")

    sets: list[DnsRecordSet] = []
    for rtype in types:
        proc = subprocess.run(
            ["dig", "+short", name, rtype.upper()],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0 and proc.stderr.strip():
            sets.append(DnsRecordSet(record_type=rtype, records=(), error=proc.stderr.strip()))
            continue
        records = tuple(
            ln.strip()
            for ln in proc.stdout.splitlines()
            if ln.strip() and not ln.startswith(";")
        )
        sets.append(DnsRecordSet(record_type=rtype, records=records, error=None))
    return DnsAllReport(name=name, sets=tuple(sets))
