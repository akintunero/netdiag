from __future__ import annotations

from netdiag.health_check import CheckStep, HealthReport
from netdiag.models import AsnRecord, BgpRecord, EnrichedHop


def _asn_dict(rec: AsnRecord | None) -> dict | None:
    if rec is None:
        return None
    return {
        "asn": rec.asn,
        "prefix": rec.prefix,
        "country": rec.country,
        "registry": rec.registry,
        "allocated": rec.allocated,
        "name": rec.name,
    }


def _bgp_dict(rec: BgpRecord | None) -> dict | None:
    if rec is None:
        return None
    return {
        "asn": rec.asn,
        "prefix": rec.prefix,
        "name": rec.name,
        "country": rec.country,
        "rir": rec.rir,
        "description": rec.description,
    }


def enriched_hop_dict(item: EnrichedHop) -> dict:
    hop = item.hop
    return {
        "index": hop.index,
        "address": hop.address,
        "hostname": hop.hostname,
        "rtt_ms": hop.rtt_ms,
        "reverse_dns": item.reverse_dns,
        "asn": _asn_dict(item.asn),
        "bgp": _bgp_dict(item.bgp),
    }


def health_report_dict(report: HealthReport) -> dict:
    return {
        "target": report.target,
        "ok": report.ok,
        "steps": [
            {"name": s.name, "ok": s.ok, "detail": s.detail}
            for s in report.steps
        ],
    }
