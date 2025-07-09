from __future__ import annotations

import math
import re
from dataclasses import dataclass

_PING_RTT_RE = re.compile(r"time[<=]([\d.]+)\s*ms", re.IGNORECASE)


@dataclass(frozen=True)
class LatencyStats:
    target: str
    probe: str
    sent: int
    received: int
    loss_pct: float
    samples_ms: tuple[float, ...]
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    stddev_ms: float | None
    jitter_ms: float | None
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None


def parse_ping_samples(output: str) -> list[float]:
    samples: list[float] = []
    for line in output.splitlines():
        for match in _PING_RTT_RE.finditer(line):
            samples.append(float(match.group(1)))
    return samples


def parse_ping_summary(output: str) -> tuple[float | None, float | None, float | None, float | None]:
    """Return min, avg, max, stddev/mdev from ping summary line."""
    for line in output.splitlines():
        lower = line.lower()
        if "min/avg/max" not in lower and "round-trip" not in lower:
            continue
        part = line.split("=")[-1].strip().split()[0]
        nums = part.replace("ms", "").split("/")
        if len(nums) < 3:
            continue
        min_ms, avg_ms, max_ms = float(nums[0]), float(nums[1]), float(nums[2])
        stddev = float(nums[3]) if len(nums) >= 4 else None
        return min_ms, avg_ms, max_ms, stddev
    return None, None, None, None


def _percentile(sorted_samples: list[float], pct: float) -> float:
    if not sorted_samples:
        raise ValueError("empty samples")
    if len(sorted_samples) == 1:
        return sorted_samples[0]
    k = (len(sorted_samples) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_samples[int(k)]
    return sorted_samples[f] + (sorted_samples[c] - sorted_samples[f]) * (k - f)


def _stddev(samples: list[float]) -> float | None:
    if len(samples) < 2:
        return None
    mean = sum(samples) / len(samples)
    variance = sum((x - mean) ** 2 for x in samples) / len(samples)
    return math.sqrt(variance)


def _rfc3550_jitter(samples: list[float]) -> float | None:
    if len(samples) < 2:
        return None
    deltas = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
    return sum(deltas) / len(deltas)


def build_latency_stats(
    target: str,
    probe: str,
    sent: int,
    samples: list[float],
    *,
    summary_min: float | None = None,
    summary_avg: float | None = None,
    summary_max: float | None = None,
    summary_stddev: float | None = None,
) -> LatencyStats:
    received = len(samples)
    loss = 100.0 * (1 - received / sent) if sent else 100.0

    if samples:
        min_ms = min(samples)
        max_ms = max(samples)
        avg_ms = sum(samples) / len(samples)
        stddev_ms = _stddev(samples)
        jitter_ms = _rfc3550_jitter(samples)
        ordered = sorted(samples)
        p50 = _percentile(ordered, 50)
        p95 = _percentile(ordered, 95)
        p99 = _percentile(ordered, 99)
    else:
        min_ms = summary_min
        avg_ms = summary_avg
        max_ms = summary_max
        stddev_ms = summary_stddev
        jitter_ms = None
        p50 = p95 = p99 = None

    if stddev_ms is None and summary_stddev is not None:
        stddev_ms = summary_stddev

    return LatencyStats(
        target=target,
        probe=probe,
        sent=sent,
        received=received,
        loss_pct=loss,
        samples_ms=tuple(samples),
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        stddev_ms=stddev_ms,
        jitter_ms=jitter_ms,
        p50_ms=p50,
        p95_ms=p95,
        p99_ms=p99,
    )


def format_ms(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "-"


_fmt_ms = format_ms


def format_latency_summary(stats: LatencyStats) -> str:
    parts = [
        f"min {_fmt_ms(stats.min_ms)}",
        f"avg {_fmt_ms(stats.avg_ms)}",
        f"max {_fmt_ms(stats.max_ms)} ms",
    ]
    if stats.stddev_ms is not None:
        parts.append(f"σ {_fmt_ms(stats.stddev_ms)}")
    if stats.jitter_ms is not None:
        parts.append(f"jitter {_fmt_ms(stats.jitter_ms)}")
    if stats.p95_ms is not None:
        parts.append(f"p95 {_fmt_ms(stats.p95_ms)}")
    return " ".join(parts)
