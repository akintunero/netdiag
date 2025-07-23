from __future__ import annotations

import platform
import socket
import subprocess
import time

from netdiag.stats import (
    LatencyStats,
    build_latency_stats,
    parse_ping_samples,
    parse_ping_summary,
)


def run_ping_latency(
    target: str,
    count: int = 10,
    *,
    interval_sec: float | None = None,
    timeout_sec: int = 5,
) -> LatencyStats:
    system = platform.system().lower()
    if system == "darwin":
        cmd = ["ping", "-c", str(count), "-W", str(timeout_sec * 1000)]
        if interval_sec is not None:
            cmd.extend(["-i", str(interval_sec)])
        cmd.append(target)
    elif system == "linux":
        cmd = ["ping", "-c", str(count), "-W", str(timeout_sec)]
        if interval_sec is not None:
            cmd.extend(["-i", str(interval_sec)])
        cmd.append(target)
    else:
        cmd = ["ping", "-n", str(count), "-w", str(timeout_sec), target]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    out = proc.stdout + proc.stderr
    samples = parse_ping_samples(out)
    s_min, s_avg, s_max, s_std = parse_ping_summary(out)
    if not samples:
        reply_count = out.lower().count("bytes from") + out.lower().count("reply from")
        if reply_count and s_avg is not None:
            samples = [s_avg] * reply_count

    return build_latency_stats(
        target,
        "icmp",
        count,
        samples,
        summary_min=s_min,
        summary_avg=s_avg,
        summary_max=s_max,
        summary_stddev=s_std,
    )


def run_tcp_latency(
    host: str,
    port: int,
    count: int = 20,
    *,
    interval_sec: float = 0.2,
    timeout: float = 5.0,
) -> LatencyStats:
    samples: list[float] = []
    errors = 0
    for i in range(count):
        if i > 0 and interval_sec > 0:
            time.sleep(interval_sec)
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                samples.append((time.monotonic() - start) * 1000)
        except OSError:
            errors += 1

    return build_latency_stats(
        f"{host}:{port}",
        "tcp",
        count,
        samples,
    )
