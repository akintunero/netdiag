from netdiag.stats import (
    _rfc3550_jitter,
    _stddev,
    build_latency_stats,
    parse_ping_samples,
    parse_ping_summary,
)


def test_parse_ping_samples():
    out = """
PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=12.345 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=14.100 ms
"""
    samples = parse_ping_samples(out)
    assert samples == [12.345, 14.1]


def test_parse_ping_summary_linux():
    out = "rtt min/avg/max/mdev = 10.000/20.000/30.000/5.000 ms"
    assert parse_ping_summary(out) == (10.0, 20.0, 30.0, 5.0)


def test_build_latency_stats_percentiles():
    stats = build_latency_stats("t", "icmp", 5, [10.0, 20.0, 30.0, 40.0, 50.0])
    assert stats.min_ms == 10.0
    assert stats.max_ms == 50.0
    assert stats.avg_ms == 30.0
    assert stats.p50_ms == 30.0
    assert stats.stddev_ms is not None
    assert stats.jitter_ms == _rfc3550_jitter([10.0, 20.0, 30.0, 40.0, 50.0])


def test_stddev_empty():
    assert _stddev([]) is None
    assert _stddev([1.0]) is None
