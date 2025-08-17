from netdiag.dns_tools import parse_trace_hops
from netdiag.json_out import to_jsonable
from netdiag.stats import build_latency_stats


def test_parse_trace_hops():
    lines = [
        ";; Received 28 bytes from 1.1.1.1#53",
        "com.			172800	IN	NS	a.gtld-servers.net.",
    ]
    hops = parse_trace_hops(lines)
    assert isinstance(hops, list)


def test_json_latency_stats():
    stats = build_latency_stats("t", "icmp", 3, [1.0, 2.0, 3.0])
    data = to_jsonable(stats)
    assert data["avg_ms"] == 2.0
    assert data["p95_ms"] is not None
