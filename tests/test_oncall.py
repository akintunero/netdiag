from unittest.mock import patch

from netdiag.health_check import CheckStep
from netdiag.oncall import run_preset_check
from netdiag.stats import LatencyStats


def _ping_ok(target, **_kwargs):
    return LatencyStats(
        target=target,
        probe="ping",
        sent=3,
        received=3,
        loss_pct=0.0,
        samples_ms=(1.0, 2.0, 3.0),
        min_ms=1.0,
        avg_ms=2.0,
        max_ms=3.0,
        stddev_ms=0.5,
        jitter_ms=0.5,
        p50_ms=2.0,
        p95_ms=3.0,
        p99_ms=3.0,
    )


@patch("netdiag.oncall.trace_and_enrich", return_value=[])
@patch("netdiag.oncall.tcp_probe", return_value=(True, 10.0, None))
@patch("netdiag.oncall.tls_inspect")
@patch("netdiag.oncall.http_timing")
@patch("netdiag.oncall.follow_redirects")
@patch("netdiag.oncall.check_security_headers")
@patch("netdiag.oncall.lookup_all_records")
@patch("netdiag.oncall.run_ping", side_effect=_ping_ok)
def test_oncall_literal_ip_skips_forward_dns(
    _ping,
    _dns_all,
    _headers,
    _redirects,
    _http,
    mock_tls,
    _tcp,
    _trace,
):
    from netdiag.http_probe import HttpTimingResult, TlsCertInfo

    mock_tls.return_value = TlsCertInfo(
        host="1.1.1.1",
        port=443,
        subject="commonName=1.1.1.1",
        issuer=None,
        sans=(),
        not_before=None,
        not_after=None,
        days_remaining=90,
        protocol="TLSv1.3",
        cipher=None,
        error=None,
    )
    _http.return_value = HttpTimingResult(
        url="https://1.1.1.1/",
        host="1.1.1.1",
        port=443,
        method="HEAD",
        status=200,
        ok=True,
        dns_ms=1.0,
        connect_ms=2.0,
        tls_ms=3.0,
        request_ms=4.0,
        total_ms=10.0,
        error=None,
    )
    report = run_preset_check("1.1.1.1", "api")
    dns_steps = [s for s in report.steps if s.name.startswith("DNS")]
    assert all(s.ok for s in dns_steps)
    assert any("literal" in s.detail.lower() for s in dns_steps)
