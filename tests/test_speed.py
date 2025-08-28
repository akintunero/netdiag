import pytest

from netdiag.speed import (
    _mbps,
    resolve_speed_endpoint,
    run_speed_test,
    speed_download,
)


def test_resolve_default_cloudflare():
    ep = resolve_speed_endpoint(None)
    assert ep.provider == "cloudflare"
    assert ep.connect_host == "speed.cloudflare.com"


def test_resolve_cloudflare_dns_ip_uses_cdn_edge(monkeypatch):
    monkeypatch.setattr(
        "netdiag.speed._cloudflare_speed_edge_ips",
        lambda: ["162.159.140.220", "2a06:98c1:58::da"],
    )
    ep = resolve_speed_endpoint("1.1.1.1")
    assert ep.connect_host == "162.159.140.220"
    assert ep.requested == "1.1.1.1"
    assert ep.tls_sni == "speed.cloudflare.com"


def test_resolve_unknown_ip_raises():
    with pytest.raises(ValueError, match="no built-in speed endpoint"):
        resolve_speed_endpoint("8.8.8.8")


def test_mbps_calculation():
    assert _mbps(1_250_000, 1.0) == pytest.approx(10.0)


def test_speed_download_invalid_url():
    result = speed_download("https://127.0.0.1:1/nope", timeout=1.0)
    assert result.error


def test_run_speed_test_mocked(monkeypatch):
    from netdiag import speed as speed_mod

    monkeypatch.setattr(
        "netdiag.speed._cloudflare_speed_edge_ips",
        lambda: ["162.159.140.220"],
    )

    def fake_parallel(endpoint, **kwargs):
        from netdiag.speed import SpeedProbeResult

        return SpeedProbeResult(
            mode="download",
            target="test",
            bytes_transferred=10_000_000,
            elapsed_sec=1.0,
            megabits_per_sec=80.0,
            parallel=4,
            error=None,
        )

    monkeypatch.setattr(speed_mod, "speed_download_parallel", fake_parallel)
    report = run_speed_test("1.1.1.1", parallel=4)
    assert report.download is not None
    assert report.download.megabits_per_sec == 80.0
    assert report.download.error is None
