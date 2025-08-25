from unittest.mock import patch

from netdiag.dns_tools import parse_trace_hops
from netdiag.doctor import run_doctor
from netdiag.exit_codes import EX_ERROR, EX_OK
from netdiag.latency_probe import run_ping_latency
from netdiag.stats import build_latency_stats, parse_ping_samples, parse_ping_summary
from netdiag.traceroute import parse_traceroute_output
from tests.helpers import load_fixture


def test_ping_macos_fixture_samples():
    text = load_fixture("ping_macos.txt")
    samples = parse_ping_samples(text)
    assert samples == [12.345, 14.1, 11.9]
    assert parse_ping_summary(text) == (11.9, 12.782, 14.1, 0.945)


def test_ping_linux_fixture_samples():
    text = load_fixture("ping_linux.txt")
    samples = parse_ping_samples(text)
    assert len(samples) == 3
    assert parse_ping_summary(text)[0] == 12.3


def test_build_stats_from_macos_fixture():
    text = load_fixture("ping_macos.txt")
    stats = build_latency_stats("8.8.8.8", "icmp", 3, parse_ping_samples(text))
    assert stats.received == 3
    assert stats.avg_ms is not None
    assert 12.7 < stats.avg_ms < 12.9
    assert stats.p95_ms is not None


def test_traceroute_macos_fixture():
    hops = parse_traceroute_output(load_fixture("traceroute_macos.txt"))
    assert len(hops) == 4
    assert hops[0].address == "10.5.0.1"
    assert hops[2].address is None
    assert hops[3].address == "8.8.8.8"
    assert hops[3].rtt_ms == [10.5, 10.2, 10.1]


def test_traceroute_linux_fixture():
    hops = parse_traceroute_output(load_fixture("traceroute_linux.txt"))
    assert len(hops) == 3
    assert hops[-1].address == "8.8.8.8"


def test_dig_trace_fixture_hops():
    hops = parse_trace_hops(load_fixture("dig_trace_snippet.txt").splitlines())
    assert len(hops) >= 1


@patch("netdiag.latency_probe.subprocess.run")
def test_run_ping_uses_fixture(mock_run):
    from subprocess import CompletedProcess

    mock_run.return_value = CompletedProcess(
        args=["ping"],
        returncode=0,
        stdout=load_fixture("ping_macos.txt"),
        stderr="",
    )
    stats = run_ping_latency("8.8.8.8", count=3)
    assert stats.received == 3
    assert stats.min_ms == 11.9


def test_doctor_report_structure():
    report = run_doctor()
    assert report.platform
    assert any(t.requirement.binary == "ping" for t in report.tools)
    categories = {t.requirement.category for t in report.tools}
    assert "required" in categories


def test_exit_code_constants():
    assert EX_OK == 0
    assert EX_ERROR == 2
