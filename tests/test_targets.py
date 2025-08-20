from netdiag.targets import (
    https_url_for_target,
    is_literal_ip,
    literal_dns_step,
    parse_probe_host,
)


def test_literal_ipv4_dns_a():
    step = literal_dns_step("1.1.1.1", "A")
    assert step is not None
    assert step.ok
    assert "1.1.1.1" in step.detail
    assert step.resolved_ip == "1.1.1.1"


def test_literal_ipv4_dns_aaaa_na():
    step = literal_dns_step("1.1.1.1", "AAAA")
    assert step is not None
    assert step.ok
    assert "N/A" in step.detail


def test_https_url_ipv4():
    assert https_url_for_target("1.1.1.1") == "https://1.1.1.1/"


def test_https_url_ipv6():
    assert https_url_for_target("2001:db8::1") == "https://[2001:db8::1]/"


def test_parse_probe_host_ipv6_bracketed():
    host, port = parse_probe_host("[2001:db8::1]:443")
    assert host == "2001:db8::1"
    assert port == 443


def test_is_literal_ip():
    assert is_literal_ip("8.8.8.8")
    assert not is_literal_ip("example.com")
