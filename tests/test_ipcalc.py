from netdiag.http_probe import parse_host_port
from netdiag.ipcalc import address_properties, describe_subnet, reverse_dns


def test_describe_subnet_v4():
    info = describe_subnet("10.0.0.0/24")
    assert info.version == 4
    assert info.network == "10.0.0.0"
    assert info.num_addresses == 256
    assert info.num_hosts == 254
    assert info.is_private is True


def test_describe_subnet_v6():
    info = describe_subnet("2001:db8::/32")
    assert info.version == 6
    assert info.is_global is False


def test_address_properties_loopback():
    props = address_properties("127.0.0.1")
    assert props["is_loopback"] is True
    assert props["version"] == 4


def test_parse_host_port_bracketed_v6():
    host, port = parse_host_port("[2001:db8::1]:8443", 443)
    assert host == "2001:db8::1"
    assert port == 8443


def test_parse_host_port_simple():
    host, port = parse_host_port("example.com:8080", 443)
    assert host == "example.com"
    assert port == 8080


def test_reverse_dns_invalid():
    host, err = reverse_dns("not-an-ip")
    assert host is None
    assert err is not None
