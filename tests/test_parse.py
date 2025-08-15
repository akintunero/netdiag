from netdiag.traceroute import parse_traceroute_line


def test_parse_macos_hop_with_hostname():
    line = " 2  unn-79-127-149-241.datapacket.com (79.127.149.241)  102.240 ms"
    hop = parse_traceroute_line(line)
    assert hop is not None
    assert hop.index == 2
    assert hop.address == "79.127.149.241"
    assert hop.hostname == "unn-79-127-149-241.datapacket.com"
    assert hop.rtt_ms == [102.240]


def test_parse_timeout_hop():
    line = " 5  * * *"
    hop = parse_traceroute_line(line)
    assert hop is not None
    assert hop.index == 5
    assert hop.address is None


def test_parse_ip_only():
    line = " 1  10.5.0.1 (10.5.0.1)  342.815 ms"
    hop = parse_traceroute_line(line)
    assert hop is not None
    assert hop.address == "10.5.0.1"
