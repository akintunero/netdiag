from netdiag.http_probe import _dn_tuple, parse_host_port


def test_dn_tuple_nested_rdn():
    subject = (
        (("countryName", "US"),),
        (("organizationName", "Cloudflare, Inc."),),
        (("commonName", "1.1.1.1"),),
    )
    assert _dn_tuple(subject) == (
        "countryName=US, organizationName=Cloudflare, Inc., commonName=1.1.1.1"
    )


def test_dn_tuple_empty():
    assert _dn_tuple(None) is None
    assert _dn_tuple(()) is None


def test_parse_host_port_ipv6_literal():
    host, port = parse_host_port("2001:db8::1", 443)
    assert host == "2001:db8::1"
    assert port == 443


def test_tcp_connect_first_ipv6_sockaddr(monkeypatch):
    import socket as std_socket
    from unittest.mock import MagicMock

    from netdiag.http_probe import _tcp_connect_first

    sockaddr = ("2606:4700:4700::1111", 443, 0, 0)
    addrs = [(std_socket.AF_INET6, std_socket.SOCK_STREAM, 6, "", sockaddr)]
    mock_sock = MagicMock()
    monkeypatch.setattr("netdiag.http_probe.socket.socket", lambda *a, **k: mock_sock)
    _tcp_connect_first(addrs, timeout=1.0)
    mock_sock.connect.assert_called_once_with(sockaddr)
