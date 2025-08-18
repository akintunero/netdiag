import pytest

from netdiag.port_scan import MAX_PORTS, parse_ports_spec, resolve_port_list


def test_parse_ports_list():
    assert parse_ports_spec("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports_spec("8000-8003") == [8000, 8001, 8002, 8003]


def test_parse_ports_mixed():
    assert parse_ports_spec("22,8000-8002") == [22, 8000, 8001, 8002]


def test_invalid_port():
    with pytest.raises(ValueError):
        parse_ports_spec("70000")


def test_resolve_common():
    ports = resolve_port_list(common=True)
    assert 443 in ports
    assert 22 in ports


def test_resolve_requires_one_source():
    with pytest.raises(ValueError):
        resolve_port_list()


def test_max_ports_enforced():
    from netdiag.port_scan import scan_tcp_ports

    with pytest.raises(ValueError):
        scan_tcp_ports("127.0.0.1", list(range(1, MAX_PORTS + 2)))
