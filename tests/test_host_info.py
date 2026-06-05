from netdiag.host_info import _parse_lsof_connections, _parse_ss_output


def test_parse_lsof_connections_macos_style() -> None:
    text = """COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Cursor    829 oak    45u  IPv4 0x1234567890abcdef      0t0  TCP 192.168.1.77:55820->3.86.150.204:443 (ESTABLISHED)
"""
    rows = _parse_lsof_connections(text)
    assert len(rows) == 1
    row = rows[0]
    assert row.command == "Cursor"
    assert row.pid == "829"
    assert row.user == "oak"
    assert row.local == "192.168.1.77:55820"
    assert row.remote == "3.86.150.204:443"
    assert row.state == "ESTABLISHED"
    assert row.proto == "tcp4"


def test_parse_ss_output_with_process() -> None:
    text = (
        'tcp ESTAB 0 0 192.168.1.77:55820 3.86.150.204:443 '
        'users:(("curl",pid=4242,fd=4))'
    )
    rows = _parse_ss_output(text)
    assert len(rows) == 1
    row = rows[0]
    assert row.command == "curl"
    assert row.pid == "4242"
    assert row.local == "192.168.1.77:55820"
    assert row.remote == "3.86.150.204:443"
