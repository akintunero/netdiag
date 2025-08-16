from netdiag.enrichment import _parse_cymru_line


def test_parse_cymru_txt():
    line = '"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'
    rec = _parse_cymru_line(line)
    assert rec is not None
    assert rec.asn == 15169
    assert rec.prefix == "8.8.8.0/24"
    assert rec.country == "US"
