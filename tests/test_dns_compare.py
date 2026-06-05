from netdiag.dns_tools import DnsCompareResult, dns_compare_is_consistent, summarize_dns_compare


def test_summarize_consistent():
    results = [
        DnsCompareResult("system", None, ("1.2.3.4",), None),
        DnsCompareResult("google", "8.8.8.8", ("1.2.3.4",), None),
    ]
    ok, detail = summarize_dns_compare(results)
    assert ok
    assert detail == "consistent"


def test_summarize_mismatch():
    results = [
        DnsCompareResult("system", None, ("1.2.3.4",), None),
        DnsCompareResult("google", "8.8.8.8", ("5.6.7.8",), None),
    ]
    ok, detail = summarize_dns_compare(results)
    assert not ok
    assert "mismatch" in detail
    assert "system=" in detail
    assert "google=" in detail


def test_dns_compare_is_consistent():
    consistent = [
        DnsCompareResult("system", None, ("1.2.3.4",), None),
        DnsCompareResult("google", "8.8.8.8", ("1.2.3.4",), None),
    ]
    assert dns_compare_is_consistent(consistent)
    assert not dns_compare_is_consistent(
        [
            DnsCompareResult("system", None, ("1.2.3.4",), None),
            DnsCompareResult("google", "8.8.8.8", ("5.6.7.8",), None),
        ]
    )
