import io

from netdiag.banner import BANNER_LINES, banner_text, print_banner
from netdiag.info import print_info


def test_banner_wordmark_lines():
    assert len(BANNER_LINES) == 11
    assert "▐░░▌" in banner_text()


def test_print_info_shows_banner():
    buf = io.StringIO()
    print_info(stream=buf, show_banner=True)
    body = buf.getvalue()
    assert "▐░░▌" in body
    assert body.index("▐") < body.index("netdiag 0")


def test_no_banner_env(monkeypatch):
    monkeypatch.setenv("NETDIAG_NO_BANNER", "1")
    buf = io.StringIO()
    print_banner(stream=buf)
    assert buf.getvalue() == ""
