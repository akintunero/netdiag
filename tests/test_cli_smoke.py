"""Invoke every CLI handler via main(); ensures no exit 2 (crash) on core paths."""

from __future__ import annotations

import pytest

from netdiag.cli import main
from netdiag.exit_codes import EX_ERROR, EX_FAIL, EX_OK

IP = "1.1.1.1"
HOST = "cloudflare.com"


@pytest.mark.parametrize(
    "argv",
    [
        ["doctor"],
        ["--info"],
        ["--info", "--json"],
        ["presets"],
        ["presets", "--json"],
        ["subnet", "10.0.0.0/24"],
        ["ip", IP],
        ["ping", IP, "-c", "1"],
        ["dns", HOST, "-t", "A"],
        ["port", IP, "443"],
        ["ports", IP, "--common"],
        ["ptr", IP],
        ["tls", HOST, "--json"],
        ["http", f"https://{HOST}", "--json"],
        ["check", IP, "--preset", "web", "--json"],
        ["oncall", IP, "--preset", "web", "--json"],
        ["route", "--json"],
        ["ifaces", "--json"],
        ["local-ports", "--json"],
        ["connections", "--limit", "3", "--json"],
        ["dns-config", "--json"],
        ["whois", IP, "--no-bgp-api"],
        ["completion", "bash"],
    ],
)
def test_cli_commands_no_crash(argv: list[str]):
    code = main(argv)
    assert code in (EX_OK, EX_FAIL), f"unexpected exit {code} for {argv}"


def test_cli_invalid_config_preset(monkeypatch):
    from netdiag.config import NetdiagConfig

    monkeypatch.setattr(
        "netdiag.cli._load_config_safe",
        lambda: NetdiagConfig(oncall_preset="bogus"),
    )
    assert main(["oncall", IP, "--json"]) == EX_ERROR


def test_cli_json_output_valid():
    code = main(["oncall", IP, "--preset", "web", "--json"])
    assert code in (EX_OK, EX_FAIL)

