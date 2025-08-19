from pathlib import Path

from netdiag.config import load_config


def test_load_config_missing_returns_defaults():
    cfg = load_config(Path("/nonexistent/netdiag/config.toml"))
    assert cfg.corp_host is None
    assert cfg.oncall_preset == "oncall"
    assert cfg.no_bgp_api is False


def test_load_config_from_file(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[defaults]
corp_host = "app.corp"
no_bgp_api = true

[oncall]
preset = "api"
""",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.corp_host == "app.corp"
    assert cfg.no_bgp_api is True
    assert cfg.oncall_preset == "api"
