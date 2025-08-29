import json
from unittest.mock import patch

from netdiag.cli import main
from netdiag.exit_codes import EX_ERROR, EX_OK


def test_main_info_json():
    assert main(["--info", "--json"]) == EX_OK


def test_main_invalid_config_preset(capsys):
    from netdiag.config import NetdiagConfig

    with patch("netdiag.cli._load_config_safe") as mock_cfg:
        mock_cfg.return_value = NetdiagConfig(oncall_preset="bogus")
        code = main(["oncall", "1.1.1.1", "--json"])
    assert code == EX_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert "error" in payload


def test_main_no_command():
    assert main([]) == EX_ERROR
