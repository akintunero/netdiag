import io
import json

from netdiag.cli import main
from netdiag.info import AUTHOR, PROJECT_NAME, info_dict, print_info


def test_info_dict_contains_developer():
    data = info_dict()
    assert data["name"] == PROJECT_NAME
    assert data["author"] == AUTHOR
    assert "akintunero" in data["homepage"]


def test_print_info_includes_author():
    buf = io.StringIO()
    print_info(stream=buf)
    text = buf.getvalue()
    assert AUTHOR in text
    assert "akintunero101@gmail.com" in text


def test_cli_info_flag():
    assert main(["--info"]) == 0


def test_cli_info_json(capsys):
    assert main(["--info", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["author"] == AUTHOR
    assert payload["version"]
