from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = Path.home() / ".config" / "netdiag" / "config.toml"


@dataclass(frozen=True)
class NetdiagConfig:
    corp_host: str | None = None
    no_bgp_api: bool = False
    oncall_preset: str = "oncall"
    json_by_default: bool = False


def load_config(path: Path | None = None) -> NetdiagConfig:
    cfg_path = path or CONFIG_PATH
    if not cfg_path.is_file():
        return NetdiagConfig()

    try:
        data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(str(exc)) from exc
    defaults = data.get("defaults", {})
    oncall = data.get("oncall", {})
    return NetdiagConfig(
        corp_host=defaults.get("corp_host") or oncall.get("corp_host"),
        no_bgp_api=bool(defaults.get("no_bgp_api", False)),
        oncall_preset=str(oncall.get("preset", defaults.get("preset", "oncall"))),
        json_by_default=bool(defaults.get("json", False)),
    )
