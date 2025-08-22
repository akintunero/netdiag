import pytest

from netdiag.presets import PRESETS, get_preset


def test_get_preset_oncall():
    p = get_preset("oncall")
    assert p.trace_max_hops == 18
    assert p.tls_check is True


def test_get_preset_vpn():
    p = get_preset("vpn")
    assert p.dns_compare is True


def test_unknown_preset():
    with pytest.raises(ValueError, match="unknown preset"):
        get_preset("nope")


def test_oncall_public_ping_targets_is_tuple():
    preset = PRESETS["oncall"]
    assert isinstance(preset.public_ping_targets, tuple)
    assert preset.public_ping_targets == ("1.1.1.1",)


def test_all_presets_documented():
    assert set(PRESETS) == {"web", "api", "vpn", "oncall"}
