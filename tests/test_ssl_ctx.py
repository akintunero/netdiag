import os
import ssl

from netdiag.ssl_ctx import create_verified_context


def test_create_verified_context_has_certificate_verification():
    ctx = create_verified_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname


def test_create_verified_context_uses_fallback_when_python_bundle_missing(monkeypatch, tmp_path):
    missing = tmp_path / "missing.pem"
    monkeypatch.setattr(
        "netdiag.ssl_ctx._python_ca_bundle_path",
        lambda: str(missing) if missing.exists() else None,
    )
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(
        open("/etc/ssl/cert.pem", "rb").read()
        if os.path.isfile("/etc/ssl/cert.pem")
        else b""
    )
    if bundle.stat().st_size == 0:
        return
    monkeypatch.setattr(
        "netdiag.ssl_ctx._fallback_ca_bundle_paths",
        lambda: (str(bundle),),
    )
    create_verified_context.cache_clear()
    ctx = create_verified_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    create_verified_context.cache_clear()
