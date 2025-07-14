from __future__ import annotations

import os
import ssl
from functools import lru_cache


def _python_ca_bundle_path() -> str | None:
    paths = ssl.get_default_verify_paths()
    if paths.cafile and os.path.isfile(paths.cafile):
        return paths.cafile
    return None


def _fallback_ca_bundle_paths() -> tuple[str, ...]:
    candidates: list[str] = []
    for env_key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        value = os.environ.get(env_key)
        if value:
            candidates.append(value)
    candidates.extend(
        (
            "/etc/ssl/cert.pem",
            "/private/etc/ssl/cert.pem",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/certs/ca-certificates.crt",
            "/opt/homebrew/etc/openssl@3/cert.pem",
            "/opt/homebrew/etc/openssl/cert.pem",
            "/usr/local/etc/openssl@3/cert.pem",
            "/usr/local/etc/openssl/cert.pem",
        )
    )
    try:
        import certifi

        candidates.append(certifi.where())
    except ImportError:
        pass
    seen: set[str] = set()
    ordered: list[str] = []
    for path in candidates:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return tuple(ordered)


def urlopen_verified(req, timeout: float = 10.0):
    """urllib opener using the same CA bundle as TLS probes."""
    from urllib.request import HTTPSHandler, build_opener

    opener = build_opener(HTTPSHandler(context=create_verified_context()))
    return opener.open(req, timeout=timeout)


@lru_cache(maxsize=1)
def create_verified_context() -> ssl.SSLContext:
    """SSL context with CA roots when Python's bundled openssl cert.pem is missing (common on macOS python.org builds)."""
    ctx = ssl.create_default_context()
    if _python_ca_bundle_path():
        return ctx
    for bundle in _fallback_ca_bundle_paths():
        if os.path.isfile(bundle):
            ctx.load_verify_locations(bundle)
            break
    return ctx
