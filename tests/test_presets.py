"""Unit tests for presets."""

from urllib.parse import urlparse

from fastapi_security_headers.presets import Presets


def test_preset_default():
    config = Presets.default()
    compiled = dict(config.compile_headers())
    assert compiled[b"x-frame-options"] == b"DENY"
    assert compiled[b"x-content-type-options"] == b"nosniff"


def test_preset_api():
    config = Presets.api()
    compiled = dict(config.compile_headers())
    assert compiled[b"content-security-policy"] == b"default-src 'none'; frame-ancestors 'none'"
    assert compiled[b"referrer-policy"] == b"no-referrer"
    assert b"accelerometer=()" in compiled[b"permissions-policy"]


def test_preset_swagger_friendly():
    config = Presets.swagger_friendly()
    compiled = dict(config.compile_headers())
    csp = compiled[b"content-security-policy"].decode("latin-1")

    directives = [d.strip() for d in csp.split(";") if d.strip()]
    script_src = next((d for d in directives if d.startswith("script-src ")), "")
    sources = script_src.split()[1:] if script_src else []
    hosts = {urlparse(source).hostname for source in sources if "://" in source}

    assert "cdn.jsdelivr.net" in hosts
    assert "fastapi.tiangolo.com" in hosts
    assert "frame-ancestors 'none'" in csp


def test_preset_strict():
    config = Presets.strict()
    compiled = dict(config.compile_headers())
    assert compiled[b"cross-origin-embedder-policy"] == b"require-corp"
    assert b"preload" in compiled[b"strict-transport-security"]
    assert b"max-age=63072000" in compiled[b"strict-transport-security"]
    assert compiled[b"referrer-policy"] == b"no-referrer"
