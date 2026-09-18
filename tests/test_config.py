"""Unit tests for configuration models and header pre-compilation."""

from fastapi_security_headers.config import HSTSConfig, SecurityHeadersConfig


def test_hsts_config_defaults():
    hsts = HSTSConfig()
    assert hsts.max_age == 31536000
    assert hsts.include_subdomains is True
    assert hsts.preload is False
    assert hsts.require_https is True
    assert hsts.to_header_value() == "max-age=31536000; includeSubDomains"


def test_hsts_config_with_preload():
    hsts = HSTSConfig(max_age=63072000, include_subdomains=True, preload=True)
    assert hsts.to_header_value() == "max-age=63072000; includeSubDomains; preload"


def test_hsts_config_without_subdomains():
    hsts = HSTSConfig(max_age=86400, include_subdomains=False, preload=False)
    assert hsts.to_header_value() == "max-age=86400"


def test_security_headers_config_defaults():
    config = SecurityHeadersConfig()
    compiled = dict(config.compile_headers())

    assert compiled[b"x-content-type-options"] == b"nosniff"
    assert compiled[b"x-frame-options"] == b"DENY"
    assert compiled[b"x-xss-protection"] == b"0"
    assert compiled[b"strict-transport-security"] == b"max-age=31536000; includeSubDomains"
    assert compiled[b"referrer-policy"] == b"strict-origin-when-cross-origin"
    assert compiled[b"permissions-policy"] == b"geolocation=(), microphone=(), camera=()"
    assert compiled[b"cross-origin-opener-policy"] == b"same-origin"
    assert compiled[b"cross-origin-resource-policy"] == b"same-origin"
    assert config.strip_server_headers is False
    # By default, CSP, CSP Report-Only, and COEP are None in base config
    assert b"content-security-policy" not in compiled
    assert b"content-security-policy-report-only" not in compiled
    assert b"cross-origin-embedder-policy" not in compiled


def test_security_headers_config_csp_report_only():
    config = SecurityHeadersConfig(
        content_security_policy_report_only="default-src 'self'; report-uri /csp-report"
    )
    compiled = dict(config.compile_headers())
    assert (
        compiled[b"content-security-policy-report-only"]
        == b"default-src 'self'; report-uri /csp-report"
    )


def test_security_headers_config_disable_headers():
    config = SecurityHeadersConfig(
        x_content_type_options=False,
        x_frame_options=None,
        x_xss_protection=None,
        strict_transport_security=None,
        referrer_policy=None,
        permissions_policy=None,
        cross_origin_opener_policy=None,
        cross_origin_resource_policy=None,
        content_security_policy_report_only=None,
    )
    compiled = config.compile_headers()
    assert len(compiled) == 0


def test_security_headers_config_custom_headers():
    config = SecurityHeadersConfig(
        custom_headers={
            "X-Clacks-Overhead": "GNU Terry Pratchett",
            "X-Permitted-Cross-Domain-Policies": "none",
        }
    )
    compiled = dict(config.compile_headers())
    assert compiled[b"x-clacks-overhead"] == b"GNU Terry Pratchett"
    assert compiled[b"x-permitted-cross-domain-policies"] == b"none"
