"""Pre-configured security presets for common use cases.

Includes presets for:
- DEFAULT: Balanced security baseline following OWASP recommendations.
- API: Hardened configuration for headless, pure JSON REST APIs.
- SWAGGER_FRIENDLY: Secure preset that maintains full compatibility with FastAPI's Swagger UI (/docs) and ReDoc.
- STRICT: Maximum security posture for banking, healthcare, and high-compliance environments.
"""

from .config import HSTSConfig, SecurityHeadersConfig


class Presets:
    """Factory collection of pre-configured SecurityHeadersConfig presets."""

    @staticmethod
    def default() -> SecurityHeadersConfig:
        """Returns the default, balanced OWASP security configuration.

        Suitable for general web applications and mixed APIs.
        """
        return SecurityHeadersConfig()

    @staticmethod
    def api() -> SecurityHeadersConfig:
        """Returns a hardened preset optimized for pure headless JSON APIs.

        Disallows any frames, scripts, or embeds since a JSON API only returns data.
        """
        return SecurityHeadersConfig(
            x_content_type_options=True,
            x_frame_options="DENY",
            x_xss_protection="0",
            strict_transport_security=HSTSConfig(
                max_age=31536000,
                include_subdomains=True,
                preload=False,
            ),
            referrer_policy="no-referrer",
            permissions_policy=(
                "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
                "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), "
                "magnetometer=(), microphone=(), midi=(), payment=(), "
                "picture-in-picture=(), usb=()"
            ),
            content_security_policy="default-src 'none'; frame-ancestors 'none'",
            cross_origin_opener_policy="same-origin",
            cross_origin_resource_policy="same-origin",
            strip_server_headers=True,
        )

    @staticmethod
    def swagger_friendly() -> SecurityHeadersConfig:
        """Returns a secure preset compatible with FastAPI's /docs (Swagger UI) and /redoc.

        Permits required CDN scripts/styles (jsdelivr) and icons (fastapi.tiangolo.com)
        while enforcing strict security on all other vectors.
        """
        swagger_csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "frame-ancestors 'none'"
        )
        return SecurityHeadersConfig(
            x_content_type_options=True,
            x_frame_options="DENY",
            x_xss_protection="0",
            strict_transport_security=HSTSConfig(
                max_age=31536000,
                include_subdomains=True,
                preload=False,
            ),
            referrer_policy="strict-origin-when-cross-origin",
            permissions_policy="geolocation=(), microphone=(), camera=()",
            content_security_policy=swagger_csp,
            cross_origin_opener_policy="same-origin",
            cross_origin_resource_policy="same-origin",
        )

    @staticmethod
    def strict() -> SecurityHeadersConfig:
        """Returns maximum security configuration for high-compliance environments.

        Enforces 2-year HSTS with preload consent, isolation policies, and restrictive CSP.
        """
        strict_csp = (
            "default-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        return SecurityHeadersConfig(
            x_content_type_options=True,
            x_frame_options="DENY",
            x_xss_protection="0",
            strict_transport_security=HSTSConfig(
                max_age=63072000,  # 2 years
                include_subdomains=True,
                preload=True,
            ),
            referrer_policy="no-referrer",
            permissions_policy=(
                "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
                "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), "
                "magnetometer=(), microphone=(), midi=(), payment=(), "
                "picture-in-picture=(), usb=()"
            ),
            content_security_policy=strict_csp,
            cross_origin_opener_policy="same-origin",
            cross_origin_resource_policy="same-origin",
            cross_origin_embedder_policy="require-corp",
            strip_server_headers=True,
        )
