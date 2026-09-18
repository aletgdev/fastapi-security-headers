"""Configuration models for FastAPI Security Headers.

Provides dataclasses with secure OWASP defaults and pre-compilation to raw ASGI bytes.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class HSTSConfig:
    """HTTP Strict Transport Security (HSTS) configuration.

    Informs browsers that the site should only be accessed using HTTPS.

    Attributes:
        max_age: Time in seconds that the browser should remember this policy (default: 1 year).
        include_subdomains: If True, applies this rule to all subdomains.
        preload: If True, indicates consent to be included in browser preload lists.
        require_https: If True (default, RFC 6797 §7.2 compliant), only sends HSTS on HTTPS
            or forwarded HTTPS connections, preventing browser lockouts on localhost/HTTP.
    """

    max_age: int = 31536000  # 1 year in seconds
    include_subdomains: bool = True
    preload: bool = False
    require_https: bool = True

    def to_header_value(self) -> str:
        """Converts configuration into a valid HSTS header string."""
        parts = [f"max-age={self.max_age}"]
        if self.include_subdomains:
            parts.append("includeSubDomains")
        if self.preload:
            parts.append("preload")
        return "; ".join(parts)


@dataclass
class SecurityHeadersConfig:
    """Master configuration for all security headers.

    Configured with secure OWASP defaults out of the box.

    Attributes:
        x_content_type_options: Prevents MIME-sniffing when set to True ("nosniff").
        x_frame_options: Mitigates clickjacking. Can be "DENY", "SAMEORIGIN", or None.
        x_xss_protection: OWASP recommended value is "0" to disable vulnerable legacy filters.
        strict_transport_security: HSTS configuration instance or None to disable.
        referrer_policy: Controls the Referer header on outgoing links.
        permissions_policy: Disables browser features not needed by an API (e.g. camera).
        content_security_policy: Content Security Policy (CSP) directive string or None.
        content_security_policy_report_only: CSP Report-Only directive string or None.
        cross_origin_opener_policy: Isolates browsing context (default: "same-origin").
        cross_origin_resource_policy: Prevents cross-origin reads (default: "same-origin").
        cross_origin_embedder_policy: Controls cross-origin resources (default: None).
        strip_server_headers: If True, removes 'Server' and 'X-Powered-By' headers to mitigate fingerprinting.
        custom_headers: Dictionary of additional custom security headers to inject.
    """

    x_content_type_options: bool = True
    x_frame_options: Optional[str] = "DENY"
    x_xss_protection: Optional[str] = "0"
    strict_transport_security: Optional[HSTSConfig] = field(default_factory=HSTSConfig)
    referrer_policy: Optional[str] = "strict-origin-when-cross-origin"
    permissions_policy: Optional[str] = "geolocation=(), microphone=(), camera=()"
    content_security_policy: Optional[str] = None
    content_security_policy_report_only: Optional[str] = None
    cross_origin_opener_policy: Optional[str] = "same-origin"
    cross_origin_resource_policy: Optional[str] = "same-origin"
    cross_origin_embedder_policy: Optional[str] = None
    strip_server_headers: bool = False
    custom_headers: Optional[Dict[str, str]] = None

    def compile_headers(self) -> List[Tuple[bytes, bytes]]:
        """Pre-compiles all active headers into raw ASGI byte tuples (b'name', b'value').

        This method runs ONCE at startup to avoid string formatting and encoding
        overhead on every HTTP request.
        """
        raw_headers: List[Tuple[bytes, bytes]] = []

        # 1. X-Content-Type-Options
        if self.x_content_type_options:
            raw_headers.append((b"x-content-type-options", b"nosniff"))

        # 2. X-Frame-Options (Clickjacking defense)
        if self.x_frame_options:
            raw_headers.append((b"x-frame-options", self.x_frame_options.encode("latin-1")))

        # 3. X-XSS-Protection (OWASP recommends "0")
        if self.x_xss_protection is not None:
            raw_headers.append((b"x-xss-protection", self.x_xss_protection.encode("latin-1")))

        # 4. Strict-Transport-Security (HSTS)
        if self.strict_transport_security is not None:
            raw_headers.append(
                (b"strict-transport-security", self.strict_transport_security.to_header_value().encode("latin-1"))
            )

        # 5. Referrer-Policy
        if self.referrer_policy:
            raw_headers.append((b"referrer-policy", self.referrer_policy.encode("latin-1")))

        # 6. Permissions-Policy
        if self.permissions_policy:
            raw_headers.append((b"permissions-policy", self.permissions_policy.encode("latin-1")))

        # 7. Content-Security-Policy (CSP)
        if self.content_security_policy:
            raw_headers.append((b"content-security-policy", self.content_security_policy.encode("latin-1")))

        # 7b. Content-Security-Policy-Report-Only
        if self.content_security_policy_report_only:
            raw_headers.append(
                (b"content-security-policy-report-only", self.content_security_policy_report_only.encode("latin-1"))
            )

        # 8. Cross-Origin-Opener-Policy (COOP)
        if self.cross_origin_opener_policy:
            raw_headers.append((b"cross-origin-opener-policy", self.cross_origin_opener_policy.encode("latin-1")))

        # 9. Cross-Origin-Resource-Policy (CORP)
        if self.cross_origin_resource_policy:
            raw_headers.append((b"cross-origin-resource-policy", self.cross_origin_resource_policy.encode("latin-1")))

        # 10. Cross-Origin-Embedder-Policy (COEP)
        if self.cross_origin_embedder_policy:
            raw_headers.append((b"cross-origin-embedder-policy", self.cross_origin_embedder_policy.encode("latin-1")))

        # 11. Custom user headers
        if self.custom_headers:
            for name, val in self.custom_headers.items():
                raw_headers.append((name.lower().encode("latin-1"), val.encode("latin-1")))

        return raw_headers
