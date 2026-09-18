"""FastAPI Security Headers.

High-performance, zero-config OWASP security headers middleware for FastAPI and Starlette.
"""

from .config import HSTSConfig, SecurityHeadersConfig
from .middleware import SecurityHeadersMiddleware
from .presets import Presets

__version__ = "0.1.1"

__all__ = [
    "SecurityHeadersMiddleware",
    "SecurityHeadersConfig",
    "HSTSConfig",
    "Presets",
    "__version__",
]
