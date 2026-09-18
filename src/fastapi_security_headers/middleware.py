"""Pure ASGI Middleware for injecting HTTP security headers.

High-performance, zero-copy architecture that operates directly on ASGI message streams
without buffering response bodies or imposing memory overhead.
"""

from typing import Any, Awaitable, Callable, Iterable, List, MutableMapping, Optional, Set, Tuple

from .config import SecurityHeadersConfig

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def _is_secure_request(scope: Scope) -> bool:
    """Checks whether the incoming request is HTTPS or forwarded HTTPS.

    Supports direct HTTPS scheme as well as standard reverse proxy headers
    (X-Forwarded-Proto: https, X-Forwarded-Ssl: on).
    """
    if scope.get("scheme") == "https":
        return True
    headers = scope.get("headers", [])
    for key, value in headers:
        key_lower = key.lower()
        if key_lower == b"x-forwarded-proto" and value.lower() == b"https":
            return True
        if key_lower == b"x-forwarded-ssl" and value.lower() == b"on":
            return True
    return False


class SecurityHeadersMiddleware:
    """Pure ASGI middleware that injects pre-compiled OWASP security headers.

    Compatible with FastAPI, Starlette, and any ASGI 3 framework.

    Example:
        ```python
        from fastapi import FastAPI
        from fastapi_security_headers import SecurityHeadersMiddleware, Presets

        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, config=Presets.api())
        ```

    Attributes:
        app: The inner ASGI application.
        config: SecurityHeadersConfig instance. Defaults to Presets.default().
        override: If True, overrides existing headers from route responses.
                  If False (default), respects headers explicitly set by routes.
        strip_server_headers: If True, strips 'Server' and 'X-Powered-By' response headers.
        excluded_paths: Optional collection of URL paths or path prefixes to bypass.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: Optional[SecurityHeadersConfig] = None,
        override: bool = False,
        strip_server_headers: Optional[bool] = None,
        excluded_paths: Optional[Iterable[str]] = None,
    ) -> None:
        self.app = app
        self.config: SecurityHeadersConfig = config or SecurityHeadersConfig()
        self.override: bool = override
        self.strip_server_headers: bool = (
            strip_server_headers
            if strip_server_headers is not None
            else self.config.strip_server_headers
        )
        self.excluded_paths: Set[str] = set(excluded_paths) if excluded_paths else set()

        # Pre-compile headers once at startup for zero-overhead per-request execution
        self._compiled_headers: List[Tuple[bytes, bytes]] = self.config.compile_headers()

        # RFC 6797 §7.2: Separate HSTS header if require_https is active
        self._require_https_hsts: bool = bool(
            self.config.strict_transport_security
            and self.config.strict_transport_security.require_https
        )
        if self._require_https_hsts:
            self._hsts_header: Optional[Tuple[bytes, bytes]] = next(
                (h for h in self._compiled_headers if h[0] == b"strict-transport-security"),
                None,
            )
            self._base_compiled_headers: List[Tuple[bytes, bytes]] = [
                h for h in self._compiled_headers if h[0] != b"strict-transport-security"
            ]
        else:
            self._hsts_header = None
            self._base_compiled_headers = self._compiled_headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only process HTTP requests; pass WebSockets and lifespan events untouched
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Check path exclusions
        if self.excluded_paths:
            path = scope.get("path", "")
            if path in self.excluded_paths or any(
                path.startswith(f"{p.rstrip('/')}/") for p in self.excluded_paths
            ):
                await self.app(scope, receive, send)
                return

        # Select pre-compiled headers (respecting RFC 6797 HTTPS enforcement)
        if self._hsts_header is not None:
            if _is_secure_request(scope):
                headers_to_inject = self._compiled_headers
            else:
                headers_to_inject = self._base_compiled_headers
        else:
            headers_to_inject = self._compiled_headers

        async def send_wrapper(message: Message) -> None:
            if message.get("type") == "http.response.start":
                raw_headers: List[Tuple[bytes, bytes]] = list(message.get("headers", []))

                if self.strip_server_headers:
                    raw_headers = [
                        (k, v)
                        for k, v in raw_headers
                        if k.lower() not in (b"server", b"x-powered-by")
                    ]

                if self.override:
                    # Remove any matching headers before appending our pre-compiled headers
                    compiled_keys: Set[bytes] = {k for k, _ in headers_to_inject}
                    raw_headers = [
                        (k, v) for k, v in raw_headers if k.lower() not in compiled_keys
                    ]
                    raw_headers.extend(headers_to_inject)
                else:
                    # Only append headers that haven't been explicitly defined by the route
                    existing_keys: Set[bytes] = {k.lower() for k, _ in raw_headers}
                    for header_name, header_value in headers_to_inject:
                        if header_name not in existing_keys:
                            raw_headers.append((header_name, header_value))

                message["headers"] = raw_headers

            await send(message)

        await self.app(scope, receive, send_wrapper)
