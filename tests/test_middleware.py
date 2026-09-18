"""Integration tests for SecurityHeadersMiddleware with FastAPI."""

from fastapi import FastAPI, WebSocket
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from fastapi_security_headers import (
    Presets,
    SecurityHeadersConfig,
    SecurityHeadersMiddleware,
)


def test_default_headers_injected(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "secure-hello"}

    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-xss-protection"] == "0"
    assert headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["permissions-policy"] == "geolocation=(), microphone=(), camera=()"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"


def test_api_preset_headers(create_app):
    app = create_app(config=Presets.api())
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    headers = response.headers
    assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert headers["referrer-policy"] == "no-referrer"


def test_swagger_friendly_preset_headers(create_app):
    app = create_app(config=Presets.swagger_friendly())
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "https://cdn.jsdelivr.net" in csp
    assert "https://fastapi.tiangolo.com" in csp


def test_strict_preset_headers(create_app):
    app = create_app(config=Presets.strict())
    client = TestClient(app, base_url="https://testserver")

    response = client.get("/")
    assert response.status_code == 200
    headers = response.headers
    assert headers["cross-origin-embedder-policy"] == "require-corp"
    assert "preload" in headers["strict-transport-security"]


def test_route_header_preserved_when_override_false(create_app):
    """When override=False (default), route-specific headers should NOT be overwritten."""
    app = create_app(override=False)
    client = TestClient(app)

    response = client.get("/custom-frame")
    assert response.status_code == 200
    # The route returned SAMEORIGIN, so it must be preserved
    assert response.headers["x-frame-options"] == "SAMEORIGIN"


def test_route_header_overridden_when_override_true(create_app):
    """When override=True, middleware should force its own headers."""
    app = create_app(override=True)
    client = TestClient(app)

    response = client.get("/custom-frame")
    assert response.status_code == 200
    # Middleware config specifies DENY, which overrides the route's SAMEORIGIN
    assert response.headers["x-frame-options"] == "DENY"


def test_custom_headers_injected(create_app):
    config = SecurityHeadersConfig(
        custom_headers={"X-Server-Protection": "Active", "X-Custom-Env": "Prod"}
    )
    app = create_app(config=config)
    client = TestClient(app)

    response = client.get("/")
    assert response.headers["x-server-protection"] == "Active"
    assert response.headers["x-custom-env"] == "Prod"


def test_streaming_response_supported():
    """Verify that pure ASGI middleware preserves streaming responses seamlessly."""
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    async def fake_stream():
        yield b"chunk1"
        yield b"chunk2"

    @app.get("/stream")
    async def stream_endpoint():
        return StreamingResponse(fake_stream(), media_type="text/plain")

    client = TestClient(app)
    response = client.get("/stream")
    assert response.status_code == 200
    assert response.text == "chunk1chunk2"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_websocket_bypass():
    """Verify that WebSocket traffic bypasses HTTP header logic without errors."""
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        data = await websocket.receive_text()
        await websocket.send_text(f"echo:{data}")
        await websocket.close()

    client = TestClient(app)
    with client.websocket_connect("/ws") as ws:
        ws.send_text("hello-asgi")
        data = ws.receive_text()
        assert data == "echo:hello-asgi"
