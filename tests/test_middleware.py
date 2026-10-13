"""Integration tests for SecurityHeadersMiddleware with FastAPI."""

from fastapi import FastAPI, WebSocket
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from fastapi_security_headers import Presets, SecurityHeadersMiddleware


def test_default_headers_injected(create_app):
    app = create_app()
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "secure-hello"}

    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-xss-protection"] == "0"
    assert headers["strict-transport-security"] == "max-age=31536000"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["permissions-policy"] == "geolocation=(), microphone=(), camera=()"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"


def test_api_preset_headers(create_app):
    app = create_app(config=Presets.api())
    client = TestClient(app)
    response = client.get("/")
    headers = response.headers
    assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert headers["referrer-policy"] == "no-referrer"
    assert "server" not in headers


def test_route_level_override_respected(create_app):
    app = create_app()

    @app.get("/embeddable")
    async def embeddable():
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content={"ok": True},
            headers={"x-frame-options": "SAMEORIGIN"},
        )

    client = TestClient(app)
    response = client.get("/embeddable")
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    # Other middleware headers still present
    assert response.headers["x-content-type-options"] == "nosniff"


def test_override_true_forces_middleware_headers(create_app):
    app = create_app(override=True)

    @app.get("/embeddable")
    async def embeddable():
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content={"ok": True},
            headers={"x-frame-options": "SAMEORIGIN"},
        )

    client = TestClient(app)
    response = client.get("/embeddable")
    # Middleware forces its value
    assert response.headers["x-frame-options"] == "DENY"


def test_excluded_paths_skipped(create_app):
    app = create_app(excluded_paths=["/health", "/metrics"])

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    client = TestClient(app)
    response = client.get("/health")
    assert "x-content-type-options" not in response.headers
    assert "strict-transport-security" not in response.headers

    # Non-excluded still protected
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_streaming_response_unaffected(create_app):
    app = create_app()

    @app.get("/stream")
    async def stream():
        def gen():
            yield b"chunk1"
            yield b"chunk2"

        return StreamingResponse(gen(), media_type="text/plain")

    client = TestClient(app)
    response = client.get("/stream")
    assert response.content == b"chunk1chunk2"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_websocket_passthrough(create_app):
    app = create_app()

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("hello")
        await websocket.close()

    client = TestClient(app)
    with client.websocket_connect("/ws") as websocket:
        data = websocket.receive_text()
        assert data == "hello"


def test_strip_server_headers(create_app):
    app = create_app(strip_server_headers=True)
    client = TestClient(app)
    response = client.get("/")
    assert "server" not in response.headers
    assert "x-powered-by" not in response.headers


def test_custom_headers_injected(create_app):
    from fastapi_security_headers import SecurityHeadersConfig

    config = SecurityHeadersConfig(
        custom_headers={"X-Custom-Header": "test-value"}
    )
    app = create_app(config=config)
    client = TestClient(app)
    response = client.get("/")
    assert response.headers["x-custom-header"] == "test-value"
