"""Pytest configuration and shared fixtures for fastapi-security-headers."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_security_headers import SecurityHeadersConfig, SecurityHeadersMiddleware


@pytest.fixture
def create_app():
    """Factory fixture to create a FastAPI application wrapped with SecurityHeadersMiddleware."""

    def _factory(
        config: SecurityHeadersConfig = None,
        override: bool = False,
        strip_server_headers: bool = None,
        excluded_paths=None,
    ) -> FastAPI:
        app = FastAPI()
        app.add_middleware(
            SecurityHeadersMiddleware,
            config=config,
            override=override,
            strip_server_headers=strip_server_headers,
            excluded_paths=excluded_paths,
        )

        @app.get("/")
        async def root():
            return {"message": "secure-hello"}

        @app.get("/custom-frame")
        async def custom_frame():
            from fastapi.responses import JSONResponse

            return JSONResponse(
                content={"message": "with-frame"},
                headers={"x-frame-options": "SAMEORIGIN"},
            )

        @app.get("/healthz")
        async def healthz():
            return {"status": "ok"}

        @app.get("/server-header")
        async def server_header():
            from fastapi.responses import JSONResponse

            return JSONResponse(
                content={"data": "ok"},
                headers={"Server": "uvicorn", "X-Powered-By": "FastAPI"},
            )

        return app

    return _factory


@pytest.fixture
def client(create_app):
    """Default TestClient using default SecurityHeadersConfig on HTTPS."""
    app = create_app()
    return TestClient(app, base_url="https://testserver")
