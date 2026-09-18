# 🛡️ FastAPI Security Headers

[![CI](https://github.com/aletgdev/fastapi-security-headers/actions/workflows/ci.yml/badge.svg)](https://github.com/aletgdev/fastapi-security-headers/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/fastapi-security-headers?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/fastapi-security-headers/)
[![Python versions](https://img.shields.io/pypi/pyversions/fastapi-security-headers?logo=python&logoColor=white)](https://pypi.org/project/fastapi-security-headers/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://github.com/aletgdev/fastapi-security-headers)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-FF5E5B?logo=kofi&logoColor=white)](https://ko-fi.com/alejandrotg)

**The missing security headers middleware for FastAPI.** Protect your API against XSS, clickjacking, MIME sniffing, and OWASP Top 10 web vulnerabilities with secure-by-default configurations and zero overhead.

---

## ⚡ Highlights

* **🚀 Zero Performance Overhead (Pure ASGI):** Bypasses heavy Starlette wrappers. Injects headers directly into ASGI raw message streams without body buffering.
* **📦 Zero Dependencies:** Uses only Python's standard library (`dataclasses`, `typing`). Zero bloat in your dependency tree.
* **⚡ Pre-compiled Bytes:** Header tuples are encoded to `(bytes, bytes)` once at application startup, running in nanoseconds per request.
* **🎛️ Out-of-the-box Presets:** Ready-made configurations for APIs, high-compliance environments, and mixed apps.
* **📖 Swagger / ReDoc Friendly:** Includes a dedicated preset that **won't break your interactive `/docs` documentation**.
* **🔄 Route-Aware:** Intelligently respects custom headers set by individual route handlers unless explicitly configured to override.
* **🌐 WebSockets & Streaming Safe:** Passes WebSockets and large streaming responses (`StreamingResponse`) seamlessly.

---

## 📦 Installation

```bash
pip install fastapi-security-headers
```

---

## 🚀 Quickstart (30 Seconds)

Add the middleware to your FastAPI application in just 2 lines of code:

```python
from fastapi import FastAPI
from fastapi_security_headers import SecurityHeadersMiddleware

app = FastAPI()

# Enable OWASP recommended security headers with secure defaults
app.add_middleware(SecurityHeadersMiddleware)

@app.get("/")
async def root():
    return {"message": "Protected by fastapi-security-headers"}
```

---

## 🛡️ The Security Headers Matrix

By default, `fastapi-security-headers` turns an **F** score on security scanners into an **A+**:

| HTTP Header | Default Value | Attack Vector Mitigated |
| :--- | :--- | :--- |
| **`X-Content-Type-Options`** | `nosniff` | **MIME-Sniffing:** Prevents browsers from guessing content types, blocking malicious scripts disguised as images or JSON. |
| **`X-Frame-Options`** | `DENY` | **Clickjacking:** Prevents external sites from embedding your API inside hidden `<iframe>` overlays. |
| **`X-XSS-Protection`** | `0` | **Audit Vulnerabilities:** Disables legacy buggy XSS filters as recommended by OWASP. |
| **`Strict-Transport-Security`** | `max-age=31536000; includeSubDomains` | **SSL Stripping / MitM:** Enforces HTTPS for all future visits over the next 365 days. |
| **`Referrer-Policy`** | `strict-origin-when-cross-origin` | **Data Leakage:** Prevents leaking sensitive URL query parameters to third-party domains. |
| **`Permissions-Policy`** | `geolocation=(), microphone=(), camera=()` | **Feature Abuse:** Disables unused device APIs (GPS, camera, microphone). |
| **`Cross-Origin-Opener-Policy`** | `same-origin` | **Side-Channel Attacks:** Isolates browsing context against Spectre-style attacks. |
| **`Cross-Origin-Resource-Policy`**| `same-origin` | **Cross-Origin Reads:** Blocks external origins from reading your API responses. |

---

## 🎛️ Built-in Presets

### 1. `Presets.swagger_friendly()` (Recommended for FastAPI)
Enforces strict Content Security Policy (CSP) while allowing necessary CDNs (`cdn.jsdelivr.net`) and assets for Swagger UI (`/docs`) and ReDoc (`/redoc`).

```python
from fastapi import FastAPI
from fastapi_security_headers import SecurityHeadersMiddleware, Presets

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware, config=Presets.swagger_friendly())
```

### 2. `Presets.api()` (For Headless JSON APIs)
Hardened specifically for pure JSON microservices. Disallows all frames, scripts, and media loading:

```python
app.add_middleware(SecurityHeadersMiddleware, config=Presets.api())
```

### 3. `Presets.strict()` (High-Compliance / Banking)
Maximum security posture for financial, health, and enterprise apps. Enforces 2-year HSTS with preload, `require-corp`, and strict CSP:

```python
app.add_middleware(SecurityHeadersMiddleware, config=Presets.strict())
```

### 4. `Presets.default()`
Balanced baseline for general web applications.

---

## 🔧 Custom Configuration

You can fully customize headers or disable any specific header by setting it to `None`:

```python
from fastapi import FastAPI
from fastapi_security_headers import SecurityHeadersMiddleware, SecurityHeadersConfig, HSTSConfig

config = SecurityHeadersConfig(
    # Customize HSTS (e.g. disable on localhost or enable preload)
    strict_transport_security=HSTSConfig(max_age=63072000, include_subdomains=True, preload=True),
    # Allow iframes from the same origin
    x_frame_options="SAMEORIGIN",
    # Add custom enterprise security headers
    custom_headers={
        "X-Permitted-Cross-Domain-Policies": "none",
    }
)

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware, config=config)
```

### Route-Level Overrides

By default (`override=False`), if a specific endpoint returns its own custom header, the middleware respects it and does not duplicate it:

```python
from fastapi.responses import JSONResponse

@app.get("/embeddable-widget")
async def widget():
    # This endpoint specifically permits embedding
    return JSONResponse(
        content={"data": "widget"},
        headers={"x-frame-options": "SAMEORIGIN"}
    )
```

To force middleware headers across **all** endpoints regardless of route return values, set `override=True`:

```python
app.add_middleware(SecurityHeadersMiddleware, override=True)
```

---

## 🧪 Testing

Run the test suite locally with `pytest`:

```bash
pip install -e ".[dev]"
pytest -v
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/aletgdev/fastapi-security-headers/issues).

---

## 👤 Author

**Alejandro Tacoronte González**

* GitHub: [@aletgdev](https://github.com/aletgdev)
* LinkedIn: [Alejandro Tacoronte](https://www.linkedin.com/in/alejandrotacoronte/)
* Portfolio: [portfolio.alejandrotg.es](https://portfolio.alejandrotg.es/)

If this project helps you secure your FastAPI applications, consider buying a coffee! ☕

[![Ko-fi](https://img.shields.io/badge/Support%20on-Ko--fi-FF5E5B?style=for-the-badge&logo=kofi&logoColor=white)](https://ko-fi.com/alejandrotg)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
