"""
tests/test_normalizer.py
========================
Testes unitários para o módulo de normalização de tráfego HTTP.
"""

from __future__ import annotations

import pytest

from trickster.utils.normalizer import (
    decode_body,
    decode_jwt_payload,
    extract_auth_tokens,
    extract_cookies,
    extract_jwt_tokens,
    extract_query_params,
    normalize_headers,
)


# ── normalize_headers ─────────────────────────────────────────────────────────

def test_normalize_headers_lowercases_keys():
    headers = {"Content-Type": "application/json", "X-API-KEY": "secret"}
    result = normalize_headers(headers)
    assert "content-type" in result
    assert "x-api-key" in result
    assert "Content-Type" not in result


def test_normalize_headers_empty():
    assert normalize_headers({}) == {}


# ── extract_query_params ──────────────────────────────────────────────────────

def test_extract_query_params_basic():
    url = "https://exemplo.com/search?q=test&page=1"
    params = extract_query_params(url)
    assert params["q"] == "test"
    assert params["page"] == "1"


def test_extract_query_params_no_params():
    url = "https://exemplo.com/home"
    assert extract_query_params(url) == {}


def test_extract_query_params_encoded():
    url = "https://exemplo.com/search?q=hello+world&filter=a%2Cb"
    params = extract_query_params(url)
    assert "q" in params


# ── extract_cookies ───────────────────────────────────────────────────────────

def test_extract_cookies_basic():
    header = "session=abc123; user_id=42"
    cookies = extract_cookies(header)
    assert cookies["session"] == "abc123"
    assert cookies["user_id"] == "42"


def test_extract_cookies_ignores_attributes():
    header = "token=xyz; Path=/; HttpOnly; SameSite=Strict"
    cookies = extract_cookies(header)
    assert "token" in cookies
    assert "path" not in cookies
    assert "httponly" not in cookies


def test_extract_cookies_empty():
    assert extract_cookies(None) == {}
    assert extract_cookies("") == {}


# ── extract_jwt_tokens ────────────────────────────────────────────────────────

_SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_extract_jwt_tokens_finds_jwt():
    text = f"Authorization: Bearer {_SAMPLE_JWT}"
    tokens = extract_jwt_tokens(text)
    assert len(tokens) == 1
    assert tokens[0] == _SAMPLE_JWT


def test_extract_jwt_tokens_no_jwt():
    tokens = extract_jwt_tokens("Authorization: Bearer simple-token-123")
    assert tokens == []


def test_extract_jwt_tokens_deduplicates():
    text = f"{_SAMPLE_JWT} {_SAMPLE_JWT}"
    tokens = extract_jwt_tokens(text)
    assert len(tokens) == 1


# ── decode_jwt_payload ────────────────────────────────────────────────────────

def test_decode_jwt_payload_valid():
    payload = decode_jwt_payload(_SAMPLE_JWT)
    assert payload is not None
    assert payload.get("sub") == "1234567890"
    assert payload.get("name") == "John Doe"


def test_decode_jwt_payload_invalid():
    result = decode_jwt_payload("not.a.jwt")
    assert result is None


# ── extract_auth_tokens ───────────────────────────────────────────────────────

def test_extract_auth_tokens_bearer():
    headers = {"authorization": "Bearer mytoken123"}
    tokens = extract_auth_tokens(headers)
    assert "mytoken123" in tokens


def test_extract_auth_tokens_basic():
    import base64
    creds = base64.b64encode(b"user:pass").decode()
    headers = {"authorization": f"Basic {creds}"}
    tokens = extract_auth_tokens(headers)
    # Basic tokens são prefixados com "BASIC:"
    assert any("BASIC:" in t for t in tokens)


def test_extract_auth_tokens_no_auth():
    headers = {"content-type": "application/json"}
    tokens = extract_auth_tokens(headers)
    assert tokens == []


# ── decode_body ───────────────────────────────────────────────────────────────

def test_decode_body_json():
    body = b'{"key": "value", "number": 42}'
    decoded, size = decode_body(body, "application/json")
    assert decoded is not None
    assert '"key"' in decoded
    assert size == len(body)


def test_decode_body_text():
    body = b"Hello, World!"
    decoded, size = decode_body(body, "text/plain")
    assert decoded == "Hello, World!"
    assert size == 13


def test_decode_body_truncation():
    body = b"A" * 20000
    decoded, size = decode_body(body, "text/plain", max_size=10240)
    assert decoded is not None
    assert "TRUNCADO" in decoded
    assert size == 20000


def test_decode_body_empty():
    decoded, size = decode_body(None, "text/plain")
    assert decoded is None
    assert size == 0


# ── Tests de integração básica dos modelos ────────────────────────────────────

def test_http_request_model():
    from trickster.utils.models import HttpRequest

    req = HttpRequest(
        session_id="test-session",
        url="https://exemplo.com/api/users?page=1",
        method="get",  # deve ser normalizado para GET
        headers={"Authorization": "Bearer token123"},
    )
    assert req.method == "GET"
    assert req.is_https is True
    assert req.domain == "exemplo.com"
    assert req.path == "/api/users"


def test_http_response_model():
    from trickster.utils.models import HttpResponse

    resp = HttpResponse(
        request_id="req-123",
        session_id="test-session",
        status_code=200,
    )
    assert resp.is_success is True
    assert resp.is_error is False
    assert resp.is_redirect is False


def test_finding_severity_enum():
    from trickster.utils.models import Severity

    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.INFORMATIONAL.value == "informational"

