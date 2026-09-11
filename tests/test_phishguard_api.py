"""
Automated Integration and Unit Tests for PhishGuard Enterprise API & Detection Engine
"""

import pytest
from fastapi.testclient import TestClient
from app.backend.main import app
from src.detection.threat_intel import ThreatIntel
from src.detection.url_analyzer import URLAnalyzer
from src.detection.text_analyzer import TextAnalyzer
from src.detection.hybrid_engine import HybridDetectionEngine


@pytest.fixture
def client():
    return TestClient(app)


def test_threat_intel():
    assert ThreatIntel.is_trusted_domain("google.com") is True
    assert ThreatIntel.is_trusted_domain("malicious-fake-site.tk") is False
    assert ThreatIntel.is_high_risk_tld("tk") is True
    assert ThreatIntel.is_high_risk_tld("org") is False
    assert ThreatIntel.is_url_shortener("bit.ly") is True

    # Brand spoofing test
    spoofed, auth = ThreatIntel.check_brand_spoofing(
        "http://chase-security-update.com.banking-auth-portal.tk",
        "banking-auth-portal.tk",
        "chase-security-update.com.banking-auth-portal.tk"
    )
    assert spoofed == "chase"
    assert auth == "chase.com"


def test_url_analyzer_safe_and_phish():
    analyzer = URLAnalyzer()

    # Safe Google
    res_safe = analyzer.analyze("https://www.google.com")
    assert res_safe["rule_score"] < 30.0
    assert res_safe["status"] == "SAFE"

    # Phish Raw IP
    res_phish = analyzer.analyze("http://192.168.1.105:8080/auth/paypal/verify-account")
    assert res_phish["rule_score"] >= 61.0
    assert res_phish["status"] == "PHISHING"
    assert any("Raw IP" in f["indicator"] for f in res_phish["failed_indicators"])


def test_text_analyzer_safe_and_phish():
    analyzer = TextAnalyzer()

    # Safe message
    msg_safe = "Hey team, the sprint planning meeting is at 2 PM in conference room B."
    res_safe = analyzer.analyze(msg_safe)
    assert res_safe["status"] == "SAFE"
    assert res_safe["risk_score"] < 30.0

    # Phishing urgent credential lure
    msg_phish = "URGENT ACTION REQUIRED: Your bank account will be suspended within 24 hours. Enter your password and OTP immediately to verify your identity."
    res_phish = analyzer.analyze(msg_phish)
    assert res_phish["status"] == "PHISHING"
    assert res_phish["risk_score"] >= 61.0
    assert "Artificial Urgency & Intimidation" in res_phish["categories_flagged"]
    assert "Credential / OTP Harvesting" in res_phish["categories_flagged"]


def test_api_scan_url(client):
    # 1. Safe scan
    res = client.post("/api/scan-url", json={"url": "https://www.google.com", "save_to_history": True})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SAFE"
    assert data["risk_score"] <= 30
    assert data["id"] is not None
    assert "components" in data
    assert "checklist" in data

    # 2. Phishing scan
    res_phish = client.post("/api/scan-url", json={
        "url": "http://chase-security-update.com.banking-auth-portal.tk/login.php",
        "save_to_history": True
    })
    assert res_phish.status_code == 200
    data_p = res_phish.json()
    assert data_p["status"] == "PHISHING"
    assert data_p["risk_score"] >= 61


def test_api_scan_message(client):
    res = client.post("/api/scan-message", json={
        "message": "CONGRATULATIONS! You won a $1,000,000 cash prize. Click http://bit.ly/claim-prize-now immediately to claim your money!",
        "save_to_history": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["SUSPICIOUS", "PHISHING"]
    assert data["risk_score"] >= 31
    assert len(data["categories_flagged"]) >= 1


def test_api_history_crud_and_export(client):
    # Get history
    res = client.get("/api/history?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "scans" in data
    assert data["total_count"] >= 1
    first_id = data["scans"][0]["id"]

    # Export CSV
    res_csv = client.get("/api/history/export?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "Risk Score" in res_csv.text

    # Export JSON
    res_json = client.get("/api/history/export?format=json")
    assert res_json.status_code == 200
    assert isinstance(res_json.json(), list)

    # Delete single scan
    res_del = client.delete(f"/api/history/{first_id}")
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "success"


def test_api_statistics(client):
    res = client.get("/api/statistics")
    assert res.status_code == 200
    stats = res.json()
    assert "total_scans" in stats
    assert "safe_percentage" in stats
    assert "phishing_percentage" in stats
    assert "recent_scans" in stats
    assert stats["total_scans"] >= 1


def test_api_feedback_and_settings(client):
    # Feedback
    res_fb = client.post("/api/feedback", json={
        "target": "https://example.com",
        "reported_as": "false_positive",
        "comments": "This is an internal development test page."
    })
    assert res_fb.status_code == 200
    assert res_fb.json()["status"] == "success"

    # Settings GET
    res_set = client.get("/api/settings")
    assert res_set.status_code == 200
    settings = res_set.json()
    assert "weight_rules" in settings

    # Settings POST
    res_up = client.post("/api/settings", json={
        "weight_rules": 0.40,
        "weight_ml": 0.40,
        "weight_intel": 0.20
    })
    assert res_up.status_code == 200
    assert res_up.json()["status"] == "success"
