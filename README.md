# AegisPhish: Research-Grade Multi-Modal AI Phishing Detection & Explainability Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![LightGBM](https://img.shields.io/badge/Champion%20Model-LightGBM-brightgreen.svg)](https://lightgbm.readthedocs.io)

An intelligent, research-grade, and production-oriented phishing website detection platform that combines **Multi-Modal Feature Engineering** (URL Lexical + DNS/Domain + HTML/DOM Structure + Security/TLS) with **Calibrated Gradient Boosting & Stacking Ensembles** to achieve state-of-the-art detection and zero-day unseen domain generalization.

---

## 🎯 Research Objectives & Key Findings

### Research Question
> *"Can a carefully engineered multi-modal feature set combined with optimized machine learning models improve phishing website detection and generalization to previously unseen websites compared with a URL/domain-only baseline?"*

### Key Results
- **97.35% Reduction in Missed Phishing Attacks ($FNR$):** Baseline URL/Domain-only Random Forest had a $3.78\%$ False Negative Rate ($FNR$) on unseen test domains. The Proposed Multi-Modal Calibrated System reduced $FNR$ down to **$0.10\%$**.
- **Zero-Day Unseen Domain Generalization:** Under strict 5-Fold Domain-Grouped Cross-Validation (`StratifiedGroupKFold`), the proposed system sustained **$99.90\% \pm 0.07\%$ accuracy** and **$99.92\%$ recall** on completely unseen domain infrastructure.
- **Calibrated Probabilities:** Achieved a **$0.0008$ Brier calibration loss** using Platt probability scaling for enterprise SOC risk scoring.
- **Ultra-Low Latency:** Average inference time of **$0.03\text{ ms}$**.

---

## 📊 Empirical Comparison Matrix

| Model System | Feature Modalities | Accuracy | Recall (TPR) | False Negative Rate ($FNR$) | ROC-AUC | Brier Score | Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Proposed Champion (Calibrated LightGBM)** | **Full Multi-Modal (30 Feats + Cross-Interactions)** | **99.91%** | **99.90%** | **0.10%** | **1.0000** | **0.0008** | **0.03 ms** |
| **Proposed Stacking Ensemble** | Full Multi-Modal (LGBM + XGB + RF) | 99.95% | 100.00% | 0.00% | 1.0000 | 0.0005 | 0.15 ms |
| **Proposed Calibrated XGBoost** | Full Multi-Modal (30 Feats + Cross-Interactions) | 99.82% | 99.69% | 0.31% | 1.0000 | 0.0012 | 0.03 ms |
| **Baseline Random Forest (Reference Paper)** | URL & Domain Only (14 Feats) | 97.28% | 96.22% | 3.78% | 0.9967 | 0.0210 | 0.05 ms |
| **Baseline Logistic Regression** | URL & Domain Only (14 Feats) | 97.91% | 97.45% | 2.55% | 0.9982 | 0.0164 | 0.00 ms |
| **Baseline Decision Tree** | URL & Domain Only (14 Feats) | 95.55% | 95.00% | 5.00% | 0.9595 | 0.0445 | 0.00 ms |
| **Baseline Naïve Bayes** | URL & Domain Only (14 Feats) | 97.82% | 97.65% | 2.35% | 0.9978 | 0.0212 | 0.01 ms |
| **Baseline K-NN** | URL & Domain Only (14 Feats) | 97.59% | 96.63% | 3.37% | 0.9913 | 0.0226 | 0.14 ms |

---

## 🏛️ Architecture & Modalities

```
                     ┌──────────────────────────────────────────────┐
                     │              Target URL / HTML               │
                     └──────────────────────┬───────────────────────┘
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               ▼                                                         ▼
    ┌──────────────────────┐                                  ┌──────────────────────┐
    │  URL & Domain Feats  │                                  │  HTML/DOM & Security │
    ├──────────────────────┤                                  ├──────────────────────┤
    │ • IP Address in URL  │                                  │ • Server Form Handler│
    │ • Entropy & Depth    │                                  │ • Mismatched Anchors │
    │ • Subdomain Cloaking │                                  │ • Hidden IFrames     │
    │ • DNS / WHOIS Age    │                                  │ • SSL / TLS Trust    │
    └──────────┬───────────┘                                  └──────────┬───────────┘
               │                                                         │
               └────────────────────────────┬────────────────────────────┘
                                            │
                               ┌────────────▼────────────┐
                               │ Feature Engineering &   │
                               │ Interaction Transforms  │
                               └────────────┬────────────┘
                                            │
                               ┌────────────▼────────────┐
                               │ Calibrated LightGBM &   │
                               │ Stacking Ensemble       │
                               └────────────┬────────────┘
                                            │
                               ┌────────────▼────────────┐
                               │ Predictions + SHAP XAI  │
                               │ Security Diagnostics    │
                               └─────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Installation
```bash
# Clone repository
git clone https://github.com/rakshitgogulwar-design/Phishing-Detector.git
cd Phishing-Detector

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Experiments & Train Models
```bash
python run_experiments.py
```

### 3. Run Automated Tests
```bash
python -m pytest tests/test_pipeline.py -v
```

### 4. Launch Web Application
```bash
python -m uvicorn app.backend.main:app --reload --port 8000
```
Open **`http://localhost:8000`** in your browser.

---

## 🛡️ API Endpoints

- `POST /api/analyze`: Inspect any URL or HTML payload for live multi-modal detection, confidence calibration, and SHAP attribution.
- `GET /api/benchmark`: Fetch research benchmark statistics, ROC/PR curves, and domain-grouped CV scores.
- `GET /api/presets`: Retrieve curated attack vectors and legitimate site test cases.
- `GET /api/health`: System health check and model loading status.

---

## 📜 License
MIT License
