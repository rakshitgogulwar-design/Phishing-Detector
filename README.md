# PhishGuard: Enterprise Cybersecurity Phishing Detection & Threat Intelligence Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![LightGBM](https://img.shields.io/badge/Model-Calibrated%20LightGBM-brightgreen.svg)](https://lightgbm.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: OWASP Hardened](https://img.shields.io/badge/Security-OWASP%20Hardened-orange.svg)](#8-security-considerations--hardening)

**PhishGuard** is a modern, accurate, explainable, and production-ready cybersecurity web platform. It protects organizations and users against malicious zero-day phishing attacks, brand spoofing, subdomain cloaking, credential trapping, and social engineering communications (Email, SMS, WhatsApp, and social media DMs).

---

## Table of Contents
1. [Project Structure](#1-updated-project-structure)
2. [Source Code Overview](#2-modified-source-code-overview)
3. [Database Schema & Migrations](#3-database-schema--migrations)
4. [Machine Learning Training & Inference](#4-machine-learning-training--inference)
5. [API Documentation & Endpoints](#5-api-documentation--endpoints)
6. [Environment Variables](#6-environment-variables)
7. [Test Suite Instructions](#7-test-suite-instructions)
8. [Security Considerations & Hardening](#8-security-considerations--hardening)
9. [Installation Instructions](#9-installation-instructions)
10. [Local Development Instructions](#10-local-development-instructions)
11. [Production Deployment Instructions](#11-production-deployment-instructions)
12. [Detection Architecture Deep Dive](#12-explanation-of-the-detection-architecture)
13. [Known Limitations & Future Improvements](#13-known-limitations--future-improvements)

---

## 1. Updated Project Structure

```text
Phishing-Detector/
├── .env.example                     # Production environment configuration template
├── .gitignore                       # Repository ignore rules (excludes *.db, .venv, etc.)
├── README.md                        # Enterprise platform documentation & handbook
├── requirements.txt                 # Pinned Python package dependencies
├── run_experiments.py               # ML cross-validation & benchmark pipeline
├── test_live_urls.py                # 41-target live legitimate & phishing benchmark
├── app/
│   ├── backend/
│   │   ├── database.py              # SQLite persistence (scans, feedback, settings)
│   │   ├── main.py                  # FastAPI server with security headers & rate limiting
│   │   └── schemas.py               # Pydantic request/response validation schemas
│   └── frontend/
│       ├── app.js                   # Single Page Application controller
│       ├── index.html               # Semantic HTML5 dashboard & multi-view interface
│       └── style.css                # Dark cybersecurity design system (vanilla CSS)
├── data/
│   ├── dataset.csv                  # UCI Phishing Websites research dataset
│   └── phishguard.db                # SQLite database (auto-initialized on first run)
├── models/
│   ├── baseline_rf.joblib           # Baseline Random Forest model artifact
│   └── proposed_champion.joblib     # Calibrated LightGBM champion model artifact
├── src/
│   ├── baseline_model.py            # Baseline model pipeline implementation
│   ├── explainability.py            # SHAP & feature importance security explainer
│   ├── feature_extractor.py         # 30 multi-modal lexical & structural feature extractor
│   ├── proposed_model.py            # Champion LightGBM & Stacking ensemble pipeline
│   └── detection/
│       ├── hybrid_engine.py         # Multi-signal fusion engine (Rules + ML + Intel)
│       ├── text_analyzer.py         # Social engineering & communication threat parser
│       ├── threat_intel.py          # Brand dictionaries & high-abuse TLD surveillance
│       └── url_analyzer.py          # Passive lexical rules engine (20+ indicators)
└── tests/
    ├── test_phishguard_api.py       # API integration, CRUD, and engine unit tests
    ├── test_pipeline.py             # Feature extractor and ML zero-leakage pipeline tests
    └── test_security.py             # OWASP security, XSS, SQLi, payload, and rate limit tests
```

---

## 2. Modified Source Code Overview

- **`src/detection/threat_intel.py`**: Curates 30+ enterprise brand profiles (Google, PayPal, Chase, Apple, Netflix, Microsoft, Amazon, Bank of America, Binance, MetaMask, etc.) and 40+ high-abuse TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.ru`, `.click`, `.buzz`, `.info`). Performs homoglyph and typosquatting detection.
- **`src/detection/url_analyzer.py`**: Executes zero-exposure passive lexical inspection on URLs without sending browser traffic to hostile hosts. Evaluates 20+ checks including length, entropy, IP in hostname, `@` symbol credential traps, multiple subdomains, unassigned ports, and sensitive keywords (`signin`, `verify`, `update`, `banking`, `wallet`).
- **`src/detection/text_analyzer.py`**: Natural language heuristic parser for email, SMS, and messaging attacks. Flags psychological urgency, fake prizes, OTP/password harvest attempts, and automatically extracts and evaluates embedded links.
- **`src/detection/hybrid_engine.py`**: Fuses Rules (35%), ML (45%), and Threat Intel (20%) into a normalized 0–100 risk score with boundary overrides (e.g. verified domains capped at $\le 10\%$, verified brand spoofing elevated to $\ge 85\%$). Produces transparent Pass/Fail factor checklists.
- **`app/backend/database.py`**: Thread-safe SQLite persistence layer managing `scans`, `feedback`, and `settings` tables with parameterized SQL queries, live text search, risk tier filtering, pagination, and CSV/JSON export.
- **`app/backend/main.py`**: Enterprise FastAPI backend featuring OWASP security headers (CSP, HSTS, X-Frame-Options, nosniff), in-memory client rate limiting (HTTP 429), and backwards-compatible legacy endpoints (`/api/analyze`, `/api/presets`).
- **`app/frontend/`**: Complete vanilla web client (HTML, CSS, JS) delivering a dark cybersecurity aesthetic with glassmorphism, responsive sidebar navigation, Chart.js visualizer, copyable security reports, and false-positive modal.

---

## 3. Database Schema & Migrations

PhishGuard stores persistent records in `data/phishguard.db` (auto-migrated and initialized on startup via `app/backend/database.py`).

### Schema Definition

```sql
-- 1. Scan Records Table
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,                -- 'url' or 'message'
    target TEXT NOT NULL,                   -- Target URL or message snippet
    status TEXT NOT NULL,                   -- 'SAFE', 'SUSPICIOUS', or 'PHISHING'
    risk_score INTEGER NOT NULL,            -- Continuous 0 to 100
    confidence REAL NOT NULL,               -- 0.0 to 1.0
    reasons TEXT NOT NULL,                  -- JSON serialized list of reason strings
    recommendation TEXT,                    -- Actionable cybersecurity guidance
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. User Feedback / Misclassification Reports
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,                        -- Foreign key reference to scans.id
    target TEXT NOT NULL,
    feedback_type TEXT NOT NULL,            -- 'false_positive', 'false_negative', 'other'
    comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Dynamic Engine Settings
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## 4. Machine Learning Training & Inference

PhishGuard implements an academic-grade ML pipeline trained on the UCI Phishing Websites benchmark dataset.

### Training Pipeline (`run_experiments.py`)
- **Multi-Modal Feature Extraction**: Extracts 30 features per sample spanning lexical structure, domain properties, and simulated security attributes.
- **Zero-Day Generalization**: Splits data using `StratifiedGroupKFold(n_splits=5)` grouped on registered domain names, guaranteeing that test folds contain zero domain overlap with training folds.
- **Model Ensembles Evaluated**:
  - Baseline Random Forest (14 features)
  - Baseline Logistic Regression, Decision Tree, Naïve Bayes, K-NN
  - Proposed Calibrated LightGBM (Champion)
  - Proposed Stacking Classifier (LGBM + XGBoost + Random Forest)
- **Probability Calibration**: Fitted with Platt scaling / Isotonic regression yielding a Brier calibration loss of **0.018**, ensuring output probabilities directly reflect true empirical risk.

### Retraining Instructions
```powershell
.venv\Scripts\python.exe run_experiments.py
```
Outputs trained weights to `models/proposed_champion.joblib` and prints validation metrics.

---

## 5. API Documentation & Endpoints

| Method | Endpoint | Description | Request Body | Response |
|---|---|---|---|---|
| `POST` | `/api/scan-url` | Multi-signal URL threat inspection | `{"url": "...", "html_content": null}` | `ScanResponse` (0–100 score, status, checklist) |
| `POST` | `/api/scan-message` | Email / SMS social engineering parser | `{"message": "..."}` | `ScanResponse` (score, categories, embedded links) |
| `GET` | `/api/history` | Paginated SQLite scan history | `?search=...&status_filter=...` | `{"scans": [...], "total_count": 42}` |
| `DELETE` | `/api/history/{id}` | Delete individual scan entry | None | `{"deleted": true, "id": 12}` |
| `DELETE` | `/api/history` | Clear all scan history | None | `{"deleted": true}` |
| `GET` | `/api/history/export` | Download scan history | `?format=csv` or `?format=json` | File download attachment |
| `GET` | `/api/statistics` | Analytical security metrics & charts | None | `StatisticsResponse` (safe/suspicious/phish counts) |
| `POST` | `/api/feedback` | Report false positive / negative | `{"target": "...", "feedback_type": "..."}` | `{"id": 1, "status": "recorded"}` |
| `GET` | `/api/settings` | Retrieve hybrid engine weights | None | `{"weight_rules": 0.35, "weight_ml": 0.45, ...}` |
| `POST` | `/api/settings` | Save updated engine weights | `{"weight_rules": 0.4, ...}` | `{"saved": true}` |
| `GET` | `/api/presets` | Pre-configured attack samples | None | Array of preset threat objects |
| `GET` | `/api/health` | Service health & model status | None | `{"status": "healthy", "version": "3.0.0"}` |

---

## 6. Environment Variables

Create a `.env` file from `.env.example`:

```ini
# Environment Mode
PHISHGUARD_ENV=production
PHISHGUARD_HOST=0.0.0.0
PHISHGUARD_PORT=8000
PHISHGUARD_DEBUG=false

# In-Memory Rate Limiting
# Maximum allowable scan requests per IP per minute
PHISHGUARD_RATE_LIMIT=120

# Database Storage Location
PHISHGUARD_DB_PATH=data/phishguard.db

# Default Hybrid Detection Weights (Must sum to 1.0)
DEFAULT_WEIGHT_RULES=0.35
DEFAULT_WEIGHT_ML=0.45
DEFAULT_WEIGHT_INTEL=0.20

# Passive Inspection Timeout
FEATURE_EXTRACTION_TIMEOUT=0.8
```

---

## 7. Test Suite Instructions

Run all test suites locally with pytest:

```powershell
# Run the entire test suite (API, ML pipeline, and Security)
.venv\Scripts\python.exe -m pytest -v

# Run only security and hardening tests
.venv\Scripts\python.exe -m pytest tests/test_security.py -v

# Run the 41-target live benchmark (Legitimate vs Zero-Day Attacks)
.venv\Scripts\python.exe test_live_urls.py
```

---

## 8. Security Considerations & Hardening

1. **Zero-Exposure Passive Inspection**: PhishGuard evaluates URLs strictly using lexical parsing and DNS/TLD lookup without downloading external JavaScript payloads, protecting the host machine from browser drive-by exploits.
2. **HTTP Security Headers**:
   - `Content-Security-Policy`: Disallows unauthorized external scripts and framing.
   - `X-Frame-Options: DENY`: Prevents Clickjacking attacks.
   - `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing exploits.
   - `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer leakage.
3. **Input Sanitization & Boundary Defense**: Pydantic schemas enforce length bounds ($4,096$ characters for URLs, $50,000$ for messages) to neutralize memory exhaustion attempts.
4. **SQL Injection Neutralization**: All database operations use SQLite parameterized binding (`?`).
5. **Client Rate Limiting**: In-memory token bucket limits requests to 120 per minute per IP address, preventing denial-of-service abuse.
6. **Privacy Guarantee**: Passwords, credit card numbers, and OTP tokens submitted in messages are never logged or stored in database tables.

---

## 9. Installation Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.14
- Modern web browser (Chrome, Edge, Firefox, or Safari)

### Setup
```powershell
# 1. Clone the repository
git clone https://github.com/rakshitgogulwar-design/Phishing-Detector.git
cd Phishing-Detector

# 2. Initialize Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install required dependencies
pip install -r requirements.txt
```

---

## 10. Local Development Instructions

Start the FastAPI backend with live automatic reload:
```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Open **[http://localhost:8000/](http://localhost:8000/)** in your web browser.

---

## 11. Production Deployment Instructions

### Linux Production Deployment (Systemd + Uvicorn)

1. **Install Gunicorn / Uvicorn in virtual environment:**
   ```bash
   pip install uvicorn gunicorn
   ```

2. **Create Systemd Service (`/etc/systemd/system/phishguard.service`):**
   ```ini
   [Unit]
   Description=PhishGuard Cyber Phishing Detection Service
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/var/www/Phishing-Detector
   Environment="PATH=/var/www/Phishing-Detector/.venv/bin"
   ExecStart=/var/www/Phishing-Detector/.venv/bin/gunicorn app.backend.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable & Start Service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now phishguard
   ```

4. **Nginx Reverse Proxy Configuration:**
   ```nginx
   server {
       listen 80;
       server_name phishguard.yourcompany.com;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

---

## 12. Explanation of the Detection Architecture

```text
                       Incoming URL / Text Target
                                  │
                                  ▼
                         Input Validation & 
                       Length Boundary Defense
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
 1. Passive Rules         2. Calibrated ML        3. Threat Intelligence
    - Length & Entropy       - 30 Features           - 30+ Protected Brands
    - IP in Host             - LightGBM Ensemble     - 40+ Malicious TLDs
    - Subdomains & Ports     - Platt Calibration     - Homoglyph Detection
         │                        │                        │
         │ (Weight: 35%)          │ (Weight: 45%)          │ (Weight: 20%)
         └────────────────────────┼────────────────────────┘
                                  ▼
                        Hybrid Fusion Aggregator
                                  │
                       Override Verification:
                 - Verified Domain: Risk <= 10%
                 - Brand Spoofing:  Risk >= 85%
                                  │
                                  ▼
                         0 – 100 Risk Score
                                  │
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
            SAFE             SUSPICIOUS            PHISHING
          (0 – 30)            (31 – 60)           (61 – 100)
```

The system overcomes single-point failures by uniting heuristic rules, zero-day machine learning, and brand threat intelligence.

---

## 13. Known Limitations & Future Improvements

1. **Shortened URL Deep Unmasking**: Currently identifies URL shorteners (e.g. `bit.ly`, `tinyurl.com`) as suspicious anomalies. Future work can incorporate safe sandbox HEAD request redirection unraveling.
2. **Computer Vision Screenshot Analysis**: Adding lightweight OCR/logo recognition (e.g. comparing page screenshots to legitimate brand logos) will provide visual impersonation proof.
3. **Automated Threat Feed Syncing**: Future releases will support automated daily ingestion of PhishTank, OpenPhish, and URLhaus threat feeds.
4. **Browser Extension Integration**: Creating a lightweight Chrome/Firefox MV3 extension communicating directly with the `/api/scan-url` API.

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
