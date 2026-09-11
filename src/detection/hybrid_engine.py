"""
PhishGuard Hybrid Detection Engine
Fuses Rule-Based Analysis (35%), Machine Learning (45%), and Threat Intelligence (20%)
into a single, robust, and transparent 0 - 100 cybersecurity risk score.
Weights are fully configurable.
"""

from typing import Dict, Any, List, Optional
import pandas as pd

from src.detection.url_analyzer import URLAnalyzer
from src.detection.threat_intel import ThreatIntel
from src.proposed_model import ProposedMultiModalPipeline
from src.feature_extractor import MultiModalFeatureExtractor


class HybridDetectionEngine:
    """
    Fuses Rule-Based, Machine Learning, and Threat Intelligence signals.
    """

    def __init__(
        self,
        weight_rules: float = 0.35,
        weight_ml: float = 0.45,
        weight_intel: float = 0.20,
        model_path: str = "models/proposed_champion.joblib"
    ):
        total_w = weight_rules + weight_ml + weight_intel
        self.w_rules = weight_rules / total_w
        self.w_ml = weight_ml / total_w
        self.w_intel = weight_intel / total_w

        self.url_analyzer = URLAnalyzer()
        self.feature_extractor = MultiModalFeatureExtractor(timeout=0.8)

        self.ml_model: Optional[ProposedMultiModalPipeline] = None
        try:
            self.ml_model = ProposedMultiModalPipeline.load(model_path)
        except Exception:
            self.ml_model = None

    def update_weights(self, weight_rules: float, weight_ml: float, weight_intel: float):
        """Updates hybrid weighting coefficients dynamically."""
        total_w = max(0.01, weight_rules + weight_ml + weight_intel)
        self.w_rules = weight_rules / total_w
        self.w_ml = weight_ml / total_w
        self.w_intel = weight_intel / total_w

    def analyze_url(self, raw_url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes hybrid inspection across Rules, ML, and Threat Intelligence.
        Returns final 0 - 100 risk score, status, confidence, and checklist.
        """
        raw_url = raw_url.strip()
        if not raw_url:
            return {
                "risk_score": 0,
                "status": "SAFE",
                "risk_tier": "SAFE",
                "confidence": 0.95,
                "reasons": ["Empty target URL supplied."],
                "recommendation": "Please provide a valid URL to inspect.",
                "checklist": []
            }

        # 1. Rule-Based Analysis
        rule_result = self.url_analyzer.analyze(raw_url)
        rule_score = rule_result["rule_score"]  # 0 to 100
        threat_intel = rule_result["threat_intel"]
        threat_score = threat_intel["threat_score"]  # 0 to 100

        # 2. Machine Learning Pipeline Inference
        ml_score = 50.0
        ml_confidence = 0.50
        if self.ml_model:
            try:
                extracted = self.feature_extractor.extract_all(raw_url, html_content=html_content)
                df_feat = pd.DataFrame([extracted["features"]])
                raw_prob = float(self.ml_model.predict_proba(df_feat)[0, 1])
                ml_score = raw_prob * 100.0
                ml_confidence = max(raw_prob, 1.0 - raw_prob)
            except Exception:
                ml_score = rule_score
                ml_confidence = 0.70
        else:
            ml_score = rule_score
            ml_confidence = 0.70

        # 3. Hybrid Synthesis Calculation
        synthesized_score = (
            (self.w_rules * rule_score) +
            (self.w_ml * ml_score) +
            (self.w_intel * threat_score)
        )

        # 4. Authority & Severe Signature Boundary Overrides
        is_trusted = threat_intel.get("is_trusted", False)
        spoofed_brand = threat_intel.get("spoofed_brand")

        if is_trusted and not spoofed_brand:
            # Genuine top-tier domain: guaranteed safe ceiling
            final_score = min(20.0, max(2.0, (synthesized_score * 0.20)))
        elif spoofed_brand:
            # Blatant brand impersonation: floor at critical threshold
            final_score = max(82.0, min(99.0, synthesized_score))
        elif rule_result["metrics"]["is_raw_ip"]:
            # Direct numeric IP: floor at high risk
            final_score = max(80.0, min(99.0, synthesized_score))
        else:
            final_score = max(2.0, min(99.0, synthesized_score))

        final_score_int = int(round(final_score))

        # 5. Standardized 3-Tier Classification
        # 0–30 = SAFE, 31–60 = SUSPICIOUS, 61–100 = HIGH RISK / PHISHING
        if final_score_int >= 61:
            status = "PHISHING"
            risk_tier = "HIGH RISK"
            confidence = min(0.99, max(0.85, ml_confidence))
            recommendation = (
                "Do not enter passwords, OTPs, banking credentials, or personal identity information "
                "on this website. Disconnect immediately."
            )
        elif final_score_int >= 31:
            status = "SUSPICIOUS"
            risk_tier = "SUSPICIOUS"
            confidence = 0.80
            recommendation = (
                "Caution advised: this website exhibits elevated risk factors. "
                "Verify the domain independently before interacting."
            )
        else:
            status = "SAFE"
            risk_tier = "SAFE"
            confidence = min(0.98, max(0.90, ml_confidence))
            recommendation = (
                "Website displays authentic domain characteristics and security transport. "
                "Normal browsing hygiene is recommended."
            )

        # Compile explainable reasons list
        summary_reasons = []
        if rule_result["failed_indicators"]:
            for f in rule_result["failed_indicators"][:4]:
                summary_reasons.append(f["details"])
        elif rule_result["warning_indicators"]:
            for w in rule_result["warning_indicators"][:2]:
                summary_reasons.append(w["details"])
        else:
            summary_reasons.append("Clean URL structure with authenticated domain and standard protocol.")

        # Construct intuitive threat diagnostic explanation
        threat_explanation = ""
        if spoofed_brand:
            threat_explanation = (
                f"🚨 Critical Brand Impersonation Detected: This URL is actively spoofing {spoofed_brand.upper()}, "
                f"but the registered root domain is actually '{rule_result['metrics'].get('domain', 'unknown')}'. "
                f"Attackers use this technique to hijack login credentials."
            )
        elif rule_result["metrics"].get("is_raw_ip"):
            threat_explanation = (
                f"🚨 Direct Numeric IP Address Attack: The host '{rule_result['metrics'].get('hostname')}' bypasses "
                f"standard DNS domain registration, a technique heavily associated with rogue malware or credential harvesting servers."
            )
        elif threat_intel.get("is_high_risk_tld"):
            threat_explanation = (
                f"⚠️ Suspicious Top-Level Domain (.{rule_result['metrics'].get('tld')}): The URL is hosted on an extension "
                f"frequently exploited in automated disposable phishing campaigns."
            )
        elif rule_result["failed_indicators"]:
            threat_explanation = (
                f"⚠️ Suspicious URL Structure: Flagged {len(rule_result['failed_indicators'])} anomalous security indicator(s), "
                f"including {rule_result['failed_indicators'][0]['indicator']}."
            )
        else:
            threat_explanation = (
                f"✅ Verified & Clean Infrastructure: The domain '{rule_result['metrics'].get('domain')}' displays authenticated "
                f"domain ownership, standard encryption, and clean URL syntax."
            )

        url_breakdown = {
            "protocol": "HTTPS (Encrypted TLS)" if rule_result["metrics"].get("is_https") else "HTTP (Unencrypted / Insecure)",
            "hostname": rule_result["metrics"].get("hostname", ""),
            "domain": rule_result["metrics"].get("domain", ""),
            "subdomain": rule_result["metrics"].get("hostname", "").replace(rule_result["metrics"].get("domain", ""), "").rstrip(".") or "None (Apex Domain)",
            "tld": "." + rule_result["metrics"].get("tld", ""),
            "spoofed_brand": spoofed_brand.upper() if spoofed_brand else "None Detected",
            "is_trusted": threat_intel.get("is_trusted", False),
            "is_high_risk_tld": threat_intel.get("is_high_risk_tld", False),
            "is_raw_ip": rule_result["metrics"].get("is_raw_ip", False),
            "matched_keywords": rule_result["metrics"].get("matched_keywords", []),
            "threat_diagnosis": threat_explanation,
            "failed_count": len(rule_result["failed_indicators"]),
            "warning_count": len(rule_result["warning_indicators"]),
            "passed_count": len(rule_result["passed_indicators"])
        }

        return {
            "status": status,
            "risk_tier": risk_tier,
            "risk_score": final_score_int,
            "confidence": round(confidence, 2),
            "reasons": summary_reasons,
            "recommendation": recommendation,
            "rule_score": round(rule_score, 1),
            "ml_score": round(ml_score, 1),
            "threat_intel_score": round(threat_score, 1),
            "components": {
                "rule_score": round(rule_score, 1),
                "ml_score": round(ml_score, 1),
                "threat_intel_score": round(threat_score, 1),
                "weights_applied": {
                    "rules": round(self.w_rules, 2),
                    "ml": round(self.w_ml, 2),
                    "threat_intel": round(self.w_intel, 2)
                }
            },
            "url_breakdown": url_breakdown,
            "checklist": rule_result["checklist"],
            "failed_indicators": rule_result["failed_indicators"],
            "warning_indicators": rule_result["warning_indicators"],
            "passed_indicators": rule_result["passed_indicators"],
            "threat_intel": threat_intel,
            "metrics": rule_result["metrics"]
        }
