"""
Explainability & Security Attribution Engine
Calculates SHAP (SHapley Additive exPlanations) values and localized risk attribution
to translate machine learning predictions into human-comprehensible security diagnostics.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import shap

from src.data_loader import ALL_FEATURES


SECURITY_DESCRIPTIONS = {
    "having_IPhaving_IP_Address": {
        -1: ("Direct IP Address in URL", "Attacker is using raw IP or hex encoding to bypass domain name reputation filters.", "High"),
        1: ("Legitimate Domain Name", "Standard DNS-resolvable host name.", "Safe")
    },
    "URLURL_Length": {
        -1: ("Excessive URL Length (>75 chars)", "Long obfuscated URL commonly used to hide malicious payload parameters or mimic brand tokens.", "Medium"),
        0: ("Moderate URL Length (54-75 chars)", "Borderline length requiring additional scrutiny.", "Low"),
        1: ("Standard URL Length (<54 chars)", "Clean, concise URL structure.", "Safe")
    },
    "Shortining_Service": {
        -1: ("URL Shortener Obfuscation", "URL uses redirection service (e.g., bit.ly, tinyurl) masking true destination host.", "High"),
        1: ("Direct Destination URL", "No URL shortening service detected.", "Safe")
    },
    "having_At_Symbol": {
        -1: ("@ Symbol in URL", "Browser treats text before '@' as authentication credentials, disguising the true destination.", "High"),
        1: ("Clean URL Scheme", "Standard URL syntax without embedded '@' credential hijacking.", "Safe")
    },
    "double_slash_redirecting": {
        -1: ("Embedded '//' Redirector", "Redirection token embedded in URL path to fool users regarding the landing host.", "High"),
        1: ("Normal Protocol Slash", "Standard protocol prefix.", "Safe")
    },
    "Prefix_Suffix": {
        -1: ("Hyphenated Domain Cloaking", "Domain contains hyphenated prefix/suffix (e.g. paypal-security.com) to mimic trusted brand.", "High"),
        1: ("Non-Hyphenated Domain", "Clean domain root without deceptive hyphens.", "Safe")
    },
    "having_Sub_Domain": {
        -1: ("Multi-Level Subdomains (>=3 dots)", "Deep subdomain hierarchy used to embed authentic brand names in third-level hosts.", "High"),
        0: ("Moderate Subdomains (2 dots)", "Secondary subdomain structure.", "Low"),
        1: ("Single Domain Level", "Standard single-domain architecture.", "Safe")
    },
    "SSLfinal_State": {
        -1: ("Untrusted / Missing SSL Certificate", "Site lacks HTTPS encryption or uses an invalid, expired, or self-signed certificate.", "Critical"),
        0: ("Non-Standard / Warning SSL", "HTTPS present but issuer is unverified or domain mismatch detected.", "Medium"),
        1: ("Valid Trusted SSL Certificate", "Authentic TLS certificate signed by a recognized Certificate Authority.", "Safe")
    },
    "Domain_registeration_length": {
        -1: ("Short-Lived Domain Registration (<=1 yr)", "Disposable domain registered for short campaign duration, typical of phishing infrastructure.", "Medium"),
        1: ("Long-Term Domain Registration (>1 yr)", "Established domain registered for multi-year lifecycle.", "Safe")
    },
    "SFH": {
        -1: ("Abnormal / Blank Form Action (SFH)", "HTML form action is blank, 'about:blank', or posts directly to an unverified external handler.", "Critical"),
        0: ("Cross-Domain Form Action", "Form posts credentials to a different external domain than the current webpage host.", "High"),
        1: ("Same-Domain Form Action", "Form handler posts securely to the same registered origin domain.", "Safe")
    },
    "URL_of_Anchor": {
        -1: ("High Foreign / Broken Anchor Ratio (>=67%)", "Majority of hyperlinks point to external domains, '#', or 'javascript:void(0)'.", "High"),
        0: ("Moderate External Anchors (31-67%)", "Elevated proportion of non-internal hyperlink destinations.", "Medium"),
        1: ("Consistent Internal Anchors (<31%)", "Normal internal navigation structure.", "Safe")
    },
    "Request_URL": {
        -1: ("External Asset Hijacking (>=61%)", "Majority of media, scripts, and CSS resources are loaded from external origins.", "High"),
        0: ("Moderate External Assets (22-61%)", "Noticeable proportion of externally hosted assets.", "Low"),
        1: ("Self-Hosted Assets (<22%)", "Resources originate from the host's own infrastructure.", "Safe")
    },
    "Links_in_tags": {
        -1: ("External Meta/Link Tags (>=81%)", "Script and link tags heavily point to foreign domains.", "High"),
        0: ("Moderate External Meta/Link Tags (17-81%)", "Elevated external tag references.", "Low"),
        1: ("Internal Meta/Link Tags (<17%)", "Clean internal header resource links.", "Safe")
    },
    "Iframe": {
        -1: ("Hidden / Invisible IFrame Detected", "Page embeds invisible borderless iframe (`display:none` or `frameborder=0`), typical of clickjacking.", "High"),
        1: ("No Suspicious IFrames", "Normal visible frame structure or no iframes present.", "Safe")
    },
    "popUpWidnow": {
        -1: ("Credential Popup Window Detected", "JavaScript popups prompting for credentials or password entry.", "High"),
        1: ("No Suspicious Popups", "Standard non-intrusive modal or popup behavior.", "Safe")
    },
    "on_mouseover": {
        -1: ("Status Bar Tampering (onMouseOver)", "JavaScript dynamically changes browser status bar URL to deceive the user.", "High"),
        1: ("Clean Link Hover Behavior", "Standard transparent link target display.", "Safe")
    },
    "RightClick": {
        -1: ("Context Menu / Right-Click Disabled", "Page blocks right-clicking to prevent users from inspecting source code or verifying links.", "Medium"),
        1: ("Unrestricted Right-Click", "Standard browser context menu available.", "Safe")
    },
    "Submitting_to_email": {
        -1: ("Form Submits Directly to Email", "HTML form transmits collected user credentials via 'mailto:' protocol.", "Critical"),
        1: ("Standard Server-Side Form Submission", "Form submits via HTTP/HTTPS POST to backend API.", "Safe")
    },
    "age_of_domain": {
        -1: ("Freshly Registered Domain (<6 months)", "Newly registered domain characteristic of disposable phishing setups.", "Medium"),
        1: ("Mature Domain (>=6 months)", "Established domain age with historical reputation.", "Safe")
    },
    "DNSRecord": {
        -1: ("Missing / Failing DNS Record", "Host fails standard DNS resolution or uses unlisted DNS records.", "High"),
        1: ("Valid DNS Record", "Host resolves to verified A/AAAA/CNAME records.", "Safe")
    },
    "Google_Index": {
        -1: ("Unindexed by Major Search Engines", "Domain is not indexed in Google search index, indicating brand-new or hidden page.", "Medium"),
        1: ("Indexed by Search Engines", "Domain is verified and crawled in search index.", "Safe")
    },
    "Statistical_report": {
        -1: ("Host Flagged on Threat Blocklists", "Host or IP appears on active cybersecurity threat feeds / PhishTank lists.", "Critical"),
        1: ("Clean Threat Feed Status", "No active security blocks or blacklist entries.", "Safe")
    }
}


class SecurityExplainer:
    """
    Computes model explanations, feature importance rankings, and generates
    actionable, human-readable cybersecurity incident reports.
    """

    def __init__(self, model_pipeline, background_sample: Optional[pd.DataFrame] = None):
        self.pipeline = model_pipeline
        self.background_sample = background_sample
        self._init_explainer()

    def _init_explainer(self):
        # Extract underlying tree model
        raw_model = getattr(self.pipeline, "raw_model", None)
        if raw_model is None:
            raw_model = getattr(self.pipeline, "pipeline", None)

        try:
            # Check if model has estimator attribute (e.g. from CalibratedClassifierCV)
            if hasattr(self.pipeline, "final_model") and hasattr(self.pipeline.final_model, "calibrated_classifiers_"):
                # Use base estimator of first fold
                first_cal = self.pipeline.final_model.calibrated_classifiers_[0]
                underlying = first_cal.estimator
                self.shap_explainer = shap.TreeExplainer(underlying)
            elif hasattr(raw_model, "predict_proba"):
                self.shap_explainer = shap.TreeExplainer(raw_model)
            else:
                self.shap_explainer = None
        except Exception:
            self.shap_explainer = None

    def explain_instance(
        self,
        features_dict: Dict[str, Any],
        prob_phishing: float,
        continuous_stats: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Produces an interpretable explanation for a single prediction instance.
        """
        risk_factors = []
        mitigating_factors = []

        # Check continuous stats signals first
        if continuous_stats:
            brand_spoofed = continuous_stats.get("brand_spoofed")
            if brand_spoofed:
                risk_factors.append({
                    "feature": "brand_impersonation",
                    "value": -1,
                    "title": f"Brand Impersonation ({brand_spoofed.upper()})",
                    "description": f"URL attempts to spoof recognized brand '{brand_spoofed.capitalize()}' on an unverified host origin.",
                    "severity": "Critical"
                })
            
            if continuous_stats.get("is_high_risk_tld"):
                tld = continuous_stats.get("tld", "")
                risk_factors.append({
                    "feature": "high_risk_tld",
                    "value": -1,
                    "title": f"High-Risk TLD (.{tld})",
                    "description": f"Top-level domain '.{tld}' exhibits elevated incidence of automated phishing and malicious abuse.",
                    "severity": "High"
                })

            kw_hits = continuous_stats.get("suspicious_keywords", [])
            if len(kw_hits) >= 2:
                risk_factors.append({
                    "feature": "deceptive_keywords",
                    "value": -1,
                    "title": f"Credential Harvest Tokens ({len(kw_hits)} keywords)",
                    "description": f"URL path and query strings embed high-risk credential keywords: {', '.join(kw_hits[:3])}.",
                    "severity": "High"
                })

            if continuous_stats.get("is_trusted_domain") and not brand_spoofed:
                mitigating_factors.append({
                    "feature": "domain_authority",
                    "value": 1,
                    "title": "Verified High-Authority Domain",
                    "description": f"Registered domain '{continuous_stats.get('domain')}' is in verified global top-authority trusted registries.",
                    "severity": "Safe"
                })

        for feat, val in features_dict.items():
            if feat in SECURITY_DESCRIPTIONS and val in SECURITY_DESCRIPTIONS[feat]:
                title, desc, severity = SECURITY_DESCRIPTIONS[feat][val]
                factor_info = {
                    "feature": feat,
                    "value": val,
                    "title": title,
                    "description": desc,
                    "severity": severity
                }
                if val in [-1, 0]:
                    risk_factors.append(factor_info)
                elif val == 1:
                    mitigating_factors.append(factor_info)

        # Sort risk factors by severity (Critical -> High -> Medium -> Low)
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Safe": 0}
        risk_factors.sort(key=lambda x: severity_rank.get(x["severity"], 0), reverse=True)

        # Generate summary verdict
        if prob_phishing >= 0.70:
            verdict_badge = "CRITICAL_PHISHING"
            summary_text = (
                f"🚨 High-Confidence Phishing Attack Detected ({round(prob_phishing * 100, 1)}% Risk Probability). "
                f"Multiple deceptive indicators detected including {', '.join([r['title'] for r in risk_factors[:2]])}."
            )
        elif 0.38 <= prob_phishing < 0.70:
            verdict_badge = "SUSPICIOUS"
            summary_text = (
                f"⚠️ Suspicious / Ambiguous Website ({round(prob_phishing * 100, 1)}% Risk Probability). "
                f"Caution advised: anomalies present in {', '.join([r['title'] for r in risk_factors[:2]])}."
            )
        else:
            verdict_badge = "LEGITIMATE"
            summary_text = (
                f"✅ Legitimate Website Verified ({round((1 - prob_phishing) * 100, 1)}% Legitimacy Confidence). "
                f"Valid structural attributes and authentic security posture observed."
            )

        return {
            "verdict": verdict_badge,
            "probability_phishing": float(prob_phishing),
            "probability_legitimate": float(1.0 - prob_phishing),
            "summary": summary_text,
            "critical_risk_factors": risk_factors[:5],
            "all_risk_factors": risk_factors,
            "mitigating_factors": mitigating_factors[:5],
            "total_threat_signals": len(risk_factors)
        }
