"""
PhishGuard Email, SMS & Social Engineering Message Analyzer
Detects spear-phishing, credential harvesting, urgency/intimidation,
fake rewards, OTP requests, financial extortion, and malicious lures.
Complies with strict privacy standards: sensitive data is never logged or stored.
"""

import re
from typing import Dict, Any, List, Optional
from src.detection.url_analyzer import URLAnalyzer


class TextAnalyzer:
    """
    Analyzes raw text content (Emails, SMS, WhatsApp, Chat DMs)
    for phishing and social engineering signatures.
    """

    # 1. Urgency & Fear Patterns
    URGENCY_PATTERNS = [
        r"\b(?:immediately|urgent|urgently|right now|without delay)\b",
        r"\b(?:within\s+\d+\s+(?:hours?|minutes?|days?))\b",
        r"\b(?:account\s+(?:will be|has been)?\s*(?:suspended|blocked|locked|terminated|deactivated|closed))\b",
        r"\b(?:act now|final notice|immediate attention|last warning|action required)\b",
        r"\b(?:legal\s+action|police|lawsuit|law enforcement|arrest warrant|court)\b"
    ]

    # 2. Fake Rewards, Lottery & Financial Lures
    REWARD_PATTERNS = [
        r"\b(?:congratulations|winner|you have won|selected as a winner|claim your prize)\b",
        r"\b(?:lottery|jackpot|cash prize|sweepstakes|free gift|gift card|bonus)\b",
        r"\b(?:refund of \$?\d+|unclaimed payment|wire transfer|inheritance|crypto giveaway)\b",
        r"\b(?:million dollars|bitcoin reward|claim your \$\d+)\b"
    ]

    # 3. Credential & Sensitive Authentication Requests
    CREDENTIAL_PATTERNS = [
        r"\b(?:enter your password|send your password|reset your password|update your password)\b",
        r"\b(?:one-time password|one time password|\botp\b|verification code|security pin|2fa code)\b",
        r"\b(?:social security number|\bssn\b|credit card number|\bcvv\b|card expiry)\b",
        r"\b(?:banking pin|atm pin|seed phrase|private key|recovery phrase)\b",
        r"\b(?:verify your identity|confirm your credentials|re-authenticate)\b"
    ]

    # 4. Financial & Payment Extortion / Demands
    FINANCIAL_PATTERNS = [
        r"\b(?:wire money|send bitcoin|crypto deposit|buy gift cards?|pay immediately)\b",
        r"\b(?:unpaid invoice|tax penalty|overdue bill|outstanding balance|settlement)\b",
        r"\b(?:western union|moneygram|cashapp|zelle transfer|reimbursement)\b"
    ]

    # 5. Authority Impersonation Lures
    IMPERSONATION_PATTERNS = [
        r"\b(?:internal revenue service|\birs\b|hmrc|department of justice|\bfbi\b)\b",
        r"\b(?:customer support desk|security team|fraud department|system administrator)\b",
        r"\b(?:microsoft support|apple support|geek squad|paypal fraud prevention)\b",
        r"\b(?:usps delivery|fedex shipment|dhl courier|package held in customs)\b"
    ]

    def __init__(self):
        self.url_analyzer = URLAnalyzer()

    def analyze(self, raw_text: str) -> Dict[str, Any]:
        """
        Executes multi-dimensional social engineering detection on raw text messages.
        Returns risk score (0 - 100), classification, and itemized reasoning.
        """
        if not raw_text or not raw_text.strip():
            return {
                "risk_score": 0.0,
                "status": "SAFE",
                "risk_tier": "SAFE",
                "confidence": 0.95,
                "reasons": ["Empty or blank message submitted."],
                "categories_flagged": [],
                "embedded_urls_analyzed": [],
                "checklist": []
            }

        text = raw_text.strip()
        text_lower = text.lower()
        reasons: List[str] = []
        checklist: List[Dict[str, Any]] = []
        categories_flagged: List[str] = []
        total_penalty: float = 0.0

        # 1. Evaluate Urgency & Threatening Tone
        urgency_matches = []
        for pat in self.URGENCY_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                urgency_matches.extend(found)

        if urgency_matches:
            total_penalty += 30.0
            categories_flagged.append("Artificial Urgency & Intimidation")
            reasons.append(f"Uses high-pressure urgency cues designed to trigger hasty action: {', '.join(set(urgency_matches[:3]))}.")
            checklist.append({
                "status": "FAIL",
                "indicator": "Urgency / Intimidation",
                "details": f"Flagged {len(urgency_matches)} urgency phrase(s)."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Normal Urgency Profile",
                "details": "No artificial urgency or threatening deadlines detected."
            })

        # 2. Evaluate Credential & OTP Harvesting Requests
        credential_matches = []
        for pat in self.CREDENTIAL_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                credential_matches.extend(found)

        if credential_matches:
            total_penalty += 45.0
            categories_flagged.append("Credential / OTP Harvesting")
            reasons.append(f"Directly requests sensitive authentication items (passwords, OTPs, PINs, or recovery codes).")
            checklist.append({
                "status": "FAIL",
                "indicator": "Credential / OTP Request",
                "details": f"Found direct credential harvesting pattern: {', '.join(set(credential_matches[:2]))}."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "No Credential Solicitations",
                "details": "Message does not request passwords, OTPs, or private keys."
            })

        # 3. Evaluate Fake Rewards / Lottery Lures
        reward_matches = []
        for pat in self.REWARD_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                reward_matches.extend(found)

        if reward_matches:
            total_penalty += 25.0
            categories_flagged.append("Fake Prize / Financial Bait")
            reasons.append(f"Promises unrealistic rewards, lotteries, or unexpected cash transfers.")
            checklist.append({
                "status": "FAIL",
                "indicator": "Unrealistic Reward Lure",
                "details": f"Matches lottery / prize lure patterns: {', '.join(set(reward_matches[:2]))}."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "No Prize Baiting",
                "details": "Message does not exhibit lottery or unverified reward lures."
            })

        # 4. Evaluate Financial Extortion / Unapproved Demands
        financial_matches = []
        for pat in self.FINANCIAL_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                financial_matches.extend(found)

        if financial_matches:
            total_penalty += 25.0
            categories_flagged.append("Suspicious Payment Demand")
            reasons.append(f"Contains non-standard financial transfer or urgent payment demands.")
            checklist.append({
                "status": "FAIL",
                "indicator": "Suspicious Payment Request",
                "details": f"Flags payment demand patterns: {', '.join(set(financial_matches[:2]))}."
            })

        # 5. Authority Impersonation Lures
        impersonation_matches = []
        for pat in self.IMPERSONATION_PATTERNS:
            found = re.findall(pat, text_lower)
            if found:
                impersonation_matches.extend(found)

        if impersonation_matches:
            total_penalty += 20.0
            categories_flagged.append("Authority / Brand Impersonation")
            reasons.append(f"Pretends to represent recognized authority, delivery, or tech support: {', '.join(set(impersonation_matches[:2]))}.")
            checklist.append({
                "status": "FAIL",
                "indicator": "Authority Impersonation",
                "details": f"Claims representation of recognized institution: {', '.join(set(impersonation_matches[:2]))}."
            })

        # 6. Extract and Evaluate Embedded Links
        url_regex = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?\S*)?"
        extracted_urls = re.findall(url_regex, text)
        embedded_evaluations = []

        if extracted_urls:
            highest_url_score = 0.0
            for u in extracted_urls[:3]:  # Check up to top 3 embedded links
                url_res = self.url_analyzer.analyze(u)
                highest_url_score = max(highest_url_score, url_res["rule_score"])
                embedded_evaluations.append({
                    "url": u,
                    "score": url_res["rule_score"],
                    "status": url_res["status"],
                    "top_fail": url_res["failed_indicators"][0]["details"] if url_res["failed_indicators"] else "Clean URL"
                })

            if highest_url_score >= 61.0:
                total_penalty += 40.0
                categories_flagged.append("High-Risk Embedded Hyperlink")
                reasons.append(f"Contains embedded hyperlink flagged as suspicious/malicious destination.")
                checklist.append({
                    "status": "FAIL",
                    "indicator": "Malicious Embedded Link",
                    "details": f"Embedded link received high risk rating ({highest_url_score}/100)."
                })
            elif highest_url_score >= 31.0:
                total_penalty += 20.0
                checklist.append({
                    "status": "WARN",
                    "indicator": "Suspicious Embedded Link",
                    "details": f"Embedded link shows elevated anomaly signals ({highest_url_score}/100)."
                })
            else:
                checklist.append({
                    "status": "PASS",
                    "indicator": "Clean Embedded Links",
                    "details": "Embedded hyperlinks pass basic safety and domain reputation verifications."
                })

        # Calculate final risk score
        final_score = min(100.0, max(5.0 if reasons else 2.0, total_penalty))

        # Risk tiering
        if final_score >= 61.0:
            status = "PHISHING"
            risk_tier = "HIGH RISK"
            confidence = min(0.98, 0.75 + (len(categories_flagged) * 0.06))
        elif final_score >= 31.0:
            status = "SUSPICIOUS"
            risk_tier = "SUSPICIOUS"
            confidence = 0.82
        else:
            status = "SAFE"
            risk_tier = "SAFE"
            confidence = 0.94
            if not reasons:
                reasons.append("No prominent social engineering, credential harvesting, or urgency patterns observed.")

        # Recommendations
        recommendations = []
        if status == "PHISHING":
            recommendations.append("Do not click any embedded links or open attached files.")
            recommendations.append("Never provide passwords, OTPs, PINs, or financial details in response to this message.")
            recommendations.append("Verify the sender independently via an official, trusted phone number or application.")
        elif status == "SUSPICIOUS":
            recommendations.append("Exercise caution: check the sender address carefully for slight typos or spoofed domains.")
            recommendations.append("Avoid clicking links directly; navigate to official websites independently.")
        else:
            recommendations.append("Message appears benign, but remain vigilant when handling unsolicited requests.")

        return {
            "risk_score": round(final_score, 1),
            "status": status,
            "risk_tier": risk_tier,
            "confidence": round(confidence, 2),
            "reasons": reasons,
            "checklist": checklist,
            "categories_flagged": categories_flagged,
            "recommendations": recommendations,
            "embedded_urls_analyzed": embedded_evaluations,
            "stats": {
                "character_count": len(text),
                "word_count": len(text.split()),
                "links_found": len(extracted_urls),
                "threat_categories_count": len(categories_flagged)
            }
        }
