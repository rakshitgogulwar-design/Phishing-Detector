"""
PhishGuard Advanced URL Phishing Detection Engine
Performs comprehensive passive lexical, syntactic, structural, and reputation analysis
across 20+ cybersecurity indicators without visiting malicious landing pages.
Generates an interpretable 0 - 100 weighted rule risk score and reasons checklist.
"""

import re
import math
import socket
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import tldextract

from src.detection.threat_intel import ThreatIntel


SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "security", "update", "banking", "auth", "authorize", "recover",
    "password", "credential", "suspend", "confirm", "wallet", "support",
    "service", "portal", "secure-login", "billing", "refund", "alert",
    "authenticate", "validation", "passcode", "identity"
]

SUSPICIOUS_QUERY_PARAMS = [
    "redirect", "redirect_to", "next", "return", "url", "target", "dest",
    "token", "session", "auth", "credential", "email", "pass", "sec"
]


class URLAnalyzer:
    """
    Passive Multi-Factor URL Phishing Inspector.
    """

    def __init__(self):
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None)

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """
        Executes exhaustive passive security analysis on a given URL string.
        Returns weighted rule score (0 - 100), risk status, checklist reasons,
        and continuous metrics.
        """
        raw_url = raw_url.strip()
        has_scheme = raw_url.startswith("http://") or raw_url.startswith("https://")
        normalized_url = raw_url if has_scheme else ("https://" + raw_url)

        try:
            parsed = urllib.parse.urlparse(normalized_url)
            tld_info = self.tld_extractor(normalized_url)
            domain = getattr(tld_info, "top_domain_under_public_suffix", None) or getattr(tld_info, "domain", "") or parsed.netloc.split(":")[0]
            hostname = parsed.netloc.split(":")[0]
            subdomain = tld_info.subdomain
            tld = tld_info.suffix.lower()
            path = parsed.path
            query = parsed.query
            try:
                port = parsed.port
            except (ValueError, Exception):
                port = -1
        except (ValueError, Exception):
            parsed = urllib.parse.urlsplit("https://malformed-target.invalid")
            domain = "malformed-target.invalid"
            hostname = "malformed-target.invalid"
            subdomain = ""
            tld = "invalid"
            path = ""
            query = ""
            port = -1

        # Threat Intelligence evaluation
        threat_data = ThreatIntel.evaluate_threat_reputation(domain, hostname, tld, raw_url)

        # Indicator checklist & penalty accumulators
        checklist: List[Dict[str, Any]] = []
        rule_penalties: float = 0.0

        # 1. Protocol & Scheme Security
        is_https = normalized_url.startswith("https://")
        if is_https:
            checklist.append({
                "status": "PASS",
                "indicator": "HTTPS Encryption",
                "details": "Connection specifies TLS/HTTPS encryption protocol."
            })
        else:
            rule_penalties += 15.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Insecure HTTP Protocol",
                "details": "Plain HTTP transport lacks encryption, highly vulnerable to credential interception."
            })

        # 2. Raw IP Address in Hostname
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        is_raw_ip = bool(re.match(ipv4_pattern, hostname)) or hostname.startswith("0x")
        if is_raw_ip:
            rule_penalties += 35.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Raw IP Address in Hostname",
                "details": f"Attacker using direct numeric IP ({hostname}) bypassing standard DNS reputation mechanisms."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Domain Name Identity",
                "details": "URL resolves via standard DNS domain naming."
            })

        # 3. Non-Standard Port
        if port is not None and port not in [80, 443]:
            rule_penalties += 20.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Non-Standard Port",
                "details": f"Connection attempts non-standard HTTP port ({port}), typical of rogue/compromised servers."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Standard Port Configuration",
                "details": "Port conforms to default web transport (80 / 443)."
            })

        # 4. Brand Impersonation & Typosquatting
        spoofed_brand = threat_data.get("spoofed_brand")
        if spoofed_brand:
            rule_penalties += 45.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Brand Impersonation / Typosquatting",
                "details": f"Spoofs protected brand '{spoofed_brand.capitalize()}' on unverified domain '{domain}'."
            })
        elif threat_data.get("is_trusted"):
            checklist.append({
                "status": "PASS",
                "indicator": "Verified Enterprise Authority",
                "details": f"Domain '{domain}' matches authenticated global authority registry."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Brand Authenticity",
                "details": "No unauthorized brand spoofing tokens identified in domain or host."
            })

        # 5. Top-Level Domain (TLD) Threat Profile
        if threat_data.get("is_high_risk_tld"):
            rule_penalties += 22.0
            checklist.append({
                "status": "FAIL",
                "indicator": f"High-Abuse TLD (.{tld})",
                "details": f"Top-level domain '.{tld}' is heavily exploited by automated malicious campaigns."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Reputable TLD",
                "details": f"Top-level domain '.{tld}' is a standard registered authority extension."
            })

        # 6. URL Shortening Services
        if threat_data.get("is_shortener"):
            rule_penalties += 20.0
            checklist.append({
                "status": "FAIL",
                "indicator": "URL Shortener Redirection Proxy",
                "details": f"Host '{hostname}' uses link shortening to conceal the true destination landing address."
            })

        # 7. Subdomain Depth & Dot Count
        dots_in_sub = subdomain.count(".") if subdomain else 0
        subdomain_levels = dots_in_sub + 1 if subdomain and subdomain.lower() != "www" else 0
        if subdomain_levels >= 2:
            rule_penalties += 18.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Excessive Subdomain Levels",
                "details": f"Subdomain hierarchy is deeply nested ({subdomain_levels} levels: '{subdomain}'), typical of host masking."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Clean Subdomain Hierarchy",
                "details": "Subdomain structure is normal and uncluttered."
            })

        # 8. URL Length & Obfuscation
        url_len = len(raw_url)
        if url_len > 75:
            rule_penalties += 12.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Excessive URL Length",
                "details": f"URL length is abnormally high ({url_len} characters), often used to push malicious tokens off-screen."
            })
        elif url_len >= 54:
            rule_penalties += 5.0
            checklist.append({
                "status": "WARN",
                "indicator": "Moderate URL Length",
                "details": f"URL length ({url_len} chars) is moderately elevated."
            })
        else:
            checklist.append({
                "status": "PASS",
                "indicator": "Concise URL Length",
                "details": f"URL length is standard ({url_len} characters)."
            })

        # 9. At Symbol (@) Credential Trick
        if "@" in raw_url:
            rule_penalties += 30.0
            checklist.append({
                "status": "FAIL",
                "indicator": "@ Symbol in URL Authority",
                "details": "URL contains '@' credential delimiter which browsers interpret as login auth, spoofing the true host."
            })

        # 10. Embedded Double Slash Redirection
        if raw_url.rfind("//") > 7:
            rule_penalties += 20.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Double Slash '//' Redirection Token",
                "details": "Secondary '//' token located in URL path used to initiate open redirection."
            })

        # 11. Suspicious Keywords in Path / Host
        url_lower = raw_url.lower()
        matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in url_lower]
        if matched_keywords and not threat_data.get("is_trusted"):
            kw_penalty = min(25.0, len(matched_keywords) * 8.0)
            rule_penalties += kw_penalty
            checklist.append({
                "status": "FAIL",
                "indicator": "Credential & Security Keywords",
                "details": f"Detected {len(matched_keywords)} sensitive keyword(s) on unranked host: {', '.join(matched_keywords[:4])}."
            })
        elif matched_keywords:
            checklist.append({
                "status": "PASS",
                "indicator": "Standard Portal Terminology",
                "details": f"Path contains standard terms on authenticated infrastructure: {', '.join(matched_keywords[:2])}."
            })

        # 12. Hyphens in Root Domain
        if "-" in domain and not threat_data.get("is_trusted") and not spoofed_brand:
            rule_penalties += 8.0
            checklist.append({
                "status": "WARN",
                "indicator": "Hyphenated Root Domain",
                "details": f"Root domain '{domain}' uses hyphen separators commonly leveraged in look-alike domains."
            })

        # 13. Digit Ratio & Character Entropy
        digit_count = sum(c.isdigit() for c in raw_url)
        digit_ratio = digit_count / max(url_len, 1)
        entropy = self._calculate_entropy(raw_url)

        if digit_ratio > 0.15 and not is_raw_ip:
            rule_penalties += 12.0
            checklist.append({
                "status": "FAIL",
                "indicator": "High Digit Ratio",
                "details": f"{round(digit_ratio * 100, 1)}% of characters are numeric, typical of algorithmic domain generation."
            })

        if entropy > 4.25:
            rule_penalties += 10.0
            checklist.append({
                "status": "WARN",
                "indicator": "High Shannon Entropy",
                "details": f"Character entropy is elevated ({entropy:.2f} bits/symbol), indicating obfuscated or randomized tokens."
            })

        # 14. Suspicious Query Parameters (Open Redirects)
        matched_params = [p for p in SUSPICIOUS_QUERY_PARAMS if f"{p}=" in query.lower()]
        if matched_params:
            rule_penalties += 10.0
            checklist.append({
                "status": "WARN",
                "indicator": "Redirect / Auth Query Parameter",
                "details": f"Query string specifies redirection/token parameters: {', '.join(matched_params[:3])}."
            })

        # 15. URL Encoding / Hex Obfuscation
        encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw_url))
        if encoded_count >= 3:
            rule_penalties += 12.0
            checklist.append({
                "status": "FAIL",
                "indicator": "Heavy Hex / Percent Encoding",
                "details": f"URL contains {encoded_count} percent-encoded hex sequences disguising the true address."
            })

        # Calculate final normalized rule score
        if threat_data.get("is_trusted") and not spoofed_brand:
            # Genuine trusted authority capped at safe range
            final_rule_score = min(25.0, 5.0 + (rule_penalties * 0.15))
        else:
            final_rule_score = min(100.0, max(0.0, rule_penalties))

        # Determine tier
        if final_rule_score >= 61.0:
            status = "PHISHING"
            risk_tier = "HIGH RISK"
        elif final_rule_score >= 31.0:
            status = "SUSPICIOUS"
            risk_tier = "SUSPICIOUS"
        else:
            status = "SAFE"
            risk_tier = "SAFE"

        # Separate checklist into fails, warnings, and passes
        fails = [c for c in checklist if c["status"] == "FAIL"]
        warnings = [c for c in checklist if c["status"] == "WARN"]
        passes = [c for c in checklist if c["status"] == "PASS"]

        return {
            "rule_score": round(final_rule_score, 1),
            "status": status,
            "risk_tier": risk_tier,
            "threat_intel": threat_data,
            "checklist": checklist,
            "failed_indicators": fails,
            "warning_indicators": warnings,
            "passed_indicators": passes,
            "metrics": {
                "url_length": url_len,
                "dot_count": raw_url.count("."),
                "subdomain_count": subdomain_levels,
                "digit_count": digit_count,
                "digit_ratio": round(digit_ratio, 4),
                "entropy": round(entropy, 2),
                "is_https": is_https,
                "is_raw_ip": is_raw_ip,
                "matched_keywords": matched_keywords,
                "domain": domain,
                "hostname": hostname,
                "tld": tld
            }
        }

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return round(-sum([p * math.log(p) / math.log(2.0) for p in prob]), 4)
