"""
PhishGuard Threat Intelligence Engine
Provides threat feeds, brand registries, high-abuse TLD classifications,
URL shorteners, lookalike/homoglyph detectors, and reputation scoring.
"""

import re
from typing import Dict, Any, Optional, Tuple, Set, List


class ThreatIntel:
    """
    Threat Intelligence repository and domain reputation engine.
    """

    TRUSTED_DOMAINS: Set[str] = {
        "google.com", "youtube.com", "facebook.com", "amazon.com", "yahoo.com",
        "wikipedia.org", "twitter.com", "x.com", "instagram.com", "linkedin.com",
        "reddit.com", "netflix.com", "github.com", "microsoft.com", "apple.com",
        "stackoverflow.com", "cloudflare.com", "openai.com", "chatgpt.com",
        "chase.com", "paypal.com", "wellsfargo.com", "bankofamerica.com", "citigroup.com",
        "cnn.com", "bbc.com", "nytimes.com", "spotify.com", "dropbox.com", "adobe.com",
        "salesforce.com", "gitlab.com", "mozilla.org", "arxiv.org", "huggingface.co",
        "kaggle.com", "medium.com", "bing.com", "duckduckgo.com", "ebay.com",
        "nih.gov", "mit.edu", "harvard.edu", "stanford.edu", "gov.uk", "irs.gov",
        "walmart.com", "target.com", "costco.com", "uber.com", "airbnb.com"
    }

    TARGETED_BRANDS: Dict[str, str] = {
        "paypal": "paypal.com",
        "chase": "chase.com",
        "wellsfargo": "wellsfargo.com",
        "bankofamerica": "bankofamerica.com",
        "citibank": "citigroup.com",
        "apple": "apple.com",
        "appleid": "apple.com",
        "icloud": "apple.com",
        "microsoft": "microsoft.com",
        "office365": "microsoft.com",
        "onedrive": "microsoft.com",
        "outlook": "microsoft.com",
        "amazon": "amazon.com",
        "netflix": "netflix.com",
        "google": "google.com",
        "gmail": "google.com",
        "binance": "binance.com",
        "metamask": "metamask.io",
        "coinbase": "coinbase.com",
        "kraken": "kraken.com",
        "steam": "steampowered.com",
        "steamcommunity": "steamcommunity.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "whatsapp": "whatsapp.com",
        "dropbox": "dropbox.com",
        "adobe": "adobe.com",
        "dhl": "dhl.com",
        "fedex": "fedex.com",
        "usps": "usps.com"
    }

    HIGH_RISK_TLDS: Set[str] = {
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club", "work",
        "rest", "cam", "ru", "cc", "icu", "click", "link", "guru", "support",
        "online", "site", "live", "space", "bid", "fit", "racing", "date",
        "zip", "mov", "monster", "cfd", "sbs", "beauty", "hair", "quest"
    }

    SHORTENING_SERVICES: Set[str] = {
        "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl",
        "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu",
        "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm",
        "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com",
        "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.ly",
        "lnkd.in", "db.tt", "qr.ae", "adf.ly", "cur.lv", "ity.im", "q.gs", "po.st", "bc.vc",
        "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org",
        "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com"
    }

    # Common homoglyphs / lookalikes
    HOMOGLYPH_MAP: Dict[str, str] = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
        'ѕ': 's', 'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n', 'օ': 'o',
        '0': 'o', '1': 'l'
    }

    @classmethod
    def is_trusted_domain(cls, domain: str) -> bool:
        """Returns True if the domain is in the verified trusted domain set."""
        if not domain:
            return False
        d_lower = domain.lower().strip()
        if d_lower in cls.TRUSTED_DOMAINS:
            return True
        for td in cls.TRUSTED_DOMAINS:
            if d_lower.endswith("." + td):
                return True
        return False

    @classmethod
    def is_high_risk_tld(cls, tld: str) -> bool:
        """Checks if the TLD has high historical malicious registration ratios."""
        return (tld or "").lower().strip(".") in cls.HIGH_RISK_TLDS

    @classmethod
    def is_url_shortener(cls, hostname: str) -> bool:
        """Checks if hostname matches a known URL shortening proxy."""
        h_lower = (hostname or "").lower()
        return any(s == h_lower or h_lower.endswith("." + s) for s in cls.SHORTENING_SERVICES)

    @classmethod
    def check_brand_spoofing(cls, raw_url: str, registered_domain: str, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Detects brand mimicry where a known brand appears in the URL/hostname
        while the actual registered domain belongs to an unverified third party.
        """
        raw_lower = raw_url.lower()
        domain_lower = (registered_domain or "").lower()
        host_lower = (hostname or "").lower()

        for brand, authentic_domain in cls.TARGETED_BRANDS.items():
            # If domain is the authentic brand domain, it's not spoofing
            if domain_lower == authentic_domain or domain_lower.endswith("." + authentic_domain):
                continue

            # Look for brand tokens in hostname, subdomains, or initial path
            has_brand_token = (
                (f"{brand}-" in host_lower) or
                (f"-{brand}" in host_lower) or
                (f".{brand}." in host_lower) or
                (host_lower.startswith(f"{brand}.")) or
                (f"/{brand}/" in raw_lower) or
                (f"/{brand}-" in raw_lower) or
                (f"/{brand}." in raw_lower) or
                (f"auth/{brand}" in raw_lower)
            )
            if has_brand_token:
                return brand, authentic_domain

        return None, None

    @classmethod
    def detect_lookalike_homoglyphs(cls, domain: str) -> List[str]:
        """Flags non-ASCII or homoglyph characters inside domain names (IDN homograph attacks)."""
        findings = []
        if not domain:
            return findings
        for char in domain:
            if ord(char) > 127:
                findings.append(f"Non-ASCII character '{char}' (Unicode U+{ord(char):04X}) detected in domain name.")
        if "xn--" in domain.lower():
            findings.append("Punycode domain prefix ('xn--') detected, indicating an internationalized look-alike.")
        return findings

    @classmethod
    def evaluate_threat_reputation(
        cls,
        domain: str,
        hostname: str,
        tld: str,
        raw_url: str
    ) -> Dict[str, Any]:
        """
        Computes a threat intelligence risk contribution (0 - 100).
        """
        is_trusted = cls.is_trusted_domain(domain)
        is_abuse_tld = cls.is_high_risk_tld(tld)
        is_short = cls.is_url_shortener(hostname)
        spoofed_brand, auth_domain = cls.check_brand_spoofing(raw_url, domain, hostname)
        homoglyphs = cls.detect_lookalike_homoglyphs(domain)

        intel_score = 0.0
        reasons = []

        if is_trusted and not spoofed_brand:
            intel_score = 5.0
            reasons.append(f"Domain '{domain}' is listed in verified global trusted authority registry.")
            return {
                "threat_score": intel_score,
                "is_trusted": True,
                "is_high_risk_tld": False,
                "is_shortener": False,
                "spoofed_brand": None,
                "homoglyphs": [],
                "reasons": reasons
            }

        if spoofed_brand:
            intel_score += 55.0
            reasons.append(f"High-confidence brand impersonation: attempts to spoof '{spoofed_brand.capitalize()}' (authentic domain: '{auth_domain}').")

        if is_abuse_tld:
            intel_score += 25.0
            reasons.append(f"Top-level domain '.{tld}' is classified as a high-abuse TLD frequently used in disposable campaigns.")

        if is_short:
            intel_score += 20.0
            reasons.append(f"Hostname '{hostname}' is a URL shortening service masking final destination.")

        if homoglyphs:
            intel_score += 30.0
            reasons.extend(homoglyphs)

        intel_score = min(100.0, max(0.0, intel_score))
        return {
            "threat_score": round(intel_score, 1),
            "is_trusted": is_trusted,
            "is_high_risk_tld": is_abuse_tld,
            "is_shortener": is_short,
            "spoofed_brand": spoofed_brand,
            "homoglyphs": homoglyphs,
            "reasons": reasons
        }
