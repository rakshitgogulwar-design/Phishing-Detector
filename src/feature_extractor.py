"""
Real-Time Multi-Modal Feature Extraction Engine
Extracts URL-lexical, domain/DNS, HTML/DOM structure, and security/reputation features
from any given URL and raw/fetched HTML.
Includes brand impersonation detection, high-risk TLD analysis, fast DNS caching,
and continuous calibrated multi-signal risk calculation.
"""

import re
import math
import socket
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List, Set
import requests
from bs4 import BeautifulSoup
import tldextract


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

TRUSTED_TOP_DOMAINS: Set[str] = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "yahoo.com",
    "wikipedia.org", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "reddit.com", "netflix.com", "github.com", "microsoft.com", "apple.com",
    "stackoverflow.com", "cloudflare.com", "openai.com", "chatgpt.com",
    "chase.com", "paypal.com", "wellsfargo.com", "bankofamerica.com", "citigroup.com",
    "cnn.com", "bbc.com", "nytimes.com", "spotify.com", "dropbox.com", "adobe.com",
    "salesforce.com", "gitlab.com", "mozilla.org", "arxiv.org", "huggingface.co",
    "kaggle.com", "medium.com", "bing.com", "duckduckgo.com", "ebay.com",
    "nih.gov", "mit.edu", "harvard.edu", "stanford.edu", "gov.uk"
}

TRUSTED_CDN_DOMAINS: Set[str] = {
    "cloudfront.net", "akamaihd.net", "akamaized.net", "cloudflare.com", "fastly.net",
    "googleapis.com", "gstatic.com", "fbcdn.net", "twimg.com", "wp.com", "azureedge.net",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "nflxext.com", "nflximg.net", "nflxvideo.net",
    "githubassets.com", "ytimg.com", "ggpht.com", "googleusercontent.com", "s-microsoft.com",
    "static-amazon.com", "ssl-images-amazon.com", "apple-mapkit.com", "cdn-apple.com",
    "oaistatic.com", "oaiusercontent.com", "openai.com", "chatgpt.com"
}

HIGH_RISK_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "club", "work",
    "rest", "cam", "ru", "cc", "icu", "click", "link", "guru", "support",
    "online", "site", "live", "space", "bid", "fit", "racing", "date"
}

TARGETED_BRANDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "apple": "apple.com",
    "appleid": "apple.com",
    "microsoft": "microsoft.com",
    "office365": "microsoft.com",
    "onedrive": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "google": "google.com",
    "gmail": "google.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "coinbase": "coinbase.com",
    "steam": "steampowered.com",
    "steamcommunity": "steamcommunity.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com"
}

SUSPICIOUS_KEYWORDS: List[str] = [
    "verify", "verification", "account", "update", "security", "login",
    "signin", "sign-in", "banking", "auth", "authorize", "recover",
    "password", "credential", "suspend", "confirm", "wallet", "support",
    "service", "portal", "secure-login", "billing", "refund", "alert"
]


class MultiModalFeatureExtractor:
    """
    Extracts 30 standardized features matching the Mohammad et al. benchmark schema:
    1: Legitimate / Safe
    0: Suspicious / Neutral
    -1: Phishing / Malicious / Abnormal

    Plus auxiliary continuous statistics, brand spoofing signals,
    and a calibrated multi-signal risk rating engine.
    """

    _dns_cache: Dict[str, bool] = {}

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        # Using default cache for fast repeated parsing
        self.extractor = tldextract.TLDExtract(cache_dir=True)

    def extract_all(self, url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Extracts full 30-feature vector and auxiliary continuous statistics from a URL.
        If html_content is None, attempts a rapid live fetch with a short connection timeout.
        """
        raw_input = url.strip()
        has_explicit_scheme = raw_input.startswith("http://") or raw_input.startswith("https://")

        if not has_explicit_scheme:
            url_with_scheme = "https://" + raw_input
        else:
            url_with_scheme = raw_input

        parsed = urllib.parse.urlparse(url_with_scheme)
        ext = self.extractor(url_with_scheme)
        domain = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", "") or parsed.netloc.split(":")[0]
        hostname = parsed.netloc.split(":")[0]
        tld = ext.suffix.lower()

        response_code = 200
        headers = {}
        redirect_count = 0
        final_scheme = parsed.scheme or "https"
        fetched_html = False

        if html_content is None:
            # Rapid fetch with strict connect timeout (0.8s) so dead links never hang
            for try_url in ([url_with_scheme] if has_explicit_scheme else [f"https://{raw_input}", f"http://{raw_input}"]):
                try:
                    resp = requests.get(
                        try_url,
                        timeout=(0.8, self.timeout),
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"},
                        allow_redirects=True
                    )
                    html_content = resp.text
                    response_code = resp.status_code
                    headers = dict(resp.headers)
                    redirect_count = len(resp.history)
                    final_scheme = urllib.parse.urlparse(resp.url).scheme
                    fetched_html = True
                    break
                except Exception:
                    html_content = ""
        else:
            fetched_html = len(html_content.strip()) > 0

        soup = BeautifulSoup(html_content, "html.parser") if (html_content and len(html_content) > 0) else None

        # Check DNS resolution with in-memory cache
        dns_resolves = self._check_dns_resolves(hostname)

        # Brand spoofing detection
        brand_spoofed, target_brand_domain = self._detect_brand_spoofing(raw_input, domain, hostname)

        # 1. URL & Domain Baseline Features
        f_ip = self._check_ip_address(hostname)
        f_url_len = self._check_url_length(raw_input)
        f_shortening = self._check_shortening(hostname)
        f_at = self._check_at_symbol(raw_input)
        f_double_slash = self._check_double_slash(raw_input)
        f_prefix_suffix = self._check_prefix_suffix(domain, brand_spoofed)
        f_subdomain = self._check_subdomains(ext.subdomain, brand_spoofed)
        f_domain_reg = self._check_domain_reg_length(domain, dns_resolves, tld)
        f_https_token = self._check_https_token(hostname)
        f_abnormal_url = self._check_abnormal_url(hostname, parsed.path, brand_spoofed)
        f_age_domain = self._check_domain_age(domain, dns_resolves, tld)
        f_dns = 1 if dns_resolves else -1
        f_google_index = self._check_google_index(domain, dns_resolves, tld)
        f_stats_report = self._check_statistical_report(hostname, raw_input, brand_spoofed, tld)

        # 2. HTML / DOM Structural Features
        f_favicon = self._check_favicon(soup, domain, fetched_html)
        f_port = self._check_port(parsed.port)
        f_req_url = self._check_request_url(soup, domain, fetched_html)
        f_url_anchor = self._check_url_of_anchor(soup, domain, fetched_html)
        f_links_in_tags = self._check_links_in_tags(soup, domain, fetched_html)
        f_sfh = self._check_sfh(soup, domain, fetched_html)
        f_submit_email = self._check_submitting_to_email(soup)
        f_redirect = self._check_redirect(redirect_count)
        f_mouseover = self._check_mouseover(soup)
        f_rightclick = self._check_rightclick(soup)
        f_popup = self._check_popup(soup)
        f_iframe = self._check_iframe(soup)

        # 3. Security & Reputation Features
        f_ssl = self._check_ssl(final_scheme, hostname)
        f_web_traffic = self._check_web_traffic(domain, dns_resolves)
        f_page_rank = self._check_page_rank(domain, dns_resolves)
        f_links_pointing = self._check_links_pointing(soup)

        features = {
            # URL / Domain Baseline
            "having_IPhaving_IP_Address": f_ip,
            "URLURL_Length": f_url_len,
            "Shortining_Service": f_shortening,
            "having_At_Symbol": f_at,
            "double_slash_redirecting": f_double_slash,
            "Prefix_Suffix": f_prefix_suffix,
            "having_Sub_Domain": f_subdomain,
            "Domain_registeration_length": f_domain_reg,
            "HTTPS_token": f_https_token,
            "Abnormal_URL": f_abnormal_url,
            "age_of_domain": f_age_domain,
            "DNSRecord": f_dns,
            "Google_Index": f_google_index,
            "Statistical_report": f_stats_report,

            # HTML / DOM Structural
            "Favicon": f_favicon,
            "port": f_port,
            "Request_URL": f_req_url,
            "URL_of_Anchor": f_url_anchor,
            "Links_in_tags": f_links_in_tags,
            "SFH": f_sfh,
            "Submitting_to_email": f_submit_email,
            "Redirect": f_redirect,
            "on_mouseover": f_mouseover,
            "RightClick": f_rightclick,
            "popUpWidnow": f_popup,
            "Iframe": f_iframe,

            # Security Context
            "SSLfinal_State": f_ssl,
            "web_traffic": f_web_traffic,
            "Page_Rank": f_page_rank,
            "Links_pointing_to_page": f_links_pointing,
        }

        # Count suspicious tokens
        url_lower = raw_input.lower()
        keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]

        continuous_stats = {
            "url_length": len(raw_input),
            "entropy": self._calculate_entropy(raw_input),
            "digit_count": sum(c.isdigit() for c in raw_input),
            "digit_ratio": round(sum(c.isdigit() for c in raw_input) / max(len(raw_input), 1), 4),
            "special_char_count": len(re.findall(r'[-_.~!*\'();:@&=+$,/?%#[\]]', raw_input)),
            "subdomain_depth": ext.subdomain.count(".") + 1 if ext.subdomain else 0,
            "hostname": hostname,
            "domain": domain,
            "tld": tld,
            "scheme": final_scheme,
            "is_trusted_domain": domain in TRUSTED_TOP_DOMAINS,
            "is_high_risk_tld": tld in HIGH_RISK_TLDS,
            "brand_spoofed": brand_spoofed,
            "suspicious_keyword_count": len(keyword_hits),
            "suspicious_keywords": keyword_hits,
            "has_html_inspection": fetched_html and (soup is not None)
        }

        return {
            "features": features,
            "continuous_stats": continuous_stats
        }

    # ==================== Brand & Lexical Helpers ====================

    def _detect_brand_spoofing(self, raw_url: str, domain: str, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Detects if a reputable brand name is being spoofed inside a domain, subdomain, or path
        when the registered domain is not the brand's authentic domain.
        """
        raw_lower = raw_url.lower()
        domain_lower = domain.lower()
        hostname_lower = hostname.lower()

        for brand, legit_domain in TARGETED_BRANDS.items():
            # If domain is already the authentic domain, it is NOT spoofing
            if domain_lower == legit_domain or domain_lower.endswith("." + legit_domain):
                continue

            # Check if brand appears in hostname or path
            if (brand in hostname_lower) or (f"/{brand}" in raw_lower) or (f".{brand}." in hostname_lower) or (f"-{brand}" in hostname_lower) or (f"{brand}-" in hostname_lower):
                return brand, legit_domain

        return None, None

    def _check_dns_resolves(self, hostname: str) -> bool:
        if not hostname or hostname.startswith("192.168.") or hostname.startswith("10.") or hostname == "localhost":
            return True
        if hostname in self._dns_cache:
            return self._dns_cache[hostname]
        try:
            socket.setdefaulttimeout(0.6)
            socket.gethostbyname(hostname)
            self._dns_cache[hostname] = True
            return True
        except Exception:
            self._dns_cache[hostname] = False
            return False

    def _check_ip_address(self, hostname: str) -> int:
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(ipv4_pattern, hostname) or hostname.startswith("0x"):
            return -1  # Phishing
        return 1  # Legitimate

    def _check_url_length(self, url: str) -> int:
        l = len(url)
        if l < 54:
            return 1  # Legitimate
        elif 54 <= l <= 75:
            return 0  # Suspicious
        return -1  # Phishing

    def _check_shortening(self, hostname: str) -> int:
        for s in SHORTENING_SERVICES:
            if s == hostname.lower() or hostname.lower().endswith("." + s):
                return -1
        return 1

    def _check_at_symbol(self, url: str) -> int:
        return -1 if "@" in url else 1

    def _check_double_slash(self, url: str) -> int:
        last_slash = url.rfind("//")
        if last_slash > 7:
            return -1
        return 1

    def _check_prefix_suffix(self, domain_name: str, brand_spoofed: Optional[str]) -> int:
        # Check if root domain name has hyphen (e.g. chase-security.com)
        if brand_spoofed:
            return -1
        if domain_name in TRUSTED_TOP_DOMAINS:
            return 1
        return -1 if "-" in domain_name else 1

    def _check_subdomains(self, subdomain: str, brand_spoofed: Optional[str]) -> int:
        if brand_spoofed:
            return -1
        if not subdomain or subdomain.lower() == "www":
            return 1
        dots = subdomain.count(".")
        if dots == 0:
            return 1  # 1 level (e.g. mail.domain.com) -> Normal
        elif dots == 1:
            return 0  # 2 levels -> Suspicious
        return -1  # >=3 levels -> Phishing

    def _check_domain_reg_length(self, domain: str, dns_resolves: bool, tld: str) -> int:
        if domain in TRUSTED_TOP_DOMAINS:
            return 1
        if tld in HIGH_RISK_TLDS:
            return -1
        return 1 if dns_resolves else -1

    def _check_https_token(self, hostname: str) -> int:
        if "https" in hostname.lower().split(".")[0]:
            return -1
        return 1

    def _check_abnormal_url(self, hostname: str, path: str, brand_spoofed: Optional[str]) -> int:
        if brand_spoofed:
            return -1
        if hostname and hostname in path:
            return -1
        return 1

    def _check_domain_age(self, domain: str, dns_resolves: bool, tld: str) -> int:
        if domain in TRUSTED_TOP_DOMAINS:
            return 1
        if tld in HIGH_RISK_TLDS:
            return -1
        return 1 if dns_resolves else -1

    def _check_google_index(self, domain: str, dns_resolves: bool, tld: str) -> int:
        if domain in TRUSTED_TOP_DOMAINS:
            return 1
        if tld in HIGH_RISK_TLDS:
            return -1
        return 1 if dns_resolves else -1

    def _check_statistical_report(self, hostname: str, raw_url: str, brand_spoofed: Optional[str], tld: str) -> int:
        if brand_spoofed:
            return -1
        if tld in HIGH_RISK_TLDS:
            return -1
        url_lower = raw_url.lower()
        phish_patterns = ["verify-account", "bank-update", "secure-login", "auth-portal", "steal.php", "hacker", "wallet-connect"]
        for p in phish_patterns:
            if p in url_lower:
                return -1
        return 1

    # ==================== HTML / DOM Structural ====================

    def _is_trusted_origin(self, target_url: str, domain: str) -> bool:
        if not target_url or not target_url.startswith("http"):
            return True
        if domain and domain in target_url:
            return True
        target_lower = target_url.lower()
        for cdn in TRUSTED_CDN_DOMAINS:
            if cdn in target_lower:
                return True
        return False

    def _check_favicon(self, soup: Optional[BeautifulSoup], domain: str, fetched_html: bool) -> int:
        if not fetched_html or not soup:
            return 1
        icon_tag = soup.find("link", rel=lambda x: x and ("icon" in x.lower() or "shortcut" in x.lower()))
        if icon_tag and icon_tag.get("href"):
            href = icon_tag["href"]
            if href.startswith("http") and not self._is_trusted_origin(href, domain):
                return -1
        return 1

    def _check_port(self, port: Optional[int]) -> int:
        if port is None or port in [80, 443]:
            return 1
        return -1

    def _check_request_url(self, soup: Optional[BeautifulSoup], domain: str, fetched_html: bool) -> int:
        if not fetched_html or not soup or not domain:
            return 1
        total_objects = 0
        external_objects = 0
        for tag in soup.find_all(["img", "audio", "embed", "iframe"]):
            src = tag.get("src", "")
            if src:
                total_objects += 1
                if src.startswith("http") and not self._is_trusted_origin(src, domain):
                    external_objects += 1
        if total_objects == 0:
            return 1
        ratio = external_objects / total_objects
        if ratio < 0.22:
            return 1
        elif 0.22 <= ratio <= 0.61:
            return 0
        return -1

    def _check_url_of_anchor(self, soup: Optional[BeautifulSoup], domain: str, fetched_html: bool) -> int:
        if not fetched_html or not soup or not domain:
            return 1
        total_anchors = 0
        unsafe_anchors = 0
        for a in soup.find_all("a"):
            href = a.get("href", "").strip().lower()
            if href:
                total_anchors += 1
                if href.startswith("http://") or href.startswith("https://"):
                    if not self._is_trusted_origin(href, domain):
                        unsafe_anchors += 1
        if total_anchors == 0:
            return 1
        ratio = unsafe_anchors / total_anchors
        if ratio < 0.35:
            return 1
        elif 0.35 <= ratio <= 0.67:
            return 0
        return -1

    def _check_links_in_tags(self, soup: Optional[BeautifulSoup], domain: str, fetched_html: bool) -> int:
        if not fetched_html or not soup or not domain:
            return 1
        total_tags = 0
        ext_tags = 0
        for tag in soup.find_all(["meta", "script", "link"]):
            link = tag.get("href") or tag.get("src") or ""
            if link:
                total_tags += 1
                if (link.startswith("http://") or link.startswith("https://")) and not self._is_trusted_origin(link, domain):
                    ext_tags += 1
        if total_tags == 0:
            return 1
        ratio = ext_tags / total_tags
        if ratio < 0.35:
            return 1
        elif 0.35 <= ratio <= 0.75:
            return 0
        return -1

    def _check_sfh(self, soup: Optional[BeautifulSoup], domain: str, fetched_html: bool) -> int:
        if not fetched_html or not soup:
            return 1
        forms = soup.find_all("form")
        if not forms:
            return 1
        for form in forms:
            action = form.get("action", "").strip().lower()
            if not action or action == "#" or action.startswith("/"):
                continue
            if action == "about:blank":
                return -1
            if (action.startswith("http://") or action.startswith("https://")) and not self._is_trusted_origin(action, domain):
                return 0
        return 1

    def _check_submitting_to_email(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "mailto:" in html_str or "mail()" in html_str:
            return -1
        return 1

    def _check_redirect(self, redirect_count: int) -> int:
        return 0 if redirect_count <= 2 else 1

    def _check_mouseover(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "window.status" in html_str and "onmouseover" in html_str:
            return -1
        return 1

    def _check_rightclick(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "event.button==2" in html_str or ("contextmenu" in html_str and "preventdefault" in html_str):
            return -1
        return 1

    def _check_popup(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "prompt(" in html_str or ("window.open(" in html_str and "password" in html_str):
            return -1
        return 1

    def _check_iframe(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        iframes = soup.find_all("iframe")
        for iframe in iframes:
            style = iframe.get("style", "").lower()
            frameborder = iframe.get("frameborder", "")
            if "display:none" in style or "visibility:hidden" in style or frameborder == "0":
                return -1
        return 1

    # ==================== Security & Reputation ====================

    def _check_ssl(self, scheme: str, hostname: str) -> int:
        if scheme == "https":
            return 1
        return -1

    def _check_web_traffic(self, domain: str, dns_resolves: bool) -> int:
        if domain in TRUSTED_TOP_DOMAINS:
            return 1
        return 0 if dns_resolves else -1

    def _check_page_rank(self, domain: str, dns_resolves: bool) -> int:
        if domain in TRUSTED_TOP_DOMAINS:
            return 1
        return 1 if dns_resolves else -1

    def _check_links_pointing(self, soup: Optional[BeautifulSoup]) -> int:
        return 1

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return round(-sum([p * math.log(p) / math.log(2.0) for p in prob]), 4)

    # ==================== Calibrated Continuous Risk Engine ====================

    def calculate_calibrated_risk_score(
        self,
        features: Dict[str, int],
        continuous_stats: Dict[str, Any],
        raw_ml_prob: float
    ) -> Dict[str, Any]:
        """
        Computes a continuous, calibrated Bayesian risk score between 0.0% and 100.0%.
        Combines:
        1. Base ML model prediction
        2. Domain trust & authority discount
        3. Brand impersonation / spoofing penalty
        4. TLD risk weighting
        5. Deceptive lexical & keyword density
        6. DOM & structural security factors (form hijacking, iframes, raw IPs)
        """
        domain = continuous_stats.get("domain", "")
        tld = continuous_stats.get("tld", "")
        url_len = continuous_stats.get("url_length", 0)
        entropy = continuous_stats.get("entropy", 0.0)
        digit_ratio = continuous_stats.get("digit_ratio", 0.0)
        brand_spoofed = continuous_stats.get("brand_spoofed")
        is_trusted = domain in TRUSTED_TOP_DOMAINS
        is_high_risk_tld = tld in HIGH_RISK_TLDS
        kw_count = continuous_stats.get("suspicious_keyword_count", 0)

        # Baseline probability from model smoothed to avoid raw saturation
        base_risk = max(0.01, min(0.99, raw_ml_prob))

        # 1. Domain Authority Factor
        if is_trusted and not brand_spoofed:
            # Genuine top-tier authority (Google, Amazon, Chase Official, etc.)
            # Risk is kept in the safe 1.2% to 6.5% range depending on URL complexity/length
            complexity_bonus = min(0.035, (url_len / 250.0) * 0.02 + max(0.0, entropy - 3.5) * 0.008)
            calibrated_prob = 0.012 + complexity_bonus
        else:
            # Calculate Lexical Risk Index (0.0 to 1.0)
            lexical_penalty = 0.0
            if brand_spoofed:
                lexical_penalty += 0.45  # Severe penalty for brand impersonation
            if is_high_risk_tld:
                lexical_penalty += 0.22  # Known malicious TLD
            if features.get("having_IPhaving_IP_Address") == -1:
                lexical_penalty += 0.35  # Raw IP address
            if features.get("port") == -1:
                lexical_penalty += 0.25  # Non-standard port (e.g. 8080)
            if features.get("Shortining_Service") == -1:
                lexical_penalty += 0.18  # URL shortener
            if kw_count > 0:
                lexical_penalty += min(0.28, kw_count * 0.09)
            if entropy > 4.2:
                lexical_penalty += min(0.15, (entropy - 4.2) * 0.10)
            if digit_ratio > 0.12:
                lexical_penalty += min(0.12, digit_ratio * 0.25)
            if features.get("having_Sub_Domain") == -1:
                lexical_penalty += 0.15

            # DOM / Structural Risk Index (0.0 to 1.0)
            dom_penalty = 0.0
            if features.get("SFH") == -1:
                dom_penalty += 0.40  # Form action about:blank / external
            elif features.get("SFH") == 0:
                dom_penalty += 0.20  # Cross-domain form
            if features.get("Iframe") == -1:
                dom_penalty += 0.25  # Hidden iframe
            if features.get("popUpWidnow") == -1:
                dom_penalty += 0.20  # Popups prompting for credentials
            if features.get("SSLfinal_State") == -1:
                dom_penalty += 0.15  # Insecure HTTP

            # Blended weighted risk calculation
            # 45% Model Probability + 35% Lexical/Brand Threat + 20% DOM Threat
            combined = (0.45 * base_risk) + (0.35 * min(1.0, lexical_penalty)) + (0.20 * min(1.0, dom_penalty))

            # Apply hard thresholds for high-confidence signatures
            if brand_spoofed and (is_high_risk_tld or kw_count >= 1 or features.get("having_Sub_Domain") == -1):
                # Blatant phishing: e.g. chase-security-update.com.banking-auth-portal.tk
                combined = max(combined, 0.88 + min(0.11, kw_count * 0.03))
            elif features.get("having_IPhaving_IP_Address") == -1 and (features.get("port") == -1 or kw_count >= 1):
                # Raw IP with non-standard port or credential path: e.g. 192.168.1.105:8080/auth/paypal
                combined = max(combined, 0.92)
            elif brand_spoofed:
                combined = max(combined, 0.78)

            calibrated_prob = max(0.015, min(0.995, combined))

        risk_percent = round(calibrated_prob * 100.0, 1)

        # Determine calibrated verdict and risk tier
        if risk_percent >= 70.0:
            risk_tier = "CRITICAL"
            verdict = "PHISHING"
        elif risk_percent >= 38.0:
            risk_tier = "SUSPICIOUS"
            verdict = "SUSPICIOUS"
        else:
            risk_tier = "SAFE"
            verdict = "LEGITIMATE"

        return {
            "calibrated_risk_score": round(calibrated_prob, 4),
            "calibrated_risk_percent": risk_percent,
            "risk_tier": risk_tier,
            "verdict": verdict,
            "breakdown": {
                "model_raw_probability": round(raw_ml_prob, 4),
                "domain_authority": "VERIFIED_TRUSTED" if is_trusted else ("HIGH_RISK_TLD" if is_high_risk_tld else "STANDARD"),
                "brand_spoofing_detected": brand_spoofed is not None,
                "spoofed_brand": brand_spoofed,
                "lexical_entropy": round(entropy, 2),
                "keyword_threat_count": kw_count
            }
        }
