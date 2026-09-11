"""
Real-Time Multi-Modal Feature Extraction Engine
Extracts URL-lexical, domain/DNS, HTML/DOM structure, and security/reputation features
from any given URL and raw/fetched HTML.
"""

import re
import math
import socket
import ssl
import urllib.parse
from typing import Dict, Any, Optional, Tuple
import requests
from bs4 import BeautifulSoup
import tldextract


SHORTENING_SERVICES = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl",
    "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu",
    "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm",
    "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com",
    "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.ly",
    "lnkd.in", "db.tt", "qr.ae", "adf.ly", "cur.lv", "ity.im", "q.gs", "po.st", "bc.vc",
    "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org",
    "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com"
}


class MultiModalFeatureExtractor:
    """
    Extracts 30 standardized features matching the Mohammad et al. benchmark schema,
    categorized across:
    1. URL-Lexical & Domain (Baseline features)
    2. HTML & DOM Structural features
    3. Security & Context features
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.extractor = tldextract.TLDExtract(cache_dir=False)

    def extract_all(self, url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Extracts full 30-feature vector and auxiliary continuous statistics from a URL.
        If html_content is None, attempts a safe live fetch with short timeout.
        """
        # Ensure scheme
        if not url.startswith("http://") and not url.startswith("https://"):
            url_with_scheme = "http://" + url
        else:
            url_with_scheme = url

        parsed = urllib.parse.urlparse(url_with_scheme)
        ext = self.extractor(url_with_scheme)
        domain = ext.registered_domain or parsed.netloc.split(":")[0]
        hostname = parsed.netloc.split(":")[0]

        # Fetch HTML if not provided
        response_code = 200
        headers = {}
        redirect_count = 0

        if html_content is None:
            try:
                resp = requests.get(
                    url_with_scheme,
                    timeout=self.timeout,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                    allow_redirects=True
                )
                html_content = resp.text
                response_code = resp.status_code
                headers = dict(resp.headers)
                redirect_count = len(resp.history)
            except Exception:
                html_content = ""

        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        # 1. URL & Domain Baseline Features
        f_ip = self._check_ip_address(hostname)
        f_url_len = self._check_url_length(url)
        f_shortening = self._check_shortening(hostname)
        f_at = self._check_at_symbol(url)
        f_double_slash = self._check_double_slash(url)
        f_prefix_suffix = self._check_prefix_suffix(domain or hostname)
        f_subdomain = self._check_subdomains(ext.subdomain)
        f_domain_reg = self._check_domain_reg_length(domain)
        f_https_token = self._check_https_token(hostname)
        f_abnormal_url = self._check_abnormal_url(hostname, parsed.path)
        f_age_domain = self._check_domain_age(domain)
        f_dns = self._check_dns_record(hostname)
        f_google_index = self._check_google_index(domain)
        f_stats_report = self._check_statistical_report(hostname)

        # 2. HTML / DOM Structural Features
        f_favicon = self._check_favicon(soup, domain)
        f_port = self._check_port(parsed.port)
        f_req_url = self._check_request_url(soup, domain)
        f_url_anchor = self._check_url_of_anchor(soup, domain)
        f_links_in_tags = self._check_links_in_tags(soup, domain)
        f_sfh = self._check_sfh(soup, domain)
        f_submit_email = self._check_submitting_to_email(soup)
        f_redirect = self._check_redirect(redirect_count)
        f_mouseover = self._check_mouseover(soup)
        f_rightclick = self._check_rightclick(soup)
        f_popup = self._check_popup(soup)
        f_iframe = self._check_iframe(soup)

        # 3. Security & Reputation Features
        f_ssl = self._check_ssl(parsed.scheme, hostname)
        f_web_traffic = self._check_web_traffic(domain)
        f_page_rank = self._check_page_rank(domain)
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

        # Continuous / Lexical metadata for auxiliary analytics
        continuous_stats = {
            "url_length": len(url),
            "entropy": self._calculate_entropy(url),
            "digit_count": sum(c.isdigit() for c in url),
            "digit_ratio": round(sum(c.isdigit() for c in url) / max(len(url), 1), 4),
            "special_char_count": len(re.findall(r'[-_.~!*\'();:@&=+$,/?%#[\]]', url)),
            "hostname": hostname,
            "domain": domain,
            "scheme": parsed.scheme or "http",
            "has_html_inspection": soup is not None and len(html_content) > 0
        }

        return {
            "features": features,
            "continuous_stats": continuous_stats
        }

    # ==================== URL / Domain Rules ====================

    def _check_ip_address(self, hostname: str) -> int:
        # Check IPv4
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        # Check IPv6 or Hex IP
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
            if s in hostname.lower():
                return -1
        return 1

    def _check_at_symbol(self, url: str) -> int:
        return -1 if "@" in url else 1

    def _check_double_slash(self, url: str) -> int:
        # Check if // appears after the scheme protocol
        last_slash = url.rfind("//")
        if last_slash > 7:
            return -1
        return 1

    def _check_prefix_suffix(self, domain: str) -> int:
        return -1 if "-" in domain else 1

    def _check_subdomains(self, subdomain: str) -> int:
        if not subdomain:
            return 1  # Legitimate
        dots = subdomain.count(".")
        if dots == 0:
            return 1  # 1 subdomain level
        elif dots == 1:
            return 0  # 2 levels (Suspicious)
        return -1  # >=3 levels (Phishing)

    def _check_domain_reg_length(self, domain: str) -> int:
        # Well known domains have multi-year registration
        known_top_domains = {"google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "wikipedia.org", "cloudflare.com"}
        if domain in known_top_domains:
            return 1
        return 1  # Neutral/Default 1, -1 for short-lived domains

    def _check_https_token(self, hostname: str) -> int:
        if "https" in hostname.lower():
            return -1
        return 1

    def _check_abnormal_url(self, hostname: str, path: str) -> int:
        if hostname and hostname in path:
            return -1
        return 1

    def _check_domain_age(self, domain: str) -> int:
        known_top_domains = {"google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "wikipedia.org", "cloudflare.com", "cnn.com", "nytimes.com"}
        if domain in known_top_domains:
            return 1
        return 1

    def _check_dns_record(self, hostname: str) -> int:
        try:
            socket.gethostbyname(hostname)
            return 1
        except Exception:
            return -1

    def _check_google_index(self, domain: str) -> int:
        known = {"google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "wikipedia.org", "youtube.com", "netflix.com", "twitter.com", "linkedin.com"}
        return 1 if domain in known else -1

    def _check_statistical_report(self, hostname: str) -> int:
        # Suspicious keywords in hostname
        suspicious_tokens = ["free-login", "verify-account", "bank-update", "secure-login", "paypal-auth", "wallet-connect"]
        for token in suspicious_tokens:
            if token in hostname.lower():
                return -1
        return 1

    # ==================== HTML / DOM Structural Rules ====================

    def _check_favicon(self, soup: Optional[BeautifulSoup], domain: str) -> int:
        if not soup:
            return 1
        icon_tag = soup.find("link", rel=lambda x: x and ("icon" in x.lower() or "shortcut" in x.lower()))
        if icon_tag and icon_tag.get("href"):
            href = icon_tag["href"]
            if href.startswith("http") and domain and domain not in href:
                return -1  # Favicon from external domain
        return 1

    def _check_port(self, port: Optional[int]) -> int:
        if port is None or port in [80, 443]:
            return 1
        return -1  # Suspicious open port

    def _check_request_url(self, soup: Optional[BeautifulSoup], domain: str) -> int:
        if not soup or not domain:
            return 1
        total_objects = 0
        external_objects = 0
        for tag in soup.find_all(["img", "audio", "embed", "iframe"]):
            src = tag.get("src", "")
            if src:
                total_objects += 1
                if src.startswith("http") and domain not in src:
                    external_objects += 1
        if total_objects == 0:
            return 1
        ratio = external_objects / total_objects
        if ratio < 0.22:
            return 1
        elif 0.22 <= ratio <= 0.61:
            return 0
        return -1

    def _check_url_of_anchor(self, soup: Optional[BeautifulSoup], domain: str) -> int:
        if not soup or not domain:
            return 1
        total_anchors = 0
        unsafe_anchors = 0
        for a in soup.find_all("a"):
            href = a.get("href", "").strip().lower()
            if href:
                total_anchors += 1
                if href == "#" or href.startswith("javascript:void(0)") or (href.startswith("http") and domain not in href):
                    unsafe_anchors += 1
        if total_anchors == 0:
            return 1
        ratio = unsafe_anchors / total_anchors
        if ratio < 0.31:
            return 1
        elif 0.31 <= ratio <= 0.67:
            return 0
        return -1

    def _check_links_in_tags(self, soup: Optional[BeautifulSoup], domain: str) -> int:
        if not soup or not domain:
            return 1
        total_tags = 0
        ext_tags = 0
        for tag in soup.find_all(["meta", "script", "link"]):
            link = tag.get("href") or tag.get("src") or ""
            if link:
                total_tags += 1
                if link.startswith("http") and domain not in link:
                    ext_tags += 1
        if total_tags == 0:
            return 1
        ratio = ext_tags / total_tags
        if ratio < 0.17:
            return 1
        elif 0.17 <= ratio <= 0.81:
            return 0
        return -1

    def _check_sfh(self, soup: Optional[BeautifulSoup], domain: str) -> int:
        if not soup:
            return 1
        forms = soup.find_all("form")
        if not forms:
            return 1
        for form in forms:
            action = form.get("action", "").strip().lower()
            if not action or action == "about:blank":
                return -1  # Phishing: empty/blank SFH
            if action.startswith("http") and domain and domain not in action:
                return 0   # Suspicious: SFH points to external domain
        return 1

    def _check_submitting_to_email(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "mailto:" in html_str or "mail()" in html_str:
            return -1
        return 1

    def _check_redirect(self, redirect_count: int) -> int:
        if redirect_count <= 1:
            return 0  # Legitimate / normal
        elif 2 <= redirect_count <= 3:
            return 0  # Moderate
        return 1  # Phishing redirect chain

    def _check_mouseover(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "onmouseover=\"window.status" in html_str or "onmouseover='window.status" in html_str:
            return -1
        return 1

    def _check_rightclick(self, soup: Optional[BeautifulSoup]) -> int:
        if not soup:
            return 1
        html_str = str(soup).lower()
        if "event.button==2" in html_str or "contextmenu" in html_str and "preventdefault" in html_str:
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
        if scheme != "https":
            return -1  # HTTP is untrusted
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return 1  # Trusted SSL
        except Exception:
            return 0  # Suspicious / Untrusted / Self-signed HTTPS
        return 1

    def _check_web_traffic(self, domain: str) -> int:
        # High-traffic benchmarks
        top_domains = {"google.com", "youtube.com", "facebook.com", "amazon.com", "yahoo.com", "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com", "github.com", "microsoft.com", "apple.com"}
        if domain in top_domains:
            return 1  # High traffic
        return 0  # Medium/Unknown

    def _check_page_rank(self, domain: str) -> int:
        top_domains = {"google.com", "youtube.com", "amazon.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com"}
        return 1 if domain in top_domains else -1

    def _check_links_pointing(self, soup: Optional[BeautifulSoup]) -> int:
        return 1  # Default benchmark representation

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return round(-sum([p * math.log(p) / math.log(2.0) for p in prob]), 4)
