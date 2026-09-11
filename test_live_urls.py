"""
Automated Multi-Modal Verification Suite: Live Legitimate & Phishing URLs
Evaluates 35+ diverse real-world targets across:
1. Legitimate Tech, Search, Financial, E-Commerce, Media, and Educational Institutions.
2. Zero-Day Phishing Attacks: Brand Spoofing, Subdomain Cloaking, Raw IPs, High-Risk TLDs, and Credential Harvesters.
Validates multi-signal calibrated risk scoring, differentiation, and latency.
"""

import time
import pandas as pd
from src.feature_extractor import MultiModalFeatureExtractor
from src.proposed_model import ProposedMultiModalPipeline
from src.baseline_model import BaselinePipeline

ext = MultiModalFeatureExtractor(timeout=1.0)
prop = ProposedMultiModalPipeline.load('models/proposed_champion.joblib')
base = BaselinePipeline.load('models/baseline_rf.joblib')

test_cases = [
    # =========================================================================
    # 1. LEGITIMATE WEBSITES (Major Tech, Search, Media, E-Commerce, Financial)
    # =========================================================================
    ('https://www.google.com', 0, "Google Search Engine"),
    ('https://github.com/login', 0, "GitHub Developer Platform"),
    ('https://www.amazon.com/dp/B08N5WRWNW', 0, "Amazon E-Commerce"),
    ('https://en.wikipedia.org/wiki/Phishing', 0, "Wikipedia Knowledge Base"),
    ('https://stackoverflow.com/questions', 0, "StackOverflow Community"),
    ('https://www.microsoft.com/en-us', 0, "Microsoft Corporate Portal"),
    ('https://www.apple.com/iphone', 0, "Apple Official Storefront"),
    ('https://www.netflix.com/browse', 0, "Netflix Streaming Service"),
    ('https://chatgpt.com', 0, "ChatGPT AI Platform"),
    ('https://openai.com/research', 0, "OpenAI Research Portal"),
    ('https://www.paypal.com/signin', 0, "PayPal Official Authentication"),
    ('https://www.chase.com', 0, "Chase Bank Official Portal"),
    ('https://www.bankofamerica.com', 0, "Bank of America Official"),
    ('https://www.wellsfargo.com', 0, "Wells Fargo Official Portal"),
    ('https://www.cnn.com', 0, "CNN News Media"),
    ('https://www.bbc.com/news', 0, "BBC News Global"),
    ('https://www.nytimes.com', 0, "New York Times"),
    ('https://www.reddit.com/r/technology', 0, "Reddit Discussion Platform"),
    ('https://www.spotify.com/us', 0, "Spotify Music Streaming"),
    ('https://www.dropbox.com/home', 0, "Dropbox Cloud Storage"),
    ('https://developer.mozilla.org/en-US', 0, "Mozilla Developer Network"),
    ('https://huggingface.co/models', 0, "Hugging Face Machine Learning Hub"),
    ('https://www.coursera.org', 0, "Coursera Learning Platform"),
    ('https://www.mercedes-benz.com', 0, "Mercedes-Benz Official (Hyphenated)"),
    ('https://www.coca-cola.com', 0, "Coca-Cola Official (Hyphenated)"),

    # =========================================================================
    # 2. PHISHING ATTACKS (Brand Spoofing, Subdomains, IPs, TLDs, Kit Traps)
    # =========================================================================
    ('http://chase-security-update.com.banking-auth-portal.tk/login.php', 1, "Chase Subdomain + .tk Cloaking"),
    ('http://192.168.1.105:8080/auth/paypal/verify-account', 1, "Raw IP + Port 8080 Credential Trap"),
    ('http://bit.ly/secure-login-microsoft-portal', 1, "Bit.ly Shortener Spoofing Microsoft"),
    ('http://paypal-account-verification-alert.ru/login', 1, "PayPal Impersonation on .ru TLD"),
    ('http://appleid-apple.com-verify.account-update.info/login', 1, "Apple ID Multi-Subdomain Theft"),
    ('http://chaseonline.banking-security-check.com/signin', 1, "Chase Online Banking Mimicry"),
    ('http://microsoft-support-security-alert01.tk/verify', 1, "Microsoft Support Alert on .tk"),
    ('http://netflix-billing-renewal-notice.com/update', 1, "Netflix Billing Phishing Scam"),
    ('http://amazon-account-suspension-resolve.org/auth', 1, "Amazon Suspension Phishing"),
    ('http://secure-login.bankofamerica.verify-credentials.com/', 1, "Bank of America Credential Harvest"),
    ('http://wellsfargo-secure-banking-logon.net/login.jsp', 1, "Wells Fargo Banking Logon Clone"),
    ('http://binance-login-verification-security.com/auth', 1, "Binance Crypto Wallet Hijack"),
    ('http://metamask-io-wallet-restore.tk/vault', 1, "MetaMask Seed Phrase Theft (.tk)"),
    ('http://facebook-security-check-account-confirm.info/', 1, "Facebook Account Security Mimic"),
    ('http://instagram-help-copyright-infringement.com/support', 1, "Instagram Copyright Phishing"),
    ('http://steamcommunity.com.id73849-trade.ru/trade', 1, "Steam Trade Community Fraud"),
]


def run_test_suite():
    print("=" * 115)
    print(f"{'Target URL':<58} | {'Exp':<4} | {'Verdict':<10} | {'Calib Risk':<10} | {'Raw ML':<8} | {'Latency':<7} | {'Status'}")
    print("=" * 115)

    passed = 0
    unique_risk_scores = set()
    total_time = 0.0

    for u, exp, desc in test_cases:
        t0 = time.perf_counter()
        res = ext.extract_all(u)
        feats = res['features']
        stats = res['continuous_stats']
        df = pd.DataFrame([feats])
        
        raw_prob = float(prop.predict_proba(df)[0, 1])
        calib = ext.calculate_calibrated_risk_score(feats, stats, raw_prob)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        total_time += elapsed_ms

        calib_risk_pct = calib['calibrated_risk_percent']
        pred_label = calib['verdict']
        pred_num = 1 if pred_label == 'PHISHING' else (0 if pred_label == 'LEGITIMATE' else (1 if calib_risk_pct >= 50 else 0))
        
        unique_risk_scores.add(calib_risk_pct)
        status = '[PASS]' if pred_num == exp else '[FAIL]'
        if pred_num == exp:
            passed += 1

        url_disp = (u[:55] + '..') if len(u) > 57 else u
        print(f"{url_disp:<58} | {exp:<4} | {pred_label:<10} | {calib_risk_pct:>8.1f}% | {raw_prob*100:>6.1f}% | {elapsed_ms:>5.1f}ms | {status}")

    total_tests = len(test_cases)
    accuracy = (passed / total_tests) * 100.0
    avg_latency = total_time / total_tests

    print("=" * 115)
    print(f"RESULTS SUMMARY:")
    print(f"Total Targets Tested:       {total_tests}")
    print(f"Passed Validations:         {passed} / {total_tests} ({accuracy:.1f}%)")
    print(f"Distinct Risk Scores Count: {len(unique_risk_scores)} (No score uniformity)")
    print(f"Average Inspection Latency: {avg_latency:.2f} ms per target")
    print(f"Risk Score Range:           {min(unique_risk_scores):.1f}% - {max(unique_risk_scores):.1f}%")
    print("=" * 115)

    assert accuracy >= 90.0, f"Accuracy {accuracy:.1f}% below threshold!"
    assert len(unique_risk_scores) >= 10, "Risk scores lack differentiation!"


if __name__ == '__main__':
    run_test_suite()
