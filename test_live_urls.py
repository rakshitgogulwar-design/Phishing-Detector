from src.feature_extractor import MultiModalFeatureExtractor
from src.proposed_model import ProposedMultiModalPipeline
from src.baseline_model import BaselinePipeline
import pandas as pd

ext = MultiModalFeatureExtractor()
prop = ProposedMultiModalPipeline.load('models/proposed_champion.joblib')
base = BaselinePipeline.load('models/baseline_rf.joblib')

test_cases = [
    # Legitimate websites
    ('https://google.com', 0, "Official Search"),
    ('https://github.com', 0, "Official Code Hosting"),
    ('https://amazon.com', 0, "Official E-Commerce"),
    ('https://wikipedia.org', 0, "Official Encyclopedia"),
    ('https://stackoverflow.com', 0, "Official Developer Forum"),
    ('https://microsoft.com', 0, "Official Enterprise"),
    ('https://apple.com', 0, "Official Tech"),
    ('https://netflix.com', 0, "Official Streaming"),

    # Phishing attacks
    ('http://chase-security-update.com.banking-auth-portal.tk/login.php', 1, "Subdomain Spoofing"),
    ('http://192.168.1.105:8080/auth/paypal/verify-account', 1, "Raw IP + Nonstandard Port"),
    ('http://bit.ly/secure-login-microsoft-portal', 1, "Shortener Phishing"),
    ('http://paypal-account-verification-alert.ru/login', 1, "Keyword Deception"),
]

print("-" * 90)
print(f"{'Target URL':<55} | {'Exp':<4} | {'Proposed':<10} | {'Risk %':<8} | {'Status'}")
print("-" * 90)

passed = 0
for u, exp, desc in test_cases:
    f = ext.extract_all(u)['features']
    df = pd.DataFrame([f])
    pred = int(prop.predict(df)[0])
    prob = float(prop.predict_proba(df)[0, 1])
    lbl = 'PHISHING' if pred == 1 else 'LEGITIMATE'
    status = '[PASS]' if pred == exp else '[FAIL]'
    if pred == exp:
        passed += 1
    print(f"{u:<55} | {exp:<4} | {lbl:<10} | {prob*100:>6.2f}% | {status}")

print("-" * 90)
print(f"Test Accuracy: {passed}/{len(test_cases)} ({passed/len(test_cases)*100:.1f}%)")
