"""
AI / Machine Learning Detection Engine.
Fake Website Detector Using Web Security Analysis (TYCS Project).

Implements:
1. Lexical and structural feature vector extraction (18 numerical features per URL, including typosquatting).
2. Random Forest Machine Learning classifier for phishing and brand impersonation prediction.
3. Feature importance explanation (Explainable AI / XAI).
4. Auto-training and model persistence using joblib.
"""

import os
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

from .url_validator import is_ip_address
from .feature_extractor import check_typosquatting
import config

# Path to the serialized ML model
MODEL_DIR = os.path.join(config.BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_rf_model.joblib")

# Ordered list of feature names used by the ML model (18 features)
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "has_ip_address",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_double_slash",
    "count_subdomains",
    "is_https",
    "count_digits",
    "digit_ratio",
    "has_punycode",
    "is_shortener",
    "count_sensitive_keywords",
    "count_special_chars",
    "suspicious_tld",
    "is_typosquatting",
    "has_digit_in_domain"
]


def extract_ml_features(url: str) -> Tuple[np.ndarray, Dict[str, float]]:
    """
    Transforms a URL string into an 18-dimensional numerical feature vector for the ML model.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    url_lower = url.lower()

    # 1. Total length of URL
    url_length = float(len(url))

    # 2. Domain length
    domain_length = float(len(hostname))

    # 3. Direct IP address as host
    has_ip = 1.0 if is_ip_address(hostname) else 0.0

    # 4. Dot count
    count_dots = float(url.count("."))

    # 5. Hyphen count
    count_hyphens = float(url.count("-"))

    # 6. '@' symbol count
    count_at = float(url.count("@"))

    # 7. Double slash '//' in path count
    count_double_slash = float(path.count("//"))

    # 8. Subdomains count
    clean_host = hostname[4:] if hostname.startswith("www.") else hostname
    parts = [p for p in clean_host.split(".") if p]
    count_subdomains = float(max(0, len(parts) - 2))

    # 9. HTTPS protocol
    is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0

    # 10. Digit count
    digits = sum(1 for c in url if c.isdigit())
    count_digits = float(digits)

    # 11. Digit ratio
    digit_ratio = float(digits / max(1, len(url)))

    # 12. Punycode presence
    has_punycode = 1.0 if "xn--" in hostname else 0.0

    # 13. URL shortener presence
    is_short = 1.0 if (hostname in config.SHORTENER_DOMAINS or any(hostname.endswith("." + d) for d in config.SHORTENER_DOMAINS)) else 0.0

    # 14. Count of sensitive security keywords
    kw_count = float(sum(1 for kw in config.SUSPICIOUS_KEYWORDS if kw in url_lower))

    # 15. Count of special query characters (?, =, &, %, _)
    special_chars = sum(url.count(c) for c in ["?", "=", "&", "%", "_"])
    count_special_chars = float(special_chars)

    # 16. Suspicious TLD
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    suspicious_tld = 1.0 if tld in config.SUSPICIOUS_TLDS else 0.0

    # 17. Brand Impersonation / Typosquatting flag
    typo_info = check_typosquatting(hostname)
    is_typosquat = 1.0 if typo_info.get("is_detected") else 0.0

    # 18. Digits inside domain label (e.g. go0gle has '0' inside brand label)
    domain_labels = [p for p in clean_host.split(".") if p]
    # Check non-TLD labels
    target_labels = domain_labels[:-1] if len(domain_labels) >= 2 else domain_labels
    has_digit_in_domain = 1.0 if any(any(c.isdigit() for c in l) for l in target_labels) else 0.0

    features_dict = {
        "url_length": url_length,
        "domain_length": domain_length,
        "has_ip_address": has_ip,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_double_slash": count_double_slash,
        "count_subdomains": count_subdomains,
        "is_https": is_https,
        "count_digits": count_digits,
        "digit_ratio": digit_ratio,
        "has_punycode": has_punycode,
        "is_shortener": is_short,
        "count_sensitive_keywords": kw_count,
        "count_special_chars": count_special_chars,
        "suspicious_tld": suspicious_tld,
        "is_typosquatting": is_typosquat,
        "has_digit_in_domain": has_digit_in_domain
    }

    vector = np.array([features_dict[name] for name in FEATURE_NAMES], dtype=np.float32)
    return vector, features_dict


# Curated baseline training dataset of legitimate and phishing URL patterns
TRAINING_DATASET: List[Tuple[str, int]] = [
    # Legitimate URLs (Label: 0)
    ("https://www.google.com/", 0),
    ("https://www.wikipedia.org/wiki/Computer_science", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://www.microsoft.com/en-us/windows", 0),
    ("https://www.apple.com/iphone/", 0),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://www.linkedin.com/feed/", 0),
    ("https://docs.python.org/3/library/urllib.parse.html", 0),
    ("https://pypi.org/project/scikit-learn/", 0),
    ("https://flask.palletsprojects.com/en/3.0.x/", 0),
    ("https://www.kaggle.com/datasets", 0),
    ("https://developer.mozilla.org/en-US/docs/Web", 0),
    ("https://www.reddit.com/r/Python/", 0),
    ("https://www.bbc.com/news/technology", 0),
    ("https://www.cnn.com/world", 0),
    ("https://www.nytimes.com/", 0),
    ("https://news.ycombinator.com/", 0),
    ("https://scholar.google.com/", 0),
    ("https://www.harvard.edu/academics/", 0),
    ("https://www.mit.edu/education/", 0),
    ("https://www.stanford.edu/research/", 0),
    ("https://www.ox.ac.uk/admissions", 0),
    ("https://getbootstrap.com/docs/5.3/getting-started/introduction/", 0),
    ("https://www.chartjs.org/docs/latest/", 0),
    ("https://sqlite.org/docs.html", 0),
    ("https://www.cloudflare.com/learning/security/what-is-ssl/", 0),
    ("https://aws.amazon.com/free/", 0),
    ("https://www.paypal.com/signin", 0),
    ("https://www.facebook.com/login", 0),
    ("https://twitter.com/explore", 0),
    ("https://www.instagram.com/", 0),

    # Phishing / Deceptive URLs (Label: 1)
    ("http://paypal-security-update.account-verify.xyz/login", 1),
    ("http://192.168.1.100@bank-login.com/secure/account", 1),
    ("http://login.appleid.apple.com.verify-recovery.net/signin", 1),
    ("http://update-chase-online-banking-security.tk/auth", 1),
    ("http://netflix-billing-verification.com//login/user", 1),
    ("http://secure-wellsfargo-account-update.xyz/login.php", 1),
    ("http://verify-microsoft-office365-passwords.cf/login", 1),
    ("http://amazon-account-suspended-action-required.top/signin", 1),
    ("http://93.184.216.34/bank/login.php?user=admin", 1),
    ("https://xn--pypal-4ve.com/account/signin", 1),
    ("http://bit.ly/secure-paypal-payment-verify-2026", 1),
    ("http://cutt.ly/bankofamerica-login-confirm", 1),
    ("http://online-banking-security-update-alert.buzz/verify", 1),
    ("http://facebook-security-checkup-checkpoint.ml/checkpoint", 1),
    ("http://instagram-copyright-infringement-appeal.ga/verify", 1),
    ("http://crypto-binance-wallet-recovery-phrase.fit/wallet", 1),
    ("http://metamask-extension-seed-phrase-restore.work/import", 1),
    ("http://steam-community-free-skins-giveaway.gq/claim", 1),
    ("http://ebay-dispute-resolution-case-status.cam/login", 1),
    ("http://dhl-express-package-delivery-failed-fee.monster/track", 1),
    ("http://fedex-parcel-pending-customs-payment.bar/pay", 1),
    ("http://irs-tax-refund-direct-deposit-claim.cfd/refund", 1),
    ("http://gov-stimulus-payment-registration-portal.sbs/claim", 1),
    ("http://google-drive-shared-confidential-document.click/view", 1),
    ("http://dropbox-secure-file-download-viewer.kim/download", 1),
    ("http://twitter-blue-verification-badge-claim.top/apply", 1),
    ("http://whatsapp-web-desktop-sync-qr-code.xyz/scan", 1),
    ("http://binance-kyc-identity-verification-portal.rest/verify", 1),
    ("http://coinbase-pro-security-lockout-unlock.bar/signin", 1),
    ("http://att-yahoo-mail-storage-quota-exceeded.top/webmail", 1),

    # Typosquatting / Lookalike Brand Spoofing URLs (Label: 1)
    ("https://go0gle.com/", 1),
    ("http://go0gle.com/", 1),
    ("https://paypa1.com/", 1),
    ("http://amaz0n.com/", 1),
    ("https://app1e.com/", 1),
    ("https://faceb00k.com/", 1),
    ("http://netfl1x.com/", 1),
    ("https://micros0ft.com/", 1),
    ("http://goolge.com/", 1),
    ("https://tw1tter.com/", 1),
    ("http://instagrarn.com/", 1),
    ("http://chasee.com/", 1)
]


def train_and_save_model() -> RandomForestClassifier:
    """
    Trains the Random Forest Machine Learning model and persists it to disk.
    """
    os.makedirs(MODEL_DIR, exist_ok=True)

    X_list = []
    y_list = []

    for url, label in TRAINING_DATASET:
        vec, _ = extract_ml_features(url)
        X_list.append(vec)
        y_list.append(label)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)

    # Train Random Forest with 100 estimators and fixed random state for reproducibility
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=2,
        random_state=42
    )
    rf.fit(X, y)

    joblib.dump(rf, MODEL_PATH)
    return rf


def get_model() -> RandomForestClassifier:
    """
    Retrieves the serialized ML model or trains a new one if not yet created.
    """
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            # Ensure model feature count matches current FEATURE_NAMES count (18)
            if model.n_features_in_ == len(FEATURE_NAMES):
                return model
            else:
                return train_and_save_model()
        except Exception:
            return train_and_save_model()
    else:
        return train_and_save_model()


def predict_url_ai(url: str) -> Dict[str, Any]:
    """
    Runs the Machine Learning classifier on the given URL.
    
    Returns structured dictionary with:
    - is_phishing: bool
    - phishing_probability: float (0.0 to 100.0)
    - legitimate_probability: float (0.0 to 100.0)
    - ai_verdict: str
    - ai_confidence: str ("High", "Moderate", "Low")
    - badge_class: str
    - top_contributing_features: list of (feature_name, importance_weight, current_value)
    - model_name: str
    """
    model = get_model()
    vector, features_dict = extract_ml_features(url)
    vector_2d = vector.reshape(1, -1)

    # Class probabilities [P(Legitimate), P(Phishing)]
    probs = model.predict_proba(vector_2d)[0]
    p_legit = round(float(probs[0]) * 100, 1)
    p_phish = round(float(probs[1]) * 100, 1)

    # Feature importances from the Random Forest model
    importances = model.feature_importances_
    ranked_indices = np.argsort(importances)[::-1]

    top_features = []
    for idx in ranked_indices[:4]:
        feat_name = FEATURE_NAMES[idx]
        top_features.append({
            "name": feat_name.replace("_", " ").title(),
            "importance": round(float(importances[idx]) * 100, 1),
            "value": features_dict[feat_name]
        })

    # Determine Verdict & Confidence Tier
    if p_phish >= 65.0:
        ai_verdict = "AI Predicts: High-Confidence Phishing"
        ai_confidence = "High Confidence"
        badge_class = "danger"
        is_phishing = True
    elif p_phish >= 40.0:
        ai_verdict = "AI Predicts: Suspicious / Potential Phishing"
        ai_confidence = "Moderate Confidence"
        badge_class = "warning"
        is_phishing = True
    else:
        ai_verdict = "AI Predicts: Likely Legitimate Website"
        ai_confidence = "High Confidence" if p_legit >= 75.0 else "Moderate Confidence"
        badge_class = "success"
        is_phishing = False

    return {
        "model_name": "Random Forest Ensemble (100 Decision Trees)",
        "is_phishing": is_phishing,
        "phishing_probability": p_phish,
        "legitimate_probability": p_legit,
        "ai_verdict": ai_verdict,
        "ai_confidence": ai_confidence,
        "badge_class": badge_class,
        "top_features": top_features,
        "features_dict": features_dict
    }
