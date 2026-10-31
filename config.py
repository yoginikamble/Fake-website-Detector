"""
Configuration module for Fake Website Detector Using Web Security Analysis.
Contains environment settings, security limits, risk scoring thresholds, and feature weights.
"""

import os
from pathlib import Path

# Base directory paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.path.join(BASE_DIR, "database", "detector.db")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Flask Settings
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-cyber-security-secret-key-tycs-2026")
DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

# Safe Fetcher & Network Security Constraints (SSRF Protection)
REQUEST_TIMEOUT_SECONDS = 4.0
MAX_REDIRECTS = 4
MAX_RESPONSE_BYTES = 256 * 1024  # 256 KB limit to prevent resource exhaustion
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "FakeWebsiteDetectorBot/1.0 (Academic Security Scanner; TYCS Project)"
)

# Risk Thresholds
# Score 0 - 29: Low Risk Indicators
# Score 30 - 59: Medium Risk Indicators
# Score 60 - 100: High Risk Indicators
RISK_LEVEL_LOW = "Low Risk Indicators"
RISK_LEVEL_MEDIUM = "Medium Risk Indicators"
RISK_LEVEL_HIGH = "High Risk Indicators"

# Configurable Scoring Weights (points assigned when an indicator is detected)
WEIGHTS = {
    "ip_address_host": 25,
    "excessive_url_length": 15,
    "medium_url_length": 8,
    "at_symbol": 25,
    "double_slash_path": 15,
    "excessive_hyphens": 16,
    "excessive_subdomains": 18,
    "punycode_domain": 22,
    "url_shortener": 16,
    "sensitive_keywords": 18,
    "insecure_http": 15,
    "non_standard_port": 18,
    "suspicious_tld": 16,
    "ssl_error": 22,
    "redirect_divergence": 18,
    "excessive_redirects": 10,
    "missing_security_headers": 6,
    "reputation_flagged": 40,
    "brand_typosquatting": 45,
    "leetspeak_in_domain": 25,
    "dns_resolution_failed": 25
}

# High-value brands commonly targeted by phishing and typosquatting attacks
POPULAR_BRANDS = {
    "google", "paypal", "amazon", "microsoft", "apple", "facebook",
    "netflix", "instagram", "twitter", "whatsapp", "youtube", "yahoo",
    "linkedin", "chase", "wellsfargo", "bankofamerica", "citibank",
    "binance", "coinbase", "ebay", "steam", "roblox", "github",
    "walmart", "target", "adobe", "dropbox", "telegram", "spotify",
    "tiktok", "snapchat", "reddit", "outlook", "office365", "gmail",
    "icloud", "meta", "crypto", "blockchain", "metamask", "gemini"
}

# Character homoglyphs and leetspeak substitution mappings
LEET_CHAR_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s"
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "adf.ly", "tiny.cc", "rebrand.ly",
    "bl.ink", "shorte.st", "s.id", "soo.gd", "bc.vc", "rb.gy"
}

# Suspicious keywords commonly found in phishing campaigns
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "account", "banking", "wallet", "paypal", "appleid",
    "support", "password", "authenticate", "confirm", "recovery",
    "free-gift", "claim-reward", "ebaysapi", "webscr", "pay-confirm"
}

# High-abuse or frequently flagged free/cheap TLDs in phishing datasets
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz",
    ".fit", ".work", ".bar", ".rest", ".monster", ".cam", ".click",
    ".kim", ".sbs", ".cfd"
}

# Optional Threat Intelligence API (Disabled by default, configured via .env)
THREAT_API_KEY = os.environ.get("THREAT_API_KEY", "").strip()
THREAT_API_PROVIDER = os.environ.get("THREAT_API_PROVIDER", "None").strip()
