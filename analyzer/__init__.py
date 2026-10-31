"""
Analyzer package for Fake Website Detector Using Web Security Analysis.
Provides URL validation, safe network fetching, feature extraction, risk scoring,
and Machine Learning AI prediction.
"""

from .url_validator import validate_url, normalize_url, is_ip_address, is_safe_ip_address
from .safe_fetcher import safe_fetch_url
from .feature_extractor import extract_url_features
from .risk_scorer import calculate_risk_score
from .reputation_checker import check_domain_reputation
from .ai_detector import predict_url_ai, extract_ml_features

__all__ = [
    "validate_url",
    "normalize_url",
    "is_ip_address",
    "is_safe_ip_address",
    "safe_fetch_url",
    "extract_url_features",
    "calculate_risk_score",
    "check_domain_reputation",
    "predict_url_ai",
    "extract_ml_features",
]
