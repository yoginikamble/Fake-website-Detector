"""
Unit tests for risk scoring engine and category boundaries.
Validates scoring normalization, weighting, and itemized findings generation.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.feature_extractor import extract_url_features
from analyzer.risk_scorer import calculate_risk_score
import config


class TestRiskScorer(unittest.TestCase):

    def test_clean_url_low_risk(self):
        """Standard benign HTTPS site should receive a Low Risk category."""
        url = "https://example.com/"
        feats = extract_url_features(url)
        score_res = calculate_risk_score(feats)

        self.assertLess(score_res["final_score"], 30)
        self.assertEqual(score_res["risk_tier"], "low")
        self.assertEqual(score_res["risk_category"], config.RISK_LEVEL_LOW)
        self.assertGreater(len(score_res["positive_findings"]), 0)

    def test_medium_risk_boundary(self):
        """Moderate indicators (insecure HTTP + shortener) should register Medium Risk (30-59)."""
        url = "http://bit.ly/xyz12"
        feats = extract_url_features(url)
        score_res = calculate_risk_score(feats)

        self.assertGreaterEqual(score_res["final_score"], 30)
        self.assertLess(score_res["final_score"], 60)
        self.assertEqual(score_res["risk_tier"], "medium")
        self.assertEqual(score_res["risk_category"], config.RISK_LEVEL_MEDIUM)

    def test_high_risk_composite_indicators(self):
        """Severe compound indicators (IP host + @ symbol + sensitive keywords) should trigger High Risk."""
        url = "http://93.184.216.34@attacker.xyz/login/verify-paypal"
        feats = extract_url_features(url)
        score_res = calculate_risk_score(feats)

        self.assertGreaterEqual(score_res["final_score"], 60)
        self.assertEqual(score_res["risk_tier"], "high")
        self.assertEqual(score_res["risk_category"], config.RISK_LEVEL_HIGH)
        self.assertGreater(score_res["total_indicators_flagged"], 2)

    def test_score_never_exceeds_100(self):
        """Even with many compounding threat indicators, score must strictly clamp at 100."""
        # Extreme synthetic case with almost all negative indicators
        synth_features = {
            "ip_address_host": {"is_detected": True, "value": "1.2.3.4"},
            "punycode": {"is_detected": True},
            "url_shortener": {"is_detected": True},
            "suspicious_characters": {
                "has_at_symbol": True,
                "has_double_slash_path": True,
                "excessive_hyphens": True,
                "hyphen_count": 5
            },
            "subdomains": {"is_excessive": True, "count": 4},
            "sensitive_keywords": {"is_detected": True, "matched": ["login", "verify", "banking"]},
            "url_length": {"is_excessive": True, "value": 150},
            "protocol_and_port": {"is_https": False, "is_standard_port": False, "port": 8888},
            "tld_analysis": {"is_suspicious": True, "tld": ".xyz"},
            "live_fetch": {"completed": True, "ssl_valid": False, "security_headers": {}},
            "redirect_analysis": {"has_diverged_domain": True, "final_hostname": "different.com"}
        }
        score_res = calculate_risk_score(synth_features)
        self.assertEqual(score_res["final_score"], 100)
        self.assertEqual(score_res["risk_category"], config.RISK_LEVEL_HIGH)

    def test_uncompleted_checks_declared(self):
        """Must explicitly list uncompleted checks for academic transparency."""
        url = "https://example.com"
        feats = extract_url_features(url)
        score_res = calculate_risk_score(feats)

        uncompleted_names = [c["check"] for c in score_res["checks_uncompleted"]]
        self.assertTrue(any("WHOIS" in name for name in uncompleted_names))


if __name__ == "__main__":
    unittest.main()
