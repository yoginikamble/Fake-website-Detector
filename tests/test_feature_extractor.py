"""
Unit tests for feature extractor module.
Tests lexical, structural, and protocol indicator extractions.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.feature_extractor import extract_url_features


class TestFeatureExtractor(unittest.TestCase):

    def test_ip_address_detection(self):
        """Should detect raw IP used as hostname."""
        url = "http://93.184.216.34/login"
        feats = extract_url_features(url)
        self.assertTrue(feats["ip_address_host"]["is_detected"])
        self.assertEqual(feats["ip_address_host"]["value"], "93.184.216.34")

    def test_domain_name_not_ip(self):
        """Should identify regular domain as not being a raw IP."""
        url = "https://example.com"
        feats = extract_url_features(url)
        self.assertFalse(feats["ip_address_host"]["is_detected"])

    def test_punycode_detection(self):
        """Should flag internationalized homograph domains starting with xn--."""
        url = "https://xn--apple-43a.com"
        feats = extract_url_features(url)
        self.assertTrue(feats["punycode"]["is_detected"])

        clean_url = "https://apple.com"
        clean_feats = extract_url_features(clean_url)
        self.assertFalse(clean_feats["punycode"]["is_detected"])

    def test_url_shortener_detection(self):
        """Should detect known link shorteners."""
        shorteners = [
            "https://bit.ly/3xSample",
            "https://tinyurl.com/abc1234",
            "https://t.co/9xyz"
        ]
        for s in shorteners:
            feats = extract_url_features(s)
            self.assertTrue(feats["url_shortener"]["is_detected"], f"Failed on shortener {s}")

    def test_suspicious_characters(self):
        """Should detect @ symbol, double slash in path, and excessive hyphens."""
        url_at = "http://legit-site.com@attacker-site.com/path"
        feats_at = extract_url_features(url_at)
        self.assertTrue(feats_at["suspicious_characters"]["has_at_symbol"])

        url_double_slash = "https://example.com//admin/login"
        feats_ds = extract_url_features(url_double_slash)
        self.assertTrue(feats_ds["suspicious_characters"]["has_double_slash_path"])

        url_hyphens = "https://paypal-security-update-center.com"
        feats_hy = extract_url_features(url_hyphens)
        self.assertTrue(feats_hy["suspicious_characters"]["excessive_hyphens"])
        self.assertGreaterEqual(feats_hy["suspicious_characters"]["hyphen_count"], 3)

    def test_sensitive_keywords_detection(self):
        """Should detect phishing keywords (login, verify, banking, account, etc.)."""
        url = "https://my-service.com/account/login/verify-credentials"
        feats = extract_url_features(url)
        self.assertTrue(feats["sensitive_keywords"]["is_detected"])
        self.assertIn("login", feats["sensitive_keywords"]["matched"])
        self.assertIn("verify", feats["sensitive_keywords"]["matched"])

    def test_url_length_tiers(self):
        """Should correctly categorize URL length into short, medium, or excessive."""
        short_url = "https://example.com/"
        feats_s = extract_url_features(short_url)
        self.assertTrue(feats_s["url_length"]["is_short"])
        self.assertFalse(feats_s["url_length"]["is_excessive"])

        long_url = "https://subdomain.example.com/very/long/nested/path/to/resource/with/very/extended/parameters?tracking_token=abcdefghijklmnopqrstuvwxyz1234567890"
        feats_l = extract_url_features(long_url)
        self.assertTrue(feats_l["url_length"]["is_excessive"])

    def test_typosquatting_detection(self):
        """Should detect brand lookalikes like go0gle.com and paypa1.com."""
        feats_google = extract_url_features("https://go0gle.com/")
        self.assertTrue(feats_google["typosquatting"]["is_detected"])
        self.assertEqual(feats_google["typosquatting"]["target_brand"], "google")

        feats_paypal = extract_url_features("https://paypa1.com/")
        self.assertTrue(feats_paypal["typosquatting"]["is_detected"])
        self.assertEqual(feats_paypal["typosquatting"]["target_brand"], "paypal")

        feats_legit = extract_url_features("https://www.google.com/")
        self.assertFalse(feats_legit["typosquatting"]["is_detected"])


if __name__ == "__main__":
    unittest.main()
