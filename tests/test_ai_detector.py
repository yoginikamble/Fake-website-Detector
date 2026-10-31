"""
Unit tests for Machine Learning AI Detection Engine.
Validates feature vector generation, Random Forest inference, and model persistence.
"""

import unittest
import sys
import os
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.ai_detector import (
    extract_ml_features,
    predict_url_ai,
    get_model,
    FEATURE_NAMES
)


class TestAiDetector(unittest.TestCase):

    def test_extract_ml_features_dimensions(self):
        """Feature vector must match FEATURE_NAMES dimensions (18 features)."""
        url = "https://example.com/test"
        vec, feat_dict = extract_ml_features(url)

        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertEqual(len(feat_dict), len(FEATURE_NAMES))
        self.assertEqual(list(feat_dict.keys()), FEATURE_NAMES)

    def test_model_prediction_legitimate_url(self):
        """AI should predict benign legitimate status for typical authentic domain."""
        url = "https://www.google.com/"
        pred = predict_url_ai(url)

        self.assertIn("ai_verdict", pred)
        self.assertIn("phishing_probability", pred)
        self.assertLess(pred["phishing_probability"], 50.0)
        self.assertEqual(pred["badge_class"], "success")
        self.assertFalse(pred["is_phishing"])

    def test_model_prediction_phishing_url(self):
        """AI should flag typical phishing structural pattern with high probability."""
        url = "http://paypal-security-update.account-verify.xyz/login"
        pred = predict_url_ai(url)

        self.assertGreaterEqual(pred["phishing_probability"], 50.0)
        self.assertTrue(pred["is_phishing"])
        self.assertIn("Phishing", pred["ai_verdict"])

    def test_typosquatting_prediction_go0gle(self):
        """AI should identify go0gle.com typosquatting as high-confidence phishing."""
        url = "https://go0gle.com/"
        pred = predict_url_ai(url)

        self.assertGreaterEqual(pred["phishing_probability"], 70.0)
        self.assertTrue(pred["is_phishing"])
        self.assertIn("Phishing", pred["ai_verdict"])

    def test_explainable_ai_top_features(self):
        """Top features list must provide explainable weights."""
        url = "https://example.com/"
        pred = predict_url_ai(url)

        self.assertGreater(len(pred["top_features"]), 0)
        for feat in pred["top_features"]:
            self.assertIn("name", feat)
            self.assertIn("importance", feat)
            self.assertIn("value", feat)

    def test_model_persistence(self):
        """Model should load properly from disk."""
        model = get_model()
        self.assertIsNotNone(model)
        self.assertTrue(hasattr(model, "predict_proba"))


if __name__ == "__main__":
    unittest.main()
