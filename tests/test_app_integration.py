"""
Integration tests for Flask application routes, exports, and workflows.
"""

import unittest
import tempfile
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from database.db import init_db
import config


class TestAppIntegration(unittest.TestCase):

    def setUp(self):
        """Configure test client with temporary database."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()

        # Override database path for testing
        config.DATABASE_PATH = self.db_path
        init_db(self.db_path)

        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass

    def test_home_page(self):
        """Should render home page successfully."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Fake Website Detector", resp.data)
        self.assertIn(b"Analyze Website", resp.data)

    def test_dashboard_page(self):
        """Should render dashboard page with zero stats initially."""
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Analytics Dashboard", resp.data)

    def test_api_stats_endpoint(self):
        """Should return real JSON statistics."""
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total_scans", data)
        self.assertIn("low_risk", data)
        self.assertEqual(data["total_scans"], 0)

    def test_analyze_empty_url(self):
        """Should redirect back to home on empty submission."""
        resp = self.client.post("/analyze", data={"url": ""}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Please enter a website URL", resp.data)

    def test_analyze_ssrf_blocked_url(self):
        """Should reject private IP addresses to prevent SSRF."""
        resp = self.client.post("/analyze", data={"url": "http://127.0.0.1:8080/admin"}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Violation", resp.data)

    def test_full_analysis_workflow_and_export(self):
        """
        Executes end-to-end scan workflow:
        1. Submit test domain
        2. View results page
        3. Export report in TXT, CSV, JSON
        4. Check history listing
        5. Delete scan record
        """
        # Step 1: Submit scan
        post_resp = self.client.post("/analyze", data={"url": "https://example.com"}, follow_redirects=False)
        self.assertEqual(post_resp.status_code, 302)
        redirect_url = post_resp.headers["Location"]
        self.assertIn("/results/", redirect_url)

        # Step 2: Access results
        results_resp = self.client.get(redirect_url)
        self.assertEqual(results_resp.status_code, 200)
        self.assertIn(b"Aggregated Risk Index", results_resp.data)
        self.assertIn(b"https://example.com/", results_resp.data)

        # Extract scan ID
        scan_id = int(redirect_url.split("/results/")[-1])

        # Step 3: Test export endpoints
        txt_resp = self.client.get(f"/export/{scan_id}/txt")
        self.assertEqual(txt_resp.status_code, 200)
        self.assertIn(b"ACADEMIC WEB SECURITY SCAN REPORT", txt_resp.data)

        csv_resp = self.client.get(f"/export/{scan_id}/csv")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn(b"Scan ID", csv_resp.data)

        json_resp = self.client.get(f"/export/{scan_id}/json")
        self.assertEqual(json_resp.status_code, 200)
        self.assertIn(b"Fake Website Detector Using Web Security Analysis", json_resp.data)

        # Step 4: Check history listing
        hist_resp = self.client.get("/history")
        self.assertEqual(hist_resp.status_code, 200)
        self.assertIn(b"example.com", hist_resp.data)

        # Step 5: Delete scan record
        del_resp = self.client.post(f"/history/delete/{scan_id}", follow_redirects=True)
        self.assertEqual(del_resp.status_code, 200)
        self.assertIn(b"successfully deleted", del_resp.data)

    def test_about_page(self):
        """Should render about project page."""
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Project Objectives &amp; System Scope", resp.data)
        self.assertIn(b"Project Viva Guide", resp.data)


if __name__ == "__main__":
    unittest.main()
