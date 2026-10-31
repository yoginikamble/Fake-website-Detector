"""
Unit tests for database management and CRUD operations.
Uses an isolated temporary SQLite database.
"""

import unittest
import tempfile
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import (
    init_db,
    insert_scan,
    get_scan_by_id,
    get_recent_scans,
    get_all_scans,
    get_dashboard_stats,
    delete_scan,
    clear_all_scans
)


class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Create a temporary database file for isolated testing."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        init_db(self.db_path)

    def tearDown(self):
        """Clean up temporary database file."""
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass

    def test_insert_and_retrieve_scan(self):
        """Should insert a scan record and retrieve it with parsed JSON findings."""
        sample_findings = {
            "features": {"url_length": {"value": 25}},
            "scoring": {"final_score": 15, "risk_category": "Low Risk Indicators"}
        }

        scan_id = insert_scan(
            submitted_url="https://legit-service.org",
            normalized_url="https://legit-service.org/",
            risk_score=15,
            risk_category="Low Risk Indicators",
            risk_tier="low",
            findings=sample_findings,
            scan_status="completed",
            resolved_ip="93.184.216.34",
            http_status=200,
            db_path=self.db_path
        )

        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

        record = get_scan_by_id(scan_id, db_path=self.db_path)
        self.assertIsNotNone(record)
        self.assertEqual(record["submitted_url"], "https://legit-service.org")
        self.assertEqual(record["risk_score"], 15)
        self.assertEqual(record["risk_tier"], "low")
        self.assertIsInstance(record["findings"], dict)
        self.assertEqual(record["findings"]["features"]["url_length"]["value"], 25)

    def test_dashboard_stats_calculation(self):
        """Should calculate real statistical counts directly from stored rows."""
        # Insert 1 Low, 1 Medium, 1 High
        insert_scan("http://low.com", "http://low.com", 10, "Low Risk", "low", {}, db_path=self.db_path)
        insert_scan("http://med.com", "http://med.com", 45, "Medium Risk", "medium", {}, db_path=self.db_path)
        insert_scan("http://high.com", "http://high.com", 85, "High Risk", "high", {}, db_path=self.db_path)

        stats = get_dashboard_stats(db_path=self.db_path)
        self.assertEqual(stats["total_scans"], 3)
        self.assertEqual(stats["low_risk_count"], 1)
        self.assertEqual(stats["medium_risk_count"], 1)
        self.assertEqual(stats["high_risk_count"], 1)
        self.assertEqual(stats["avg_risk_score"], 46.7)

    def test_search_and_filter(self):
        """Should filter scans by search term and risk category using parameterized SQL."""
        insert_scan("https://bank-alpha.com", "https://bank-alpha.com", 10, "Low Risk", "low", {}, db_path=self.db_path)
        insert_scan("https://bank-beta-phish.xyz", "https://bank-beta-phish.xyz", 80, "High Risk", "high", {}, db_path=self.db_path)

        # Search for 'phish'
        search_results = get_all_scans(search="phish", db_path=self.db_path)
        self.assertEqual(len(search_results), 1)
        self.assertEqual(search_results[0]["normalized_url"], "https://bank-beta-phish.xyz")

        # Filter by category 'low'
        low_results = get_all_scans(category="low", db_path=self.db_path)
        self.assertEqual(len(low_results), 1)
        self.assertEqual(low_results[0]["risk_tier"], "low")

    def test_delete_individual_and_clear_all(self):
        """Should delete single records and wipe all rows when requested."""
        id1 = insert_scan("http://site1.com", "http://site1.com", 10, "Low Risk", "low", {}, db_path=self.db_path)
        id2 = insert_scan("http://site2.com", "http://site2.com", 20, "Low Risk", "low", {}, db_path=self.db_path)

        # Delete single
        deleted = delete_scan(id1, db_path=self.db_path)
        self.assertTrue(deleted)
        self.assertIsNone(get_scan_by_id(id1, db_path=self.db_path))
        self.assertIsNotNone(get_scan_by_id(id2, db_path=self.db_path))

        # Clear all
        clear_all_scans(db_path=self.db_path)
        remaining = get_all_scans(db_path=self.db_path)
        self.assertEqual(len(remaining), 0)


if __name__ == "__main__":
    unittest.main()
