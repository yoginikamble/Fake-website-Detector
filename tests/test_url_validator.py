"""
Unit tests for URL validation, normalization, and SSRF prevention.
Synthetic test cases for academic verification.
"""

import unittest
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.url_validator import (
    validate_url,
    normalize_url,
    is_ip_address,
    is_safe_ip_address
)


class TestUrlValidator(unittest.TestCase):

    def test_empty_url(self):
        """Should reject empty strings or whitespace-only inputs."""
        res = validate_url("")
        self.assertFalse(res["is_valid"])
        self.assertIn("cannot be empty", res["error_message"].lower())

        res_spaces = validate_url("   ")
        self.assertFalse(res_spaces["is_valid"])

    def test_unsupported_schemes(self):
        """Should reject non-HTTP/HTTPS schemes (e.g. ftp, file, javascript, gopher)."""
        schemes = [
            "ftp://files.example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "gopher://gopher.floodgap.com"
        ]
        for url in schemes:
            res = validate_url(url)
            self.assertFalse(res["is_valid"], f"Should reject unsupported scheme: {url}")
            self.assertIn("unsupported url scheme", res["error_message"].lower())

    def test_url_normalization(self):
        """Should automatically prepend https:// and lowercase domain names."""
        norm1 = normalize_url("EXAMPLE.COM")
        self.assertEqual(norm1, "https://example.com/")

        norm2 = normalize_url("http://MyBank.Com/Login")
        self.assertEqual(norm2, "http://mybank.com/Login")

        norm3 = normalize_url("   https://test.org/path?q=1   ")
        self.assertEqual(norm3, "https://test.org/path?q=1")

    def test_missing_hostname(self):
        """Should reject URLs lacking a valid host."""
        invalid_urls = [
            "http://",
            "https:///",
            "https:///path/to/page"
        ]
        for url in invalid_urls:
            res = validate_url(url)
            self.assertFalse(res["is_valid"], f"Should reject missing host: {url}")

    def test_is_ip_address(self):
        """Should accurately detect IPv4, IPv6, and domain names."""
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("8.8.8.8"))
        self.assertTrue(is_ip_address("127.0.0.1"))
        self.assertTrue(is_ip_address("::1"))
        self.assertTrue(is_ip_address("2001:4860:4860::8888"))
        
        self.assertFalse(is_ip_address("example.com"))
        self.assertFalse(is_ip_address("192.168.1.1.nip.io"))
        self.assertFalse(is_ip_address("google.co.uk"))

    def test_ssrf_defense_loopback(self):
        """Should block loopback localhost addresses."""
        loopback_ips = ["127.0.0.1", "127.0.0.254", "::1"]
        for ip in loopback_ips:
            safe, reason = is_safe_ip_address(ip)
            self.assertFalse(safe, f"Loopback IP {ip} should be blocked")
            self.assertIn("loopback", reason.lower())

    def test_ssrf_defense_private_ranges(self):
        """Should block RFC 1918 private subnets."""
        private_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.1.100"
        ]
        for ip in private_ips:
            safe, reason = is_safe_ip_address(ip)
            self.assertFalse(safe, f"Private IP {ip} should be blocked")
            self.assertIn("private internal network", reason.lower())

    def test_ssrf_defense_link_local(self):
        """Should block cloud metadata and link-local addresses (169.254.169.254)."""
        link_local = "169.254.169.254"
        safe, reason = is_safe_ip_address(link_local)
        self.assertFalse(safe)
        self.assertIn("link-local", reason.lower())

    def test_ssrf_defense_public_ip(self):
        """Should allow valid public IP addresses (e.g. 8.8.8.8, 93.184.216.34)."""
        public_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34"]
        for ip in public_ips:
            safe, _ = is_safe_ip_address(ip)
            self.assertTrue(safe, f"Public IP {ip} should be permitted")

    def test_valid_domain_validation(self):
        """Should accept syntactically correct HTTP/HTTPS domains."""
        res = validate_url("https://example.com/test")
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["hostname"], "example.com")
        self.assertEqual(res["scheme"], "https")


if __name__ == "__main__":
    unittest.main()
