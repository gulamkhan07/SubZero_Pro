"""
Unit tests for SubZero DNS Asset Integrity & Dangling CNAME Auditor.
Verifies defensive detection of misconfigured cloud asset pointers across expanded signatures.
"""
import unittest
from unittest.mock import Mock, patch

from enumerator.cname_auditor import (
    SERVICE_SIGNATURES,
    resolve_cname,
    resolve_cname_chain,
    _audit_single_host,
    audit_hosts,
)


class TestCnameAuditor(unittest.TestCase):

    def test_signatures_catalog_coverage(self):
        """Verifies that the signature catalog covers 70+ cloud and SaaS providers."""
        self.assertGreaterEqual(len(SERVICE_SIGNATURES), 70)
        services = {s["service"] for s in SERVICE_SIGNATURES}
        self.assertIn("AWS S3", services)
        self.assertIn("GitHub Pages", services)
        self.assertIn("Microsoft Azure", services)
        self.assertIn("Amazon CloudFront", services)
        self.assertIn("Vercel", services)
        self.assertIn("Netlify", services)
        self.assertIn("Fly.io", services)
        self.assertIn("Ghost", services)
        self.assertIn("Firebase Hosting", services)
        self.assertIn("Readme.io", services)

    def test_direct_host_no_cname(self):
        """Host without CNAME is classified as Direct Record (safe)."""
        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=[]):
            res = _audit_single_host("api.example.com")
            self.assertEqual(res["status"], "safe")
            self.assertEqual(res["service"], "Internal / Direct")
            self.assertIn("No external CNAME", res["evidence"])

    def test_dangling_s3_bucket(self):
        """Detects dangling AWS S3 bucket via NoSuchBucket signature."""
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.iter_content = Mock(return_value=iter([b"NoSuchBucket: The specified bucket does not exist"]))
        mock_resp.text = "NoSuchBucket: The specified bucket does not exist"

        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["test-bucket.s3.amazonaws.com"]), \
             patch("enumerator.cname_auditor.requests.get", return_value=mock_resp):
            res = _audit_single_host("assets.example.com")
            self.assertEqual(res["status"], "dangling")
            self.assertEqual(res["service"], "AWS S3")
            self.assertIn("bucket", res["evidence"].lower())

    def test_dangling_github_pages(self):
        """Detects dangling GitHub Pages via 404 signature."""
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.iter_content = Mock(return_value=iter([b"404 - There isn't a GitHub Pages site here."]))
        mock_resp.text = "404 - There isn't a GitHub Pages site here."

        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["user.github.io"]), \
             patch("enumerator.cname_auditor.requests.get", return_value=mock_resp):
            res = _audit_single_host("docs.example.com")
            self.assertEqual(res["status"], "dangling")
            self.assertEqual(res["service"], "GitHub Pages")

    def test_dangling_vercel_deployment(self):
        """Detects dangling Vercel custom domain via DEPLOYMENT_NOT_FOUND."""
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.iter_content = Mock(return_value=iter([b"The deployment could not be found on Vercel (DEPLOYMENT_NOT_FOUND)"]))
        mock_resp.text = "The deployment could not be found on Vercel"

        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["cname.vercel-dns.com"]), \
             patch("enumerator.cname_auditor.requests.get", return_value=mock_resp):
            res = _audit_single_host("app.example.com")
            self.assertEqual(res["status"], "dangling")
            self.assertEqual(res["service"], "Vercel")

    def test_dangling_readme_project(self):
        """Detects dangling Readme.io project."""
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.iter_content = Mock(return_value=iter([b"Project doesnt exist... yet!"]))
        mock_resp.text = "Project doesnt exist... yet!"

        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["custom.readme.io"]), \
             patch("enumerator.cname_auditor.requests.get", return_value=mock_resp):
            res = _audit_single_host("developer.example.com")
            self.assertEqual(res["status"], "dangling")
            self.assertEqual(res["service"], "Readme.io")

    def test_cname_chain_resolution_identifies_nested_saas(self):
        """Multi-hop CNAME chain accurately identifies SaaS provider at end of chain."""
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.iter_content = Mock(return_value=iter([b"Fastly error: unknown domain"]))
        mock_resp.text = "Fastly error: unknown domain"

        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["cdn.target.com", "edge.fastly.net"]), \
             patch("enumerator.cname_auditor.requests.get", return_value=mock_resp):
            res = _audit_single_host("static.target.com")
            self.assertEqual(res["status"], "dangling")
            self.assertEqual(res["service"], "Fastly")

    def test_orphaned_cname_nxdomain(self):
        """Detects orphaned third-party CNAME pointing to an unresolvable domain (NXDOMAIN)."""
        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["nonexistent.decommissioned-vendor.com"]), \
             patch("enumerator.cname_auditor._check_target_resolves", return_value=False):
            res = _audit_single_host("legacy.example.com")
            self.assertEqual(res["status"], "dangling")
            self.assertEqual(res["service"], "Orphaned Pointer / NXDOMAIN")
            self.assertIn("NXDOMAIN", res["evidence"])

    def test_active_safe_cname(self):
        """Active CNAME without dangling fingerprints is classified as safe."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.iter_content = Mock(return_value=iter([b"<html><head><title>Welcome to Shopify Store</title></head></html>"]))
        mock_resp.text = "Welcome to Shopify Store"

        with patch("enumerator.cname_auditor.resolve_cname_chain", return_value=["myshop.myshopify.com"]), \
             patch("enumerator.cname_auditor.requests.get", return_value=mock_resp):
            res = _audit_single_host("shop.example.com")
            self.assertEqual(res["status"], "safe")
            self.assertEqual(res["service"], "Shopify")

    def test_audit_hosts_sorting(self):
        """audit_hosts correctly prioritizes dangling risks first, then info, then safe."""
        mock_results = {
            "safe.com": {"host": "safe.com", "status": "safe", "service": "Direct"},
            "info.com": {"host": "info.com", "status": "info", "service": "Third-Party"},
            "dangling.com": {"host": "dangling.com", "status": "dangling", "service": "AWS S3"}
        }

        with patch("enumerator.cname_auditor._audit_single_host", side_effect=lambda h: mock_results.get(h, {})):
            findings = audit_hosts(["safe.com", "info.com", "dangling.com"])
            self.assertEqual(len(findings), 3)
            self.assertEqual(findings[0]["host"], "dangling.com")
            self.assertEqual(findings[1]["host"], "info.com")
            self.assertEqual(findings[2]["host"], "safe.com")


if __name__ == "__main__":
    unittest.main()
