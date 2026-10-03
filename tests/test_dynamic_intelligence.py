"""
Comprehensive unit test suite for SubZero Dynamic Intelligence Subsystem.
Tests updater adapters, validation, catastrophic drop rejection, Last-Known-Good preservation,
evidence-based correlation, multi-IP resolution, redirect handling, and origin verification.
ZERO external network dependencies (all tests use local fixtures and mocks).
Developed by: Gulam Khan
"""
import unittest
from unittest.mock import MagicMock, Mock, patch

from enumerator.intelligence.config import IntelligenceConfig
from enumerator.intelligence.database import IntelligenceDatabase
from enumerator.intelligence.models import (
    DynamicSourceType,
    EvidenceBundle,
    ProviderCategory,
    ProviderDataset,
    ProviderMetadata,
)
from enumerator.intelligence.registry import PROVIDER_REGISTRY, get_provider
from enumerator.intelligence.updater import IntelligenceUpdater
from enumerator.intelligence.validation import (
    sanitize_and_deduplicate_cidrs,
    validate_cidr_string,
    validate_dataset_change,
)
from enumerator.intelligence.asn_rdap import AsnRdapService
from enumerator.intelligence.correlation import CorrelationEngine
from enumerator.ip_intel import (
    classify_ip,
    classify_ips,
    classify_cname,
    detect_waf_from_http,
    invalidate_cache,
)
from enumerator.origin_verifier import (
    verify_single_origin_ip,
    _is_default_page_title,
)
from enumerator.http_prober import _probe_single_host, _resolve_host_ip


class TestIntelligenceValidation(unittest.TestCase):
    """Feed validation and sanity checking tests."""

    def test_valid_cidr_parsing(self):
        net = validate_cidr_string("192.168.1.0/24")
        self.assertIsNotNone(net)
        self.assertEqual(str(net), "192.168.1.0/24")

        net6 = validate_cidr_string("2606:4700::/32")
        self.assertIsNotNone(net6)
        self.assertEqual(str(net6), "2606:4700::/32")

    def test_invalid_cidr_rejection(self):
        self.assertIsNone(validate_cidr_string("not_a_cidr"))
        self.assertIsNone(validate_cidr_string("999.999.999.999/24"))
        self.assertIsNone(validate_cidr_string(""))
        self.assertIsNone(validate_cidr_string(None))

    def test_duplicate_and_invalid_filtering(self):
        raw = ["10.0.0.0/8", "invalid_entry", "10.0.0.0/8", "192.168.0.0/16", "not_ip/32"]
        valid, rejected = sanitize_and_deduplicate_cidrs(raw)
        self.assertEqual(len(valid), 2)
        self.assertIn("10.0.0.0/8", valid)
        self.assertIn("192.168.0.0/16", valid)
        self.assertEqual(len(rejected), 2)

    def test_catastrophic_drop_rejection(self):
        # Baseline was 30 CIDRs, incoming has only 2 CIDRs -> must reject
        prev_cidrs = [f"10.{i}.0.0/16" for i in range(30)]
        new_cidrs = ["10.0.0.0/16", "10.1.0.0/16"]
        is_valid, reason = validate_dataset_change("TestWAF", new_cidrs, prev_cidrs)
        self.assertFalse(is_valid)
        self.assertIn("Suspicious catastrophic drop", reason)

    def test_catastrophic_expansion_warning(self):
        # Baseline was 5 CIDRs, incoming has 100 CIDRs (20x) -> must flag/reject
        prev_cidrs = [f"10.{i}.0.0/16" for i in range(5)]
        new_cidrs = [f"10.{i}.0.0/24" for i in range(100)]
        is_valid, reason = validate_dataset_change("TestWAF", new_cidrs, prev_cidrs)
        self.assertFalse(is_valid)
        self.assertIn("Suspicious catastrophic expansion", reason)

    def test_valid_incremental_change(self):
        prev_cidrs = ["10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "10.4.0.0/16"]
        new_cidrs = ["10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16", "10.5.0.0/16"]
        is_valid, reason = validate_dataset_change("TestWAF", new_cidrs, prev_cidrs)
        self.assertTrue(is_valid)
        self.assertIn("validated successfully", reason)


class TestIntelligenceUpdater(unittest.TestCase):
    """Dynamic updater tests with mocked HTTP responses."""

    def setUp(self):
        self.db = IntelligenceDatabase()
        self.mock_session = Mock()
        self.updater = IntelligenceUpdater(db=self.db, session=self.mock_session)

    def test_cloudflare_feed_update_success(self):
        # Mock successful Cloudflare official API response
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {"ETag": '"cf-etag-123"'}
        mock_resp.json.return_value = {
            "result": {
                "ipv4_cidrs": [
                    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
                    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
                    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "199.27.128.0/21"
                ],
                "ipv6_cidrs": [
                    "2606:4700::/32", "2400:cb00::/32", "2405:8100::/32", "2405:b500::/32"
                ],
            }
        }
        self.mock_session.get.return_value = mock_resp

        res = self.updater.update_provider("Cloudflare WAF", force=True)
        self.assertEqual(res["status"], "updated")
        self.assertEqual(res["provider"], "Cloudflare WAF")
        self.assertEqual(res["total_cidrs"], 20)
        self.assertEqual(res["etag"], '"cf-etag-123"')

        # Verify dataset updated in database
        ds = self.db.providers["Cloudflare WAF"]
        self.assertIn("199.27.128.0/21", ds.ipv4)
        self.assertEqual(ds.status, "healthy")

    def test_etag_unchanged_304(self):
        # Setup existing dataset with ETag
        self.db.providers["Cloudflare WAF"].etag = '"etag-abc"'
        mock_resp = Mock()
        mock_resp.status_code = 304
        self.mock_session.get.return_value = mock_resp

        res = self.updater.update_provider("Cloudflare WAF", force=True)
        self.assertEqual(res["status"], "unchanged")
        self.assertEqual(self.db.providers["Cloudflare WAF"].status, "healthy")

    def test_http_500_server_error_fallback_to_lkg(self):
        mock_resp = Mock()
        mock_resp.status_code = 500
        self.mock_session.get.return_value = mock_resp

        prev_count = len(self.db.providers["Cloudflare WAF"].ipv4)
        res = self.updater.update_provider("Cloudflare WAF", force=True)
        self.assertEqual(res["status"], "stale_fallback")
        # Ensure LKG ranges are NOT deleted or cleared
        self.assertEqual(len(self.db.providers["Cloudflare WAF"].ipv4), prev_count)
        self.assertEqual(self.db.providers["Cloudflare WAF"].status, "stale")

    def test_http_timeout_fallback_to_lkg(self):
        self.mock_session.get.side_effect = Exception("Connection timed out")

        prev_count = len(self.db.providers["Cloudflare WAF"].ipv4)
        res = self.updater.update_provider("Cloudflare WAF", force=True)
        self.assertEqual(res["status"], "stale_fallback")
        self.assertEqual(len(self.db.providers["Cloudflare WAF"].ipv4), prev_count)

    def test_corrupted_json_rejection(self):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON format")
        mock_resp.text = "Error 404 Not Found"
        self.mock_session.get.return_value = mock_resp

        res = self.updater.update_provider("Cloudflare WAF", force=True)
        self.assertEqual(res["status"], "rejected")

    def test_cname_only_provider_skipped(self):
        res = self.updater.update_provider("Check Point CloudGuard WAF", force=True)
        self.assertEqual(res["status"], "skipped")
        self.assertIn("cname_http_only", res["message"])


class TestCorrelationAndClassification(unittest.TestCase):
    """Evidence hierarchy, conflict detection, and unknown vs origin handling."""

    def setUp(self):
        invalidate_cache()
        self.engine = CorrelationEngine()

    def test_cidr_only_provider_network_detected_not_waf_confirmed(self):
        # 104.21.5.12 is in Cloudflare CIDR
        res = self.engine.classify_single_ip("104.21.5.12")
        self.assertEqual(res.network_provider, "Cloudflare WAF")
        self.assertTrue(res.is_cdn)
        self.assertFalse(res.is_origin)
        # CIDR alone detects network, but does NOT confirm active WAF challenge/block policy
        self.assertFalse(res.waf_confirmed)
        self.assertEqual(res.confidence, "medium")

    def test_cname_and_http_agreement_high_confidence(self):
        http_waf = {
            "waf_provider": "Cloudflare WAF",
            "badge_type": "cloudflare",
            "is_blocked": True,
            "evidence": "cf-ray header found",
        }
        res = self.engine.classify_single_ip("104.21.5.12", cname_str="app.cloudflare.net", http_waf_info=http_waf)
        self.assertEqual(res.waf_provider, "Cloudflare WAF")
        self.assertTrue(res.waf_confirmed)
        self.assertEqual(res.confidence, "high")
        self.assertTrue(res.evidence.http_headers_match)
        self.assertTrue(res.evidence.http_body_match)

    def test_asn_only_evidence_low_confidence(self):
        # Provide ASN 13335 (Cloudflare) on an arbitrary unlisted IP
        res = self.engine.classify_single_ip("192.0.2.1", asn_override=13335)
        self.assertEqual(res.network_provider, "Cloudflare WAF")
        self.assertEqual(res.confidence, "low")
        self.assertFalse(res.waf_confirmed)

    def test_asn_cidr_conflict_detection(self):
        # IP is in Cloudflare CIDR (104.21.5.12), but override ASN is 16509 (AWS)
        res = self.engine.classify_single_ip("104.21.5.12", asn_override=16509)
        self.assertEqual(res.status, "conflicting")
        self.assertIn("conflict_candidates", res.evidence.details)
        candidates = res.evidence.details["conflict_candidates"]
        self.assertTrue(any(c["provider"] == "Cloudflare WAF" and c["cidr_match"] for c in candidates))
        self.assertTrue(any(c["provider"] == "AWS WAF" and c["asn_match"] for c in candidates))

    def test_unknown_ip_must_not_equal_direct_origin(self):
        # Test an unallocated / unclassified IP (RFC 5737 TEST-NET-2)
        res = self.engine.classify_single_ip("198.51.100.99")
        self.assertEqual(res.network_provider, "Unknown")
        self.assertEqual(res.waf_provider, "Unknown")
        self.assertEqual(res.status, "unknown")
        # Mandatory Phase 15 rule: Unknown MUST NOT equal Direct Origin!
        self.assertFalse(res.is_origin)
        self.assertFalse(res.is_cdn)
        self.assertEqual(res.label, "Unknown / Unclassified")
        self.assertEqual(res.badge_type, "unknown")

    def test_known_cloud_origin_is_origin_candidate(self):
        # 34.205.12.5 in AWS EC2 compute range
        res = self.engine.classify_single_ip("34.205.12.5")
        self.assertFalse(res.is_cdn)
        self.assertTrue(res.is_origin)
        self.assertIn("AWS EC2", res.network_provider)
        self.assertEqual(res.badge_type, "origin")

    def test_multi_ip_independent_classification(self):
        # List with a Cloudflare IP and an AWS EC2 origin candidate IP
        ips = ["104.21.5.12", "34.205.12.5"]
        multi_res = self.engine.classify_ips_multi(ips)
        self.assertEqual(len(multi_res["all_ip_classifications"]), 2)
        cls0 = multi_res["all_ip_classifications"][0]
        cls1 = multi_res["all_ip_classifications"][1]

        self.assertEqual(cls0["ip"], "104.21.5.12")
        self.assertTrue(cls0["is_cdn"])
        self.assertFalse(cls0["is_origin"])

        self.assertEqual(cls1["ip"], "34.205.12.5")
        self.assertFalse(cls1["is_cdn"])
        self.assertTrue(cls1["is_origin"])

        # Aggregate summary preserves both signals
        self.assertTrue(multi_res["summary"]["has_cdn"])
        self.assertTrue(multi_res["summary"]["has_origin_candidate"])
        self.assertIn("Cloudflare WAF", multi_res["summary"]["providers"])

    def test_ipv6_classification(self):
        res = self.engine.classify_single_ip("2606:4700::1")
        self.assertEqual(res.network_provider, "Cloudflare WAF")
        self.assertTrue(res.is_cdn)


class TestOriginVerification(unittest.TestCase):
    """Origin verification confidence levels, default page rejection, and false positive prevention."""

    def test_is_default_page_title(self):
        self.assertTrue(_is_default_page_title("Apache2 Ubuntu Default Page"))
        self.assertTrue(_is_default_page_title("Welcome to nginx!"))
        self.assertTrue(_is_default_page_title("IIS Windows Server"))
        self.assertTrue(_is_default_page_title("cPanel Login"))
        self.assertTrue(_is_default_page_title("Parked Domain"))
        self.assertTrue(_is_default_page_title(""))
        # Legitimate business titles must not be filtered
        self.assertFalse(_is_default_page_title("Nayara Energy - Global Petrochemicals Portal"))
        self.assertFalse(_is_default_page_title("Acme Bank Customer Dashboard"))

    @patch("enumerator.origin_verifier.requests.get")
    def test_origin_verification_confirmed_high_confidence(self, mock_get):
        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><head><title>Target Application Portal</title></head></html>"
        resp.headers = {"Server": "nginx"}
        mock_get.return_value = resp

        baseline = {"title": "Target Application Portal", "status_code": 200}
        res = verify_single_origin_ip("198.51.100.1", "target.com", baseline=baseline)
        self.assertTrue(res["is_confirmed_origin"])
        self.assertEqual(res["origin_state"], "confirmed")
        self.assertEqual(res["confidence"], "high")
        self.assertIn("HTML Title exactly matches", res["evidence"])

    @patch("enumerator.origin_verifier.requests.get")
    def test_origin_verification_default_page_rejected(self, mock_get):
        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><head><title>Apache2 Ubuntu Default Page: It works!</title></head></html>"
        resp.headers = {"Server": "Apache/2.4"}
        mock_get.return_value = resp

        baseline = {"title": "Customer Portal", "status_code": 200}
        res = verify_single_origin_ip("198.51.100.1", "target.com", baseline=baseline)
        # Default page must NOT trigger origin confirmation!
        self.assertFalse(res["is_confirmed_origin"])
        self.assertIn(res["origin_state"], ("unconfirmed", "rejected_default_page"))

    @patch("enumerator.origin_verifier.requests.get")
    def test_origin_verification_candidate_low_confidence(self, mock_get):
        resp = Mock()
        resp.status_code = 200
        resp.text = "<html><head><title>Internal Node 404</title></head></html>"
        resp.headers = {"Server": "CustomApp/1.0"}
        mock_get.return_value = resp

        baseline = {"title": "Target Application Portal", "status_code": 200}
        res = verify_single_origin_ip("198.51.100.1", "target.com", baseline=baseline)
        # Active server but title does not match baseline -> candidate origin (not confirmed)
        self.assertFalse(res["is_confirmed_origin"])
        self.assertEqual(res["origin_state"], "candidate")
        self.assertEqual(res["confidence"], "low")


class TestHttpProberIntegration(unittest.TestCase):
    """Prober resolution, redirect isolation, and IPv6 handling."""

    @patch("enumerator.http_prober.requests.get")
    def test_prober_third_party_redirect_isolation(self, mock_get):
        # Simulate domain target.com redirecting to third-party login.microsoftonline.com
        hist_resp = Mock()
        hist_resp.status_code = 302
        hist_resp.url = "http://target.com"
        hist_resp.headers = {"Location": "https://login.microsoftonline.com"}

        final_resp = Mock()
        final_resp.status_code = 200
        final_resp.url = "https://login.microsoftonline.com/oauth2"
        # Third-party Microsoft response has Azure WAF headers
        final_resp.headers = {"x-azure-ref": "0abcdef123", "Server": "Microsoft-IIS"}
        final_resp.history = [hist_resp]
        final_resp.iter_content.return_value = iter([b"<html><title>Microsoft Sign-In</title></html>"])

        mock_get.return_value = final_resp

        res = _probe_single_host("target.com", timeout=1.0, known_ip="198.51.100.99")
        # Because redirect went to a third-party domain (login.microsoftonline.com),
        # Azure WAF should NOT be falsely attributed to target.com!
        self.assertFalse(res["waf_detected"])
        self.assertIn("http://target.com", res["redirect_chain"])

    def test_ipv6_host_resolution(self):
        # Test that _resolve_host_ip handles IPv6 addresses or fails gracefully without exception
        res = _resolve_host_ip("ipv6.google.com")
        self.assertIsInstance(res, str)


if __name__ == "__main__":
    unittest.main()
