"""
Unit tests for Shodan Domain API 1:1 Schema Exporter.
Ensures SubZero exports identical JSON structures to Shodan's Domain endpoint.
100% offline unit tests with mocked DNS fixtures.
"""
import unittest
from unittest.mock import patch, MagicMock
import json

from enumerator.shodan_exporter import (
    fetch_domain_apex_records,
    detect_shodan_tags,
    export_shodan_format,
)
import app as flask_app


class TestShodanExporter(unittest.TestCase):

    def setUp(self):
        flask_app.app.config["TESTING"] = True
        self.client = flask_app.app.test_client()

    def test_shodan_schema_structure(self):
        """Verifies that the generated dictionary strictly adheres to Shodan's schema."""
        sample_results = [
            {"subdomain": "admin.example.com", "dns_ips": ["1.2.3.4"], "ttl": 300},
            {"subdomain": "api.example.com", "cname": "lb.example.net", "cname_ttl": 3600},
        ]
        mock_apex = [
            {"subdomain": "", "type": "A", "options": {"ttl": 300}, "value": "93.184.216.34", "last_seen": "2026-09-29T10:00:00Z"},
            {"subdomain": "", "type": "NS", "options": {"ttl": 3600}, "value": "a.iana-servers.net", "last_seen": "2026-09-29T10:00:00Z"},
            {"subdomain": "", "type": "TXT", "options": {"ttl": 600}, "value": "v=spf1 -all", "last_seen": "2026-09-29T10:00:00Z"},
            {"subdomain": "_dmarc", "type": "TXT", "options": {"ttl": 600}, "value": "v=DMARC1; p=reject;", "last_seen": "2026-09-29T10:00:00Z"},
        ]

        shodan_json = export_shodan_format("example.com", sample_results, apex_records=mock_apex)

        # 1. Top-level keys must match exactly
        expected_keys = {"domain", "tags", "subdomains", "data", "more"}
        self.assertEqual(set(shodan_json.keys()), expected_keys)

        # 2. Key types
        self.assertEqual(shodan_json["domain"], "example.com")
        self.assertIsInstance(shodan_json["tags"], list)
        self.assertIsInstance(shodan_json["subdomains"], list)
        self.assertIsInstance(shodan_json["data"], list)
        self.assertIs(shodan_json["more"], False)

        # 3. Subdomains list must contain clean relative prefixes
        self.assertIn("admin", shodan_json["subdomains"])
        self.assertIn("api", shodan_json["subdomains"])
        self.assertIn("_dmarc", shodan_json["subdomains"])

        # 4. Each data record must have the exact Shodan structure
        for record in shodan_json["data"]:
            self.assertIn("subdomain", record)
            self.assertIn("type", record)
            self.assertIn("options", record)
            self.assertIn("value", record)
            self.assertIn("last_seen", record)
            self.assertIsInstance(record["options"], dict)

    def test_shodan_tag_detection(self):
        """Verifies intelligent inference of Shodan-compatible domain tags."""
        records = [
            {"subdomain": "_dmarc", "type": "TXT", "value": "v=DMARC1; p=reject;"},
            {"subdomain": "", "type": "TXT", "value": "v=spf1 include:_spf.google.com ~all"},
            {"subdomain": "", "type": "TXT", "value": "google-site-verification=abc123xyz"},
            {"subdomain": "", "type": "TXT", "value": "MS=ms16965041"},
            {"subdomain": "", "type": "TXT", "value": "zoho-verification=zb123"},
            {"subdomain": "", "type": "TXT", "value": "Dynatrace-site-verification=dt987"},
            {"subdomain": "", "type": "TXT", "value": "Sendinblue-code:sb456"},
            {"subdomain": "", "type": "TXT", "value": "apple-domain-verification=app001"},
            {"subdomain": "", "type": "TXT", "value": "globalsign-domain-verification=gs22"},
        ]

        tags = detect_shodan_tags(records)

        expected = [
            "apple-verified",
            "dmarc",
            "dynatrace",
            "globalsign",
            "google-verified",
            "microsoft-office-365",
            "sendinblue",
            "spf",
            "zoho",
        ]
        for t in expected:
            self.assertIn(t, tags)

    def test_nested_subdomain_prefixing(self):
        """Verifies multi-level subdomains are stripped relative to apex domain."""
        results = [
            {"subdomain": "stores.ctbsplus.target.com", "dns_ips": ["1.2.3.4"]},
            {"subdomain": "target.com", "dns_ips": ["5.6.7.8"]},
            {"subdomain": "vpn1.target.com", "dns_ips": ["9.10.11.12"]},
        ]
        out = export_shodan_format("target.com", results, apex_records=[])
        self.assertEqual(out["subdomains"], ["stores.ctbsplus", "vpn1"])

        # Check prefixes in data records
        data_prefixes = {r["subdomain"] for r in out["data"]}
        self.assertIn("stores.ctbsplus", data_prefixes)
        self.assertIn("vpn1", data_prefixes)
        self.assertIn("", data_prefixes)

    @patch("enumerator.shodan_exporter.dns.resolver.Resolver")
    def test_fetch_domain_apex_records_offline(self, mock_resolver_cls):
        """Tests fetch_domain_apex_records offline using mocked dnspython responses."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        # Mock A record
        mock_a = MagicMock()
        mock_a.to_text.return_value = "104.26.0.97"
        mock_a_set = MagicMock()
        mock_a_set.rrset.ttl = 300
        mock_a_set.__iter__.return_value = [mock_a]

        # Mock MX record
        mock_mx = MagicMock()
        mock_mx.preference = 10
        mock_mx.exchange.to_text.return_value = "mail.example.com."
        mock_mx_set = MagicMock()
        mock_mx_set.rrset.ttl = 600
        mock_mx_set.__iter__.return_value = [mock_mx]

        def resolve_side_effect(qname, rtype):
            if rtype == "A" and qname == "example.com":
                return mock_a_set
            elif rtype == "MX":
                return mock_mx_set
            raise Exception("Record not found")

        mock_resolver.resolve.side_effect = resolve_side_effect

        records = fetch_domain_apex_records("example.com")
        self.assertGreaterEqual(len(records), 2)

        types = [r["type"] for r in records]
        self.assertIn("A", types)
        self.assertIn("MX", types)

        mx_rec = next(r for r in records if r["type"] == "MX")
        self.assertEqual(mx_rec["value"], "mail.example.com")
        self.assertEqual(mx_rec["options"]["priority"], 10)
        self.assertEqual(mx_rec["options"]["ttl"], 600)

    def test_api_results_shodan_json_endpoint(self):
        """Verifies GET /api/results/shodan.json returns 1:1 Shodan schema."""
        job_id = "test-shodan-job"
        flask_app.JOBS[job_id] = {
            "domain": "example.com",
            "status": "completed",
            "results": [
                {"subdomain": "sub.example.com", "dns_ips": ["1.1.1.1"], "ttl": 300}
            ],
            "apex_records": [
                {"subdomain": "", "type": "A", "options": {"ttl": 300}, "value": "93.184.216.34", "last_seen": "2026-09-29T10:00:00Z"}
            ],
        }

        try:
            resp = self.client.get(f"/api/results/shodan.json?job={job_id}")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.content_type, "application/json")

            data = json.loads(resp.data)
            self.assertEqual(set(data.keys()), {"domain", "tags", "subdomains", "data", "more"})
            self.assertEqual(data["domain"], "example.com")
            self.assertIn("sub", data["subdomains"])
        finally:
            flask_app.JOBS.pop(job_id, None)

    def test_api_shodan_domain_endpoint(self):
        """Verifies GET /api/shodan/domain with ?job= returns 1:1 Shodan schema."""
        job_id = "test-shodan-domain-job"
        flask_app.JOBS[job_id] = {
            "domain": "example.com",
            "status": "completed",
            "results": [
                {"subdomain": "portal.example.com", "cname": "app.okta.com", "cname_ttl": 3600}
            ],
            "apex_records": [],
        }

        try:
            resp = self.client.get(f"/api/shodan/domain?job={job_id}")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertEqual(data["domain"], "example.com")
            self.assertIn("portal", data["subdomains"])
            cname_record = next(r for r in data["data"] if r["type"] == "CNAME")
            self.assertEqual(cname_record["value"], "app.okta.com")
            self.assertEqual(cname_record["options"]["ttl"], 3600)
        finally:
            flask_app.JOBS.pop(job_id, None)

    def test_record_deduplication_and_sorting(self):
        """Verifies records are deduped and sorted (apex first, then subdomains alphabetically)."""
        results = [
            {"subdomain": "zeta.example.com", "dns_ips": ["1.1.1.1"]},
            {"subdomain": "alpha.example.com", "dns_ips": ["2.2.2.2"]},
            {"subdomain": "alpha.example.com", "dns_ips": ["2.2.2.2"]},  # duplicate
            {"subdomain": "alpha.example.com", "cname": "target.net"},
        ]
        mock_apex = [
            {"subdomain": "", "type": "TXT", "options": {"ttl": 300}, "value": "v=spf1 -all", "last_seen": "2026-09-29T10:00:00.000000"},
            {"subdomain": "", "type": "A", "options": {"ttl": 300}, "value": "93.184.216.34", "last_seen": "2026-09-29T10:00:00.000000"},
        ]
        out = export_shodan_format("example.com", results, apex_records=mock_apex)
        
        # Verify deduplication
        tuples = [(r["subdomain"], r["type"], r["value"]) for r in out["data"]]
        self.assertEqual(len(tuples), len(set(tuples)))

        # Verify sorting: apex records first
        self.assertEqual(out["data"][0]["subdomain"], "")
        self.assertEqual(out["data"][0]["type"], "A")
        self.assertEqual(out["data"][1]["subdomain"], "")
        self.assertEqual(out["data"][1]["type"], "TXT")

        # Subdomains alphabetically
        sub_records = [r for r in out["data"] if r["subdomain"] != ""]
        self.assertEqual(sub_records[0]["subdomain"], "alpha")
        self.assertEqual(sub_records[-1]["subdomain"], "zeta")

    def test_timestamp_microsecond_format(self):
        """Verifies last_seen matches ISO-8601 with microseconds and no timezone offset."""
        results = [{"subdomain": "api.example.com", "dns_ips": ["1.1.1.1"]}]
        out = export_shodan_format("example.com", results, apex_records=[])
        for r in out["data"]:
            ts = r["last_seen"]
            self.assertNotIn("+", ts)
            self.assertNotIn("Z", ts)
            self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+$")

    def test_direct_shodan_domain_route(self):
        """Verifies GET /dns/domain/<domain> works as a drop-in replacement for Shodan API."""
        job_id = "test-dropin-job"
        flask_app.JOBS[job_id] = {
            "domain": "testdropin.com",
            "status": "completed",
            "results": [
                {"subdomain": "srv1.testdropin.com", "dns_ips": ["10.0.0.1"], "ttl": 300}
            ],
            "apex_records": [
                {"subdomain": "", "type": "A", "options": {"ttl": 300}, "value": "10.0.0.99", "last_seen": "2026-09-29T10:00:00.000000"}
            ],
        }

        try:
            # 1. Test /dns/domain/<domain>
            resp = self.client.get("/dns/domain/testdropin.com")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertEqual(data["domain"], "testdropin.com")
            self.assertIn("srv1", data["subdomains"])
            self.assertFalse(data["more"])

            # 2. Test /api/dns/domain/<domain>
            resp2 = self.client.get("/api/dns/domain/testdropin.com")
            self.assertEqual(resp2.status_code, 200)
            data2 = json.loads(resp2.data)
            self.assertEqual(data2["domain"], "testdropin.com")
        finally:
            flask_app.JOBS.pop(job_id, None)


if __name__ == "__main__":
    unittest.main()

