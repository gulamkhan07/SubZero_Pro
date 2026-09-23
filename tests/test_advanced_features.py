import socket
import unittest
from unittest.mock import patch, Mock

from enumerator.tls_scraper import extract_sans_from_der, scrape_host_tls
from enumerator.wildcard_detector import detect_wildcard_dns, is_wildcard_false_positive
from enumerator.origin_verifier import verify_origin_candidates, verify_single_origin_ip
from enumerator.ptr_sweeper import get_surrounding_ips, sweep_ips_for_ptrs
from enumerator.ip_intel import get_ip_geo, classify_ips
from enumerator.cli import build_parser, run_cli_scan


class TestAdvancedFeatures(unittest.TestCase):

    # -----------------------------------------------------------------------
    # 1. TLS SAN Certificate Scraper
    # -----------------------------------------------------------------------
    def test_extract_san_from_der(self):
        # Create a synthetic DER fragment with 0x82 tags (dNSName)
        # 0x82 followed by length byte and ASCII domain string
        domain1 = b"api.example.com"
        domain2 = b"admin.example.com"
        fake_der = b"\x30\x50" + bytes([0x82, len(domain1)]) + domain1 + bytes([0x82, len(domain2)]) + domain2
        
        extracted = extract_sans_from_der(fake_der)
        self.assertIn("api.example.com", extracted)
        self.assertIn("admin.example.com", extracted)

    @patch('enumerator.tls_scraper.ssl.create_default_context')
    @patch('enumerator.tls_scraper.socket.create_connection')
    def test_scrape_ip_tls_sans_success(self, mock_conn, mock_ctx):
        mock_sock = Mock()
        mock_ssl_sock = Mock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        
        domain = b"portal.testdomain.com"
        mock_ssl_sock.getpeercert.return_value = b"\x30\x30" + bytes([0x82, len(domain)]) + domain
        
        subs = scrape_host_tls("1.2.3.4", "testdomain.com", timeout=1.0)
        self.assertIn("portal.testdomain.com", subs)

    # -----------------------------------------------------------------------
    # 2. DNS Wildcard Detection & Filtering
    # -----------------------------------------------------------------------
    @patch('enumerator.wildcard_detector.dns.resolver.Resolver')
    def test_detect_wildcard_dns_positive(self, mock_resolver_cls):
        mock_resolver = Mock()
        mock_resolver_cls.return_value = mock_resolver
        
        mock_ans = Mock()
        mock_rr = Mock()
        mock_rr.address = "192.0.2.100"
        mock_ans.__iter__ = Mock(return_value=iter([mock_rr]))
        mock_ans.canonical_name = "wildcard.example.com."
        mock_resolver.resolve.return_value = mock_ans

        wc_info = detect_wildcard_dns("example.com", timeout=1.0)
        self.assertTrue(wc_info['is_wildcard'])
        self.assertIn("192.0.2.100", wc_info['wildcard_ips'])
        self.assertIn("wildcard.example.com", wc_info['wildcard_cnames'])

    def test_is_wildcard_false_positive(self):
        wc_info = {
            'is_wildcard': True,
            'wildcard_ips': ['192.0.2.100'],
            'wildcard_cnames': ['wildcard.example.com']
        }
        # Matches wildcard IP -> false positive
        self.assertTrue(is_wildcard_false_positive(['192.0.2.100'], '', wc_info))
        # Matches wildcard CNAME -> false positive
        self.assertTrue(is_wildcard_false_positive(['10.0.0.1'], 'wildcard.example.com', wc_info))
        # Unique origin IP -> genuine
        self.assertFalse(is_wildcard_false_positive(['192.0.2.200'], 'unique.example.com', wc_info))

    # -----------------------------------------------------------------------
    # 3. True Origin IP Active Verification
    # -----------------------------------------------------------------------
    @patch('enumerator.origin_verifier.requests.get')
    def test_verify_origin_candidates(self, mock_get):
        # Setup mock baseline response for https://example.com
        baseline_resp = Mock()
        baseline_resp.status_code = 200
        baseline_resp.text = "<html><head><title>Example Domain</title></head><body>Welcome</body></html>"
        baseline_resp.headers = {'Server': 'nginx'}

        # Setup mock candidate response for http://198.51.100.1 with Host: example.com
        candidate_resp = Mock()
        candidate_resp.status_code = 200
        candidate_resp.text = "<html><head><title>Example Domain</title></head><body>Welcome</body></html>"
        candidate_resp.headers = {'Server': 'nginx'}

        def side_effect(url, **kwargs):
            if "198.51.100.1" in url:
                return candidate_resp
            return baseline_resp

        mock_get.side_effect = side_effect

        results = verify_origin_candidates(["198.51.100.1"], "example.com", max_workers=1, timeout=2.0)
        self.assertIn("198.51.100.1", results)
        self.assertTrue(results["198.51.100.1"]["is_confirmed_origin"])
        self.assertIn("HTML Title", results["198.51.100.1"]["evidence"])

    # -----------------------------------------------------------------------
    # 4. Reverse DNS (PTR) Subnet Sweeper
    # -----------------------------------------------------------------------
    def test_get_surrounding_ips(self):
        ips = get_surrounding_ips("192.168.1.10", window=2)
        # Should contain 192.168.1.8, .9, .10, .11, .12
        self.assertEqual(len(ips), 5)
        self.assertEqual(ips[0], "192.168.1.8")
        self.assertEqual(ips[-1], "192.168.1.12")

    @patch('enumerator.ptr_sweeper.lookup_ptr_single')
    def test_sweep_ips_for_ptrs(self, mock_lookup):
        mock_lookup.side_effect = lambda ip, *args, **kwargs: "dev-gateway.target.com" if ip == "192.168.1.5" else ""

        res = sweep_ips_for_ptrs(["192.168.1.5"], "target.com", sweep_surrounding=False)
        self.assertIn("dev-gateway.target.com", res['discovered_subdomains'])
        self.assertEqual(res['ptr_map']["192.168.1.5"], "dev-gateway.target.com")

    # -----------------------------------------------------------------------
    # 5. GeoIP & Country Intelligence
    # -----------------------------------------------------------------------
    def test_geoip_lookup(self):
        # UAE IP
        geo_uae = get_ip_geo("5.32.10.5")
        self.assertEqual(geo_uae['country_code'], 'AE')
        self.assertEqual(geo_uae['country_flag'], '🇦🇪')

        # Germany IP
        geo_de = get_ip_geo("138.201.50.1")
        self.assertEqual(geo_de['country_code'], 'DE')
        self.assertEqual(geo_de['country_flag'], '🇩🇪')

        # Classification enrichment
        intel = classify_ips(["5.32.10.5"])
        self.assertEqual(intel['country_code'], 'AE')
        self.assertEqual(intel['country_flag'], '🇦🇪')
        self.assertTrue(intel['is_origin'])

    # -----------------------------------------------------------------------
    # 6. CLI Parser & Flags Integration
    # -----------------------------------------------------------------------
    def test_cli_advanced_flags_parser(self):
        parser = build_parser()
        args = parser.parse_args([
            "-d", "example.com",
            "--tls-san",
            "--wildcard",
            "--verify-origin",
            "--ptr-sweep"
        ])
        self.assertTrue(args.tls_san)
        self.assertTrue(args.wildcard)
        self.assertTrue(args.verify_origin)
        self.assertTrue(args.ptr_sweep)

    # -----------------------------------------------------------------------
    # 7. Web App Reusable Enrichment Helpers
    # -----------------------------------------------------------------------
    def test_app_enrich_subdomain_record(self):
        from app import _enrich_subdomain_record
        item = {'subdomain': 'cf.example.com'}
        dns_res = {
            'status': 'resolved',
            'resolver': 'Cloudflare',
            'summary': 'Resolved via Cloudflare',
            'ips': ['104.21.5.12'],
            'cname': 'example.cdn.cloudflare.net',
        }
        wc_info = {'is_wildcard': False, 'wildcard_ips': [], 'wildcard_cnames': []}
        _enrich_subdomain_record(item, dns_res, wc_info)
        self.assertEqual(item['dns'], 'resolved')
        self.assertEqual(item['primary_ip'], '104.21.5.12')
        self.assertEqual(item['waf_provider'], 'Cloudflare WAF')
        self.assertTrue(item['is_cdn'])
        self.assertFalse(item['is_origin'])
        self.assertFalse(item['is_wildcard_catchall'])

    @patch('app.check_domain_multi_resolver')
    def test_app_resolve_and_enrich_hosts(self, mock_resolve):
        from app import _resolve_and_enrich_hosts
        mock_resolve.return_value = {
            'status': 'resolved',
            'resolver': 'Google DNS',
            'ips': ['34.205.12.5'],
            'cname': '',
            'summary': 'Resolved via Google',
        }
        found_by = {}
        results = []
        job = {'logs': [], 'id': 'test-job'}
        wc_info = {'is_wildcard': False, 'wildcard_ips': []}
        _resolve_and_enrich_hosts(['api.test.com'], 'tls-san', 'all', wc_info, found_by, results, job)
        self.assertIn('api.test.com', found_by)
        self.assertIn('tls-san', found_by['api.test.com'])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['subdomain'], 'api.test.com')
        self.assertEqual(results[0]['primary_ip'], '34.205.12.5')
        self.assertTrue(results[0]['is_origin'])


if __name__ == "__main__":
    unittest.main()

