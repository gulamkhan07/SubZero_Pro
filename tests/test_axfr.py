"""
Unit tests for DNS Zone Transfer (AXFR) Pre-Flight Auditor and API Endpoint.
Developed by: Gulam
"""
import unittest
from unittest.mock import patch, Mock, MagicMock

from enumerator.axfr_auditor import check_zone_transfer, _test_nameserver_axfr
from app import app


class TestAXFRAuditor(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_invalid_domain(self):
        res = check_zone_transfer("invalid domain!@#")
        self.assertFalse(res['is_vulnerable'])
        self.assertEqual(res['subdomains'], [])
        self.assertIn("Invalid", res['evidence'])

    @patch('enumerator.axfr_auditor.dns.resolver.Resolver')
    @patch('enumerator.axfr_auditor.dns.query.xfr')
    @patch('enumerator.axfr_auditor.dns.zone.from_xfr')
    def test_zone_transfer_vulnerable(self, mock_from_xfr, mock_xfr, mock_resolver_cls):
        mock_resolver = Mock()
        mock_resolver_cls.return_value = mock_resolver

        # Mock NS records
        ns_rec = Mock()
        ns_rec.target = "ns1.example.com."
        mock_resolver.resolve.side_effect = [
            [ns_rec],            # NS query
            [Mock(address="198.51.100.1")]  # A record for ns1.example.com
        ]

        # Mock zone transfer payload
        mock_zone = Mock()
        mock_zone.nodes = {
            '@': Mock(),
            'admin': Mock(),
            'dev': Mock(),
            'api.internal': Mock()
        }
        mock_from_xfr.return_value = mock_zone

        res = check_zone_transfer("example.com", timeout=1.0)
        self.assertTrue(res['is_vulnerable'])
        self.assertEqual(len(res['vulnerable_nameservers']), 1)
        self.assertEqual(res['vulnerable_nameservers'][0]['nameserver'], "ns1.example.com")
        self.assertIn("admin.example.com", res['subdomains'])
        self.assertIn("dev.example.com", res['subdomains'])
        self.assertIn("api.internal.example.com", res['subdomains'])

    @patch('enumerator.axfr_auditor.dns.resolver.Resolver')
    @patch('enumerator.axfr_auditor.dns.query.xfr')
    def test_zone_transfer_secure_rejected(self, mock_xfr, mock_resolver_cls):
        mock_resolver = Mock()
        mock_resolver_cls.return_value = mock_resolver

        ns_rec = Mock()
        ns_rec.target = "ns1.example.com."
        mock_resolver.resolve.side_effect = [
            [ns_rec],
            [Mock(address="198.51.100.1")]
        ]

        # Simulate TransferFailed exception (standard secure behavior)
        mock_xfr.side_effect = Exception("TransferFailed: REFUSED")

        res = check_zone_transfer("example.com", timeout=1.0)
        self.assertFalse(res['is_vulnerable'])
        self.assertEqual(res['vulnerable_nameservers'], [])
        self.assertEqual(res['subdomains'], [])
        self.assertIn("rejected", res['evidence'].lower())

    @patch('app.check_zone_transfer')
    def test_api_audit_axfr_endpoint(self, mock_check):
        mock_check.return_value = {
            'developed_by': 'Gulam',
            'domain': 'target.com',
            'is_vulnerable': True,
            'vulnerable': True,
            'vulnerable_nameservers': [{'nameserver': 'ns1.target.com', 'ip': '1.2.3.4'}],
            'subdomains': ['secret.target.com'],
            'total_subdomains': 1,
            'evidence': 'Open zone transfer confirmed',
            'duration': 0.5
        }

        resp = self.client.post('/api/audit/axfr', json={'domain': 'target.com'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['is_vulnerable'])
        self.assertEqual(data['subdomains'], ['secret.target.com'])


if __name__ == '__main__':
    unittest.main()
