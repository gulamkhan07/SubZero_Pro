"""
Unit tests for Shodan Free InternetDB Subdomain Harvester
"""
import unittest
from unittest.mock import patch, MagicMock

from enumerator.shodan_free import query_shodan_ip, harvest_shodan_internetdb


class TestShodanFree(unittest.TestCase):

    @patch('enumerator.shodan_free.requests.get')
    def test_query_shodan_ip_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'cpes': ['some-cpe'],
            'hostnames': ['api.example.com', 'admin.example.com', 'other.com'],
            'ip': '1.2.3.4',
            'ports': [80, 443],
            'vulns': ['CVE-2021-1234']
        }
        mock_get.return_value = mock_resp

        # query_shodan_ip should strictly return hostnames list, ignoring ports and CVEs
        hostnames = query_shodan_ip('1.2.3.4')
        self.assertIsNotNone(hostnames)
        self.assertIn('api.example.com', hostnames)
        self.assertIn('admin.example.com', hostnames)

    @patch('enumerator.shodan_free.query_shodan_ip')
    def test_harvest_shodan_internetdb_subdomains_only(self, mock_query):
        mock_query.return_value = ['portal.example.com', 'unrelated.org']

        res = harvest_shodan_internetdb(['5.6.7.8'], 'example.com')
        self.assertEqual(res['total_queried'], 1)
        self.assertEqual(res['total_discovered'], 1)
        self.assertIn('portal.example.com', res['subdomains'])
        self.assertNotIn('unrelated.org', res['subdomains'])
        # Ensure no vulnerability or port data is in result
        self.assertNotIn('vulns', res)
        self.assertNotIn('ports', res)
        self.assertNotIn('cpes', res)

    def test_harvest_shodan_empty(self):
        res = harvest_shodan_internetdb([], 'example.com')
        self.assertEqual(res['total_queried'], 0)
        self.assertEqual(res['total_discovered'], 0)
        self.assertEqual(res['subdomains'], [])


if __name__ == '__main__':
    unittest.main()
