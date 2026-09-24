"""
Unit tests for Nested & Recursive Subdomain Engine and APIs
"""
import unittest
from unittest.mock import patch, MagicMock

from enumerator.nested_engine import extract_subzones, mine_nested_patterns, discover_nested_subdomains
from app import app


class TestNestedEngine(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_extract_subzones(self):
        hosts = [
            'api.gilead.devsecops.example.com',
            'app.devsecops.example.com',
            'auth.sqa.example.com',
            'single.example.com',
            'otherdomain.org'
        ]
        subzones = extract_subzones(hosts, 'example.com')
        subzone_names = [sz for sz, _ in subzones]
        self.assertIn('devsecops.example.com', subzone_names)
        self.assertIn('gilead.devsecops.example.com', subzone_names)
        self.assertIn('sqa.example.com', subzone_names)

    def test_mine_nested_patterns(self):
        hosts = [
            'api.gilead.devsecops.example.com',
            'app.merck.devsecops.example.com',
            'portal.sqa.example.com'
        ]
        candidates = mine_nested_patterns(hosts, 'example.com', max_candidates=100)
        self.assertTrue(len(candidates) > 0)
        # Should generate cross-multiplied candidates like api.merck.devsecops.example.com
        self.assertTrue(any(c.endswith('.devsecops.example.com') for c in candidates))

    @patch('enumerator.nested_engine.check_domain_multi_resolver')
    def test_discover_nested_subdomains(self, mock_resolve):
        def side_effect(host, resolver):
            if host == 'api.merck.devsecops.example.com':
                return {'status': 'resolved', 'ips': ['1.1.1.1'], 'resolver': 'Cloudflare'}
            return {'status': 'unresolved', 'ips': [], 'resolver': 'Public DNS'}

        mock_resolve.side_effect = side_effect

        hosts = [
            'api.gilead.devsecops.example.com',
            'app.merck.devsecops.example.com'
        ]
        live = discover_nested_subdomains('example.com', hosts, max_candidates=50, max_workers=2)
        self.assertIsInstance(live, set)

    def test_api_nested_subzones(self):
        resp = self.client.post('/api/nested/subzones', json={
            'domain': 'example.com',
            'hosts': ['api.dev.example.com', 'app.dev.example.com']
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get('domain'), 'example.com')
        self.assertIn('subzones', data)

    def test_api_shodan_free(self):
        with patch('app.harvest_shodan_internetdb') as mock_harvest:
            mock_harvest.return_value = {
                'subdomains': ['api.example.com'],
                'total_discovered': 1,
                'total_queried': 1
            }
            resp = self.client.post('/api/shodan/free', json={
                'domain': 'example.com',
                'ips': ['1.1.1.1']
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data.get('total_queried'), 1)
            self.assertIn('api.example.com', data.get('subdomains', []))


if __name__ == '__main__':
    unittest.main()
