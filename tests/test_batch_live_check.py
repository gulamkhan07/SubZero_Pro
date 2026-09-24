import json
import unittest
from unittest.mock import patch

from app import app, BATCH_JOBS, BATCH_LOCK, JOBS, JOBS_LOCK


class TestBatchLiveCheck(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_batch_subdomains_endpoint(self):
        batch_id = "test_batch_live_123"
        job_id_1 = "sub_job_1"
        job_id_2 = "sub_job_2"

        with BATCH_LOCK:
            BATCH_JOBS[batch_id] = {
                'id': batch_id,
                'batch_id': batch_id,
                'domains': ["alpha.com", "beta.com"],
                'status': 'completed',
                'cancelled': False,
                'targets': {
                    'alpha.com': {'job_id': job_id_1, 'status': 'completed', 'count': 2},
                    'beta.com': {'job_id': job_id_2, 'status': 'completed', 'count': 1}
                }
            }

        with JOBS_LOCK:
            JOBS[job_id_1] = {
                'id': job_id_1,
                'domain': 'alpha.com',
                'results': [
                    {'subdomain': 'api.alpha.com', 'dns': 'resolved', 'dns_ips': ['1.2.3.4']},
                    {'subdomain': 'dev.alpha.com', 'dns': 'unresolved', 'dns_ips': []}
                ]
            }
            JOBS[job_id_2] = {
                'id': job_id_2,
                'domain': 'beta.com',
                'results': [
                    {'subdomain': 'mail.beta.com', 'dns': 'resolved', 'dns_ips': ['5.6.7.8']}
                ]
            }

        resp = self.client.get(f'/api/batch/{batch_id}/subdomains')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['batch_id'], batch_id)
        self.assertEqual(data['total_subdomains'], 3)
        self.assertEqual(data['live_count'], 2)
        self.assertEqual(data['dead_count'], 1)
        self.assertIn('api.alpha.com', data['live_subdomains'])
        self.assertIn('mail.beta.com', data['live_subdomains'])
        self.assertIn('dev.alpha.com', data['dead_subdomains'])

    @patch('app.check_domain_multi_resolver')
    def test_batch_live_check_dns_mode(self, mock_check_dns):
        def fake_resolver(host, resolver, timeout):
            if 'live' in host:
                return {
                    'status': 'resolved',
                    'alive': True,
                    'resolver': 'Cloudflare',
                    'ips': ['104.16.1.1'],
                    'cname': '',
                    'summary': 'Live via Cloudflare'
                }
            return {
                'status': 'unresolved',
                'alive': False,
                'resolver': None,
                'ips': [],
                'cname': '',
                'summary': 'NXDOMAIN'
            }

        mock_check_dns.side_effect = fake_resolver

        payload = {
            'hosts': ['live.example.com', 'dead.example.com'],
            'mode': 'dns',
            'resolver': 'all'
        }
        resp = self.client.post('/api/batch/live-check', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['total'], 2)
        self.assertEqual(data['live_count'], 1)
        self.assertEqual(data['dead_count'], 1)
        self.assertIn('live.example.com', data['live_hosts'])
        self.assertIn('dead.example.com', data['dead_hosts'])
        self.assertIn('104.16.1.1', data['unique_ips'])

    @patch('app.probe_hosts')
    def test_batch_live_check_http_mode(self, mock_probe_hosts):
        mock_probe_hosts.return_value = [
            {
                'host': 'web.example.com',
                'alive': True,
                'status_code': 200,
                'title': 'Test Site',
                'ip': '1.1.1.1',
                'waf_provider': 'Cloudflare'
            },
            {
                'host': 'offline.example.com',
                'alive': False,
                'status_code': 0,
                'title': '—',
                'ip': None,
                'waf_provider': ''
            }
        ]

        payload = {
            'hosts': ['web.example.com', 'offline.example.com'],
            'mode': 'http'
        }
        resp = self.client.post('/api/batch/live-check', data=json.dumps(payload), content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['mode'], 'http')
        self.assertEqual(data['live_count'], 1)
        self.assertEqual(data['dead_count'], 1)
        self.assertIn('web.example.com', data['live_hosts'])
        self.assertIn('offline.example.com', data['dead_hosts'])


if __name__ == '__main__':
    unittest.main()
