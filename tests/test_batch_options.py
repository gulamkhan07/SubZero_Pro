import json
import unittest
from unittest.mock import patch, MagicMock

from app import app, BATCH_JOBS, BATCH_LOCK, _run_batch


class TestBatchOptions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_batch_start_accepts_options(self):
        payload = {
            "domains": ["alpha.com", "beta.com"],
            "sources": ["subfinder", "crtsh", "sslmate"],
            "validate_dns": True,
            "active_dns": True,
            "active_wordlist": "10000",
            "selected_resolver": "cloudflare",
            "dns_resolver": "cloudflare"
        }
        with patch('app.BATCH_EXECUTOR.submit') as mock_submit:
            resp = self.client.post(
                '/api/batch/start',
                data=json.dumps(payload),
                content_type='application/json'
            )
            self.assertEqual(resp.status_code, 202)
            data = resp.get_json()
            self.assertIn('batch_id', data)
            self.assertEqual(data['total_targets'], 2)
            mock_submit.assert_called_once()
            args = mock_submit.call_args[0]
            # args: (_run_batch, batch_id, valid_targets, data)
            self.assertEqual(args[0], _run_batch)
            self.assertEqual(args[2], ["alpha.com", "beta.com"])
            self.assertEqual(args[3]['sources'], ["subfinder", "crtsh", "sslmate"])
            self.assertTrue(args[3]['active_dns'])
            self.assertEqual(args[3]['active_wordlist'], "10000")
            self.assertEqual(args[3]['dns_resolver'], "cloudflare")

    @patch('app._run_scan')
    def test_run_batch_passes_options_to_sub_jobs(self, mock_run_scan):
        batch_id = "test_batch_123"
        with BATCH_LOCK:
            BATCH_JOBS[batch_id] = {
                'id': batch_id,
                'domains': ["example.com"],
                'status': 'queued',
                'cancelled': False,
                'targets': {}
            }

        config = {
            "sources": ["sub-finder", "crt.sh"],
            "active_dns": True,
            "active_wordlist": "1500",
            "validate_dns": True,
            "selected_resolver": "google"
        }

        _run_batch(batch_id, ["example.com"], config)

        self.assertTrue(mock_run_scan.called)
        sub_job_id, selected = mock_run_scan.call_args[0]
        # Verify alias normalization: sub-finder -> subfinder, crt.sh -> crtsh
        self.assertIn("subfinder", selected)
        self.assertIn("crtsh", selected)
