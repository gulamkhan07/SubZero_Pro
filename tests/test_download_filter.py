import unittest
import json
import io
import csv
import app as flask_app
from app import app, _is_result_live, _is_result_dead, _filter_results


class TestDownloadFilter(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.job_id = "test-filter-job-123"

        # Mock scan job with a mix of live and dead subdomains
        self.sample_results = [
            {
                "subdomain": "api.example.com",
                "sources": ["subfinder", "crtsh"],
                "confidence": "high",
                "dns": "resolved",
                "dns_ips": ["93.184.216.34"],
                "primary_ip": "93.184.216.34",
                "waf_provider": "Cloudflare WAF",
                "is_origin": False,
                "is_cdn": True,
                "is_live": True,
                "is_dead": False,
            },
            {
                "subdomain": "mail.example.com",
                "sources": ["crtsh"],
                "confidence": "single-source",
                "dns": "resolved",
                "dns_ips": ["93.184.216.35"],
                "primary_ip": "93.184.216.35",
                "waf_provider": "Direct Server",
                "is_origin": True,
                "is_cdn": False,
                "is_live": True,
                "is_dead": False,
            },
            {
                "subdomain": "old-dev.example.com",
                "sources": ["alienvault"],
                "confidence": "single-source",
                "dns": "unresolved",
                "dns_ips": [],
                "primary_ip": "",
                "waf_provider": "",
                "is_origin": False,
                "is_cdn": False,
                "is_live": False,
                "is_dead": True,
            },
            {
                "subdomain": "staging-catchall.example.com",
                "sources": ["rapiddns"],
                "confidence": "single-source",
                "dns": "wildcard-catchall",
                "dns_ips": ["192.0.2.1"],
                "primary_ip": "192.0.2.1",
                "waf_provider": "",
                "is_origin": False,
                "is_cdn": False,
                "is_wildcard_catchall": True,
                "is_live": False,
                "is_dead": True,
            },
        ]

        flask_app.JOBS[self.job_id] = {
            "id": self.job_id,
            "domain": "example.com",
            "status": "completed",
            "progress": "Completed",
            "sources": {"subfinder": 1, "crtsh": 2, "alienvault": 1, "rapiddns": 1},
            "errors": [],
            "results": self.sample_results,
            "dns_validation": True,
            "active_dns": False,
            "cached": False,
            "logs": [],
            "created_at": 1700000000.0,
            "main_domain": {
                "domain": "example.com",
                "subdomain": "example.com",
                "dns": "resolved",
                "primary_ip": "93.184.216.34",
                "dns_ips": ["93.184.216.34"],
                "waf_provider": "Cloudflare WAF",
            },
        }

    def tearDown(self):
        flask_app.JOBS.pop(self.job_id, None)

    def test_filter_helpers_live_and_dead_detection(self):
        """Verifies _is_result_live and _is_result_dead classify accurately."""
        live_item = self.sample_results[0]
        dead_item = self.sample_results[2]
        catchall_item = self.sample_results[3]

        self.assertTrue(_is_result_live(live_item))
        self.assertFalse(_is_result_dead(live_item))

        self.assertFalse(_is_result_live(dead_item))
        self.assertTrue(_is_result_dead(dead_item))

        self.assertFalse(_is_result_live(catchall_item))
        self.assertTrue(_is_result_dead(catchall_item))

    def test_filter_results_helper(self):
        """Verifies _filter_results correctly partitions lists by status."""
        all_res = _filter_results(self.sample_results, 'all')
        self.assertEqual(len(all_res), 4)

        live_res = _filter_results(self.sample_results, 'live')
        self.assertEqual(len(live_res), 2)
        self.assertEqual([r['subdomain'] for r in live_res], ['api.example.com', 'mail.example.com'])

        dead_res = _filter_results(self.sample_results, 'dead')
        self.assertEqual(len(dead_res), 2)
        self.assertEqual([r['subdomain'] for r in dead_res], ['old-dev.example.com', 'staging-catchall.example.com'])

    def test_results_txt_live_filter(self):
        """GET /api/results.txt?status=live downloads ONLY live subdomains."""
        resp = self.client.get(f"/api/results.txt?job={self.job_id}&status=live")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        self.assertIn("filename=example.com_live_subdomains.txt", resp.headers.get("Content-Disposition", ""))

        text = resp.get_data(as_text=True)
        self.assertIn("api.example.com", text)
        self.assertIn("mail.example.com", text)
        self.assertNotIn("old-dev.example.com", text)
        self.assertNotIn("staging-catchall.example.com", text)
        self.assertIn("Total Found (LIVE): 2", text)

    def test_results_txt_dead_filter(self):
        """GET /api/results.txt?status=dead downloads ONLY dead subdomains."""
        resp = self.client.get(f"/api/results.txt?job={self.job_id}&status=dead")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        self.assertIn("filename=example.com_dead_subdomains.txt", resp.headers.get("Content-Disposition", ""))

        text = resp.get_data(as_text=True)
        self.assertNotIn("api.example.com", text)
        self.assertNotIn("mail.example.com", text)
        self.assertIn("old-dev.example.com", text)
        self.assertIn("staging-catchall.example.com", text)
        self.assertIn("Total Found (DEAD): 2", text)

    def test_results_txt_all_filter(self):
        """GET /api/results.txt?status=all downloads ALL subdomains."""
        resp = self.client.get(f"/api/results.txt?job={self.job_id}&status=all")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("filename=example.com_subdomains.txt", resp.headers.get("Content-Disposition", ""))

        text = resp.get_data(as_text=True)
        self.assertIn("api.example.com", text)
        self.assertIn("mail.example.com", text)
        self.assertIn("old-dev.example.com", text)
        self.assertIn("staging-catchall.example.com", text)
        self.assertIn("Total Found: 4", text)

    def test_results_csv_live_and_dead_filter(self):
        """GET /api/results.csv filters accurately by live and dead status."""
        # Live
        resp_live = self.client.get(f"/api/results.csv?job={self.job_id}&status=live")
        self.assertEqual(resp_live.status_code, 200)
        self.assertIn("filename=example.com_live_subdomains.csv", resp_live.headers.get("Content-Disposition", ""))
        csv_live = resp_live.get_data(as_text=True)
        self.assertIn("api.example.com", csv_live)
        self.assertIn("mail.example.com", csv_live)
        self.assertNotIn("old-dev.example.com", csv_live)
        self.assertNotIn("staging-catchall.example.com", csv_live)

        # Dead
        resp_dead = self.client.get(f"/api/results.csv?job={self.job_id}&status=dead")
        self.assertEqual(resp_dead.status_code, 200)
        self.assertIn("filename=example.com_dead_subdomains.csv", resp_dead.headers.get("Content-Disposition", ""))
        csv_dead = resp_dead.get_data(as_text=True)
        self.assertNotIn("api.example.com", csv_dead)
        self.assertNotIn("mail.example.com", csv_dead)
        self.assertIn("old-dev.example.com", csv_dead)
        self.assertIn("staging-catchall.example.com", csv_dead)

    def test_results_json_filter(self):
        """GET /api/results.json returns filtered results and updated metadata."""
        resp = self.client.get(f"/api/results.json?job={self.job_id}&status=live")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.get_data(as_text=True))
        self.assertEqual(data["status_filter"], "live")
        self.assertEqual(data["total_subdomains"], 2)
        subdomains = [r["subdomain"] for r in data["results"]]
        self.assertEqual(subdomains, ["api.example.com", "mail.example.com"])

        resp_dead = self.client.get(f"/api/results.json?job={self.job_id}&status=dead")
        self.assertEqual(resp_dead.status_code, 200)
        data_dead = json.loads(resp_dead.get_data(as_text=True))
        self.assertEqual(data_dead["status_filter"], "dead")
        self.assertEqual(data_dead["total_subdomains"], 2)
        subdomains_dead = [r["subdomain"] for r in data_dead["results"]]
        self.assertEqual(subdomains_dead, ["old-dev.example.com", "staging-catchall.example.com"])

    def test_results_ips_txt_filter(self):
        """GET /api/results/ips.txt filters unique IPs based on live/dead selection."""
        resp_live = self.client.get(f"/api/results/ips.txt?job={self.job_id}&status=live")
        self.assertEqual(resp_live.status_code, 200)
        text_live = resp_live.get_data(as_text=True)
        self.assertIn("93.184.216.34", text_live)
        self.assertIn("93.184.216.35", text_live)
        self.assertNotIn("192.0.2.1", text_live) # Catchall IP excluded from live

        resp_dead = self.client.get(f"/api/results/ips.txt?job={self.job_id}&status=dead")
        self.assertEqual(resp_dead.status_code, 200)
        text_dead = resp_dead.get_data(as_text=True)
        # Catchall has 192.0.2.1, but no live IPs
        self.assertNotIn("93.184.216.34", text_dead)
        self.assertNotIn("93.184.216.35", text_dead)

    def test_results_html_filter(self):
        """GET /api/results.html correctly filters subdomains inside the HTML report."""
        resp = self.client.get(f"/api/results.html?job={self.job_id}&status=live")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("api.example.com", html)
        self.assertIn("mail.example.com", html)
        self.assertNotIn("old-dev.example.com", html)
        self.assertIn("filename=example.com_live_recon_report.html", resp.headers.get("Content-Disposition", ""))


if __name__ == '__main__':
    unittest.main()
