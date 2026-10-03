import os
import tempfile
import unittest
from unittest.mock import Mock, patch



from enumerator.normalizer import normalize_subdomains
from enumerator.providers import (
    DEFAULT_PROVIDER_ORDER,
    PROVIDERS,
    amass,
    crtsh,
    hackertarget,
    otx,
    rapiddns,
    resolve_binary,
    subfinder,
    subfinder_all,
    urlscan,
    subdomain_center,
    anubis,
    threatminer,
)
from enumerator.active_scanner import dns_brute_force, check_wildcard_dns


class RequirementChecks(unittest.TestCase):
    def test_primary_provider_order(self):
        expected = (
            'amass', 'subfinder', 'subfinder_all', 'subdomain_center', 'sslmate', 'crtsh',
            'rapiddns', 'hackertarget', 'otx', 'urlscan', 'anubis', 'threatminer'
        )
        self.assertEqual(DEFAULT_PROVIDER_ORDER, expected)
        self.assertEqual(tuple(PROVIDERS.keys()), DEFAULT_PROVIDER_ORDER)
        self.assertNotIn('findomain', PROVIDERS)
        self.assertNotIn('assetfinder', PROVIDERS)
        self.assertNotIn('chaos', PROVIDERS)

    def test_root_domain_filtering(self):
        values = [
            'example.com',
            'www.example.com',
            'api.example.com',
            'not-example.com',
            'evil.com',
            'sub.example.net',
            'https://www.example.com/path',
            '*.example.com',
            'foo.bar.example.com',
        ]
        self.assertEqual(
            normalize_subdomains(values, 'example.com'),
            {'www.example.com', 'api.example.com', 'foo.bar.example.com'}
        )

    def test_go_bin_directories_are_checked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            exe_path = os.path.join(tmpdir, 'amass')
            with open(exe_path, 'wb') as fh:
                fh.write(b'fake')

            with patch('enumerator.providers.shutil.which', return_value=None), \
                 patch('enumerator.providers._discover_go_bin_dirs', return_value=[tmpdir]):
                self.assertEqual(resolve_binary('amass'), exe_path)

    def test_known_wsl_go_bin_path_is_checked(self):
        expected = os.path.normpath('/home/testuser/go/bin/subfinder')
        with patch('enumerator.providers.shutil.which', return_value=None), \
             patch('enumerator.providers._discover_go_bin_dirs', return_value=['/home/testuser/go/bin']), \
             patch('enumerator.providers.os.path.isfile', side_effect=lambda path: os.path.normpath(path) == expected):
            resolved = resolve_binary('subfinder')
            self.assertIsNotNone(resolved)
            self.assertEqual(os.path.normpath(resolved), expected)

    @patch('enumerator.providers._run_cmd', return_value=([], None, 0))
    def test_amass_uses_supported_quiet_v4_flags(self, run_cmd):
        amass('example.com')
        args = run_cmd.call_args.args[0]
        self.assertIn('-silent', args)
        self.assertIn('-nocolor', args)
        self.assertNotIn('-noalts', args)
        self.assertNotIn('-passive', args)

    @patch('enumerator.providers._run_cmd', return_value=([], None, 0))
    def test_subfinder_avoids_all_sources_mode(self, run_cmd):
        subfinder('example.com')
        args = run_cmd.call_args.args[0]
        self.assertNotIn('-all', args)
        self.assertIn('-duc', args)
        self.assertIn('-silent', args)

    @patch('enumerator.providers.retry_request')
    def test_hackertarget_parses_lines(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = "api.example.com,1.2.3.4\nmail.example.com,1.2.3.5\nother.com,1.2.3.6"
        mock_retry.return_value = mock_resp
        values, err, count = hackertarget('example.com')
        self.assertIsNone(err)
        self.assertEqual(values, ['api.example.com', 'mail.example.com'])
        self.assertEqual(count, 2)

    def test_scan_respects_the_selected_sources(self):
        import time
        from app import app

        subfinder_provider = Mock(return_value=(['api.example.com'], None, 1))
        amass_provider = Mock()
        sslmate_provider = Mock()
        with app.test_client() as client, patch.dict(
            'app.PROVIDERS',
            {
                'amass': amass_provider,
                'subfinder': subfinder_provider,
                'sslmate': sslmate_provider,
            },
        ):
            response = client.post('/api/scan', json={
                'domain': 'example.com',
                'sources': ['subfinder'],
            })

            self.assertEqual(response.status_code, 202)
            job_id = response.get_json()['id']

            # Wait for background job to finish
            data = {}
            for _ in range(100):
                res = client.get(f'/api/scan/{job_id}')
                data = res.get_json()
                if data.get('status') == 'completed':
                    break
                time.sleep(0.05)

            self.assertEqual(data.get('status'), 'completed')
            self.assertEqual(data.get('results'), [
                {'subdomain': 'api.example.com', 'sources': ['subfinder'], 'confidence': 'single-source', 'dns': 'not-checked'}
            ])
            amass_provider.assert_not_called()
            sslmate_provider.assert_not_called()

    @patch('enumerator.providers.retry_request')
    def test_crtsh_parses_json(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {'name_value': 'admin.example.com\n*.dev.example.com'},
            {'name_value': 'mail.example.com'},
            {'name_value': 'evil.other.com'}
        ]
        mock_retry.return_value = mock_resp
        values, err, count = crtsh('example.com')
        self.assertIsNone(err)
        self.assertIn('admin.example.com', values)
        self.assertIn('dev.example.com', values)
        self.assertIn('mail.example.com', values)
        self.assertNotIn('evil.other.com', values)
        self.assertEqual(count, 3)

    @patch('enumerator.providers.retry_request')
    def test_otx_parses_json(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'url_list': [
                {'hostname': 'api.example.com'},
                {'hostname': 'vpn.example.com'},
                {'hostname': 'unrelated.com'}
            ]
        }
        mock_retry.return_value = mock_resp
        values, err, count = otx('example.com')
        self.assertIsNone(err)
        self.assertEqual(values, ['api.example.com', 'vpn.example.com'])
        self.assertEqual(count, 2)

    @patch('enumerator.providers.retry_request')
    def test_urlscan_parses_json(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'results': [
                {'page': {'domain': 'auth.example.com', 'ptr': 'ptr.example.com'}},
                {'page': {'domain': 'other.org'}}
            ]
        }
        mock_retry.return_value = mock_resp
        values, err, count = urlscan('example.com')
        self.assertIsNone(err)
        self.assertIn('auth.example.com', values)
        self.assertIn('ptr.example.com', values)
        self.assertNotIn('other.org', values)
        self.assertEqual(count, 2)

    @patch('enumerator.providers.retry_request')
    def test_subdomain_center_parses_json(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = ['api.example.com', 'portal.example.com', 'other.com']
        mock_retry.return_value = mock_resp
        values, err, count = subdomain_center('example.com')
        self.assertIsNone(err)
        self.assertIn('api.example.com', values)
        self.assertIn('portal.example.com', values)
        self.assertNotIn('other.com', values)
        self.assertEqual(count, 2)

    @patch('enumerator.providers.retry_request')
    def test_anubis_parses_json(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = ['dev.example.com', 'test.example.com']
        mock_retry.return_value = mock_resp
        values, err, count = anubis('example.com')
        self.assertIsNone(err)
        self.assertIn('dev.example.com', values)
        self.assertEqual(count, 2)

    @patch('enumerator.providers.retry_request')
    def test_threatminer_parses_json(self, mock_retry):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'status_code': '200',
            'results': ['admin.example.com', 'db.example.com']
        }
        mock_retry.return_value = mock_resp
        values, err, count = threatminer('example.com')
        self.assertIsNone(err)
        self.assertIn('admin.example.com', values)
        self.assertIn('db.example.com', values)
        self.assertEqual(count, 2)

    @patch('enumerator.active_scanner.check_wildcard_dns', return_value=True)
    def test_active_dns_detects_wildcard(self, mock_wc):
        values, err, count = dns_brute_force('example.com')
        self.assertEqual(values, [])
        self.assertIn('Wildcard DNS detected', err)
        self.assertEqual(count, 0)

    def test_history_store_save_and_diff(self):
        from enumerator.history_store import save_scan_history, compute_diff, get_recent_scans
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = Path(tmpdir) / 'test_history.db'
            with patch('enumerator.history_store.DB_PATH', test_db):
                save_scan_history('scan1', 'example.com', [{'subdomain': 'api.example.com'}, {'subdomain': 'mail.example.com'}], {'crtsh': 2})
                save_scan_history('scan2', 'example.com', [{'subdomain': 'mail.example.com'}, {'subdomain': 'admin.example.com'}, {'subdomain': 'dev.example.com'}], {'subfinder': 3})

                scans = get_recent_scans('example.com')
                self.assertEqual(len(scans), 2)

                diff = compute_diff('scan1', 'scan2')
                self.assertIsNotNone(diff)
                self.assertEqual(set(diff['added']), {'admin.example.com', 'dev.example.com'})
                self.assertEqual(set(diff['removed']), {'api.example.com'})
                self.assertEqual(set(diff['unchanged']), {'mail.example.com'})
                self.assertEqual(diff['counts']['added'], 2)
                self.assertEqual(diff['counts']['removed'], 1)
                self.assertEqual(diff['counts']['unchanged'], 1)

    @patch('enumerator.http_prober.requests.get')
    def test_http_prober_extracts_metadata(self, mock_get):
        from enumerator.http_prober import probe_hosts

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.url = 'https://app.example.com'
        mock_resp.headers = {'server': 'nginx/1.25.0', 'content-length': '1024'}
        mock_resp.text = '<html><head><title>Secure Portal</title></head><body>Welcome</body></html>'
        mock_get.return_value = mock_resp

        results = probe_hosts(['app.example.com'], timeout=2.0)
        self.assertEqual(len(results), 1)
        item = results[0]
        self.assertEqual(item['host'], 'app.example.com')
        self.assertEqual(item['status_code'], 200)
        self.assertEqual(item['title'], 'Secure Portal')
        self.assertEqual(item['server'], 'nginx/1.25.0')

    def test_results_html_report_export(self):
        from app import app, JOBS

        test_job_id = 'test-job-report-123'
        JOBS[test_job_id] = {
            'id': test_job_id,
            'domain': 'testgulam.com',
            'status': 'completed',
            'results': [
                {'subdomain': 'vpn.testgulam.com', 'sources': ['crtsh', 'subfinder'], 'confidence': 'high', 'dns': 'resolved'}
            ],
            'sources': {'crtsh': 1, 'subfinder': 1},
            'cached': False
        }

        with app.test_client() as client:
            resp = client.get(f'/api/results.html?job={test_job_id}')
            self.assertEqual(resp.status_code, 200)
            self.assertIn('text/html', resp.content_type)
            html_text = resp.get_data(as_text=True)
            self.assertIn('Developed by Gulam', html_text)
            self.assertIn('vpn.testgulam.com', html_text)
            self.assertIn('testgulam.com', html_text)


    def test_cname_auditor_detects_dangling_service(self):
        from enumerator.cname_auditor import audit_hosts

        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.text = '<html><body>NoSuchBucket: The specified bucket does not exist</body></html>'

        with patch('enumerator.cname_auditor.resolve_cname', return_value='mytestbucket.s3.amazonaws.com'), \
             patch('enumerator.cname_auditor.requests.get', return_value=mock_resp):
            findings = audit_hosts(['storage.example.com'])
            self.assertEqual(len(findings), 1)
            f = findings[0]
            self.assertEqual(f['host'], 'storage.example.com')
            self.assertEqual(f['service'], 'AWS S3')
            self.assertEqual(f['status'], 'dangling')
            self.assertTrue('bucket' in f['evidence'].lower())

    def test_api_graph_data_categorization(self):
        from app import app

        with app.test_client() as client:
            resp = client.post('/api/graph/data', json={
                'domain': 'example.com',
                'subdomains': [
                    'api.example.com',
                    'dev-portal.example.com',
                    'auth.example.com',
                    'www.example.com',
                    'ns1.example.com'
                ]
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data['domain'], 'example.com')
            self.assertEqual(data['developed_by'], 'Gulam')
            cats = data['category_counts']
            self.assertGreaterEqual(cats['api'], 1)
            self.assertGreaterEqual(cats['dev'], 1)
            self.assertGreaterEqual(cats['auth'], 1)
            self.assertGreaterEqual(cats['web'], 1)
            self.assertGreaterEqual(cats['infra'], 1)
            self.assertEqual(len(data['nodes']), 6) # root + 5 subs

    def test_api_info_endpoint(self):
        from app import app
        with app.test_client() as client:
            resp = client.get('/api/info')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data['name'], 'SubZero')
            self.assertEqual(data['version'], '2.2.0')
            self.assertEqual(data['author'], 'Gulam Khan')
            self.assertEqual(data['license'], 'MIT')
            self.assertEqual(data['status'], 'online')



if __name__ == '__main__':
    unittest.main()


