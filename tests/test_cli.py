import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from enumerator.cli import (
    build_parser,
    run_cli_scan,
    write_outputs,
    list_sources_table,
    main,
)
from enumerator.request_utils import check_network_connectivity


class TestSubZeroCLI(unittest.TestCase):
    def test_parser_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertEqual(args.domain, "example.com")
        self.assertFalse(args.silent)
        self.assertFalse(args.active)
        self.assertFalse(args.resolve)
        self.assertEqual(args.wordlist, "5000")
        self.assertEqual(args.threads, 500)
        self.assertEqual(args.resolver, "all")

    def test_parser_custom_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "-dL", "targets.txt",
            "-s", "crtsh,otx",
            "-es", "amass",
            "-all",
            "-a",
            "-w", "1000",
            "-t", "250",
            "--permute",
            "-r",
            "--resolver", "cloudflare",
            "--only-resolved",
            "--cname",
            "--probe",
            "--ip-intel",
            "--archive",
            "-o", "out.txt",
            "-oJ", "out.json",
            "-oCSV", "out.csv",
            "-silent",
            "-v",
            "--no-color",
            "-i",
        ])
        self.assertEqual(args.list, "targets.txt")
        self.assertEqual(args.sources, "crtsh,otx")
        self.assertEqual(args.exclude_sources, "amass")
        self.assertTrue(args.deep)
        self.assertTrue(args.active)
        self.assertEqual(args.wordlist, "1000")
        self.assertEqual(args.threads, 250)
        self.assertTrue(args.permute)
        self.assertTrue(args.resolve)
        self.assertEqual(args.resolver, "cloudflare")
        self.assertTrue(args.only_resolved)
        self.assertTrue(args.cname)
        self.assertTrue(args.probe)
        self.assertTrue(args.ip_intel)
        self.assertTrue(args.archive)
        self.assertEqual(args.output, "out.txt")
        self.assertEqual(args.json, "out.json")
        self.assertEqual(args.csv, "out.csv")
        self.assertTrue(args.silent)
        self.assertTrue(args.verbose)
        self.assertTrue(args.no_color)
        self.assertTrue(args.interactive)

    @patch('enumerator.cli.run_interactive_wizard')
    def test_interactive_wizard_dispatch(self, mock_wizard):
        main(["-i"])
        mock_wizard.assert_called_once()

    def test_list_sources_table(self):
        out = io.StringIO()
        with patch('sys.stdout', out):
            list_sources_table()
        rendered = out.getvalue()
        self.assertIn("subfinder", rendered)
        self.assertIn("crtsh", rendered)
        self.assertIn("otx", rendered)

    def test_write_outputs(self):
        scan_data = {
            'domain': 'test.com',
            'elapsed': 3.14,
            'subdomains': ['api.test.com', 'dead.test.com'],
            'results': [
                {
                    'subdomain': 'api.test.com',
                    'sources': ['crtsh'],
                    'dns_status': 'resolved',
                    'ips': ['1.2.3.4'],
                    'waf_provider': 'Cloudflare',
                    'http_status': 200,
                    'http_title': 'API Gateway',
                    'http_server': 'cloudflare'
                },
                {
                    'subdomain': 'dead.test.com',
                    'sources': ['otx'],
                    'dns_status': 'unresolved',
                    'ips': []
                }
            ],
            'sources': {'crtsh': 1, 'otx': 1},
            'errors': []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            txt_path = os.path.join(tmpdir, "out.txt")
            json_path = os.path.join(tmpdir, "out.json")
            csv_path = os.path.join(tmpdir, "out.csv")

            # Test write all
            write_outputs(scan_data, txt_path=txt_path, json_path=json_path, csv_path=csv_path, only_resolved=False)

            with open(txt_path, 'r', encoding='utf-8') as f:
                txt_content = f.read().splitlines()
            self.assertEqual(txt_content, ['api.test.com', 'dead.test.com'])

            with open(json_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            self.assertEqual(json_data['target'], 'test.com')
            self.assertEqual(len(json_data['details']), 2)

            with open(csv_path, 'r', encoding='utf-8') as f:
                csv_lines = f.read().splitlines()
            self.assertEqual(len(csv_lines), 3)  # Header + 2 rows

            # Test write only_resolved
            write_outputs(scan_data, txt_path=txt_path, json_path=json_path, csv_path=csv_path, only_resolved=True)
            with open(txt_path, 'r', encoding='utf-8') as f:
                resolved_txt = f.read().splitlines()
            self.assertEqual(resolved_txt, ['api.test.com'])

    @patch('enumerator.cli.PROVIDERS')
    def test_run_cli_scan_integration(self, mock_providers):
        mock_providers.__getitem__.side_effect = lambda name: (
            lambda domain: (['sub1.example.com', 'sub2.example.com'], None, 2)
        )
        mock_providers.__contains__.return_value = True

        data = run_cli_scan(
            domain="example.com",
            sources=["otx"],
            silent=True
        )
        self.assertEqual(data['domain'], 'example.com')
        self.assertEqual(data['subdomains'], ['sub1.example.com', 'sub2.example.com'])
        self.assertEqual(len(data['results']), 2)

    def test_run_cli_scan_invalid_domain(self):
        data = run_cli_scan(
            domain="invalid domain!@#",
            sources=["otx"],
            silent=True
        )
        self.assertEqual(data['subdomains'], [])
        self.assertIn("Invalid domain format", data['errors'])

    @patch('enumerator.cli.run_cli_scan')
    def test_cli_main_silent_mode(self, mock_run):
        mock_run.return_value = {
            'domain': 'example.com',
            'subdomains': ['api.example.com', 'dev.example.com'],
            'results': [
                {'subdomain': 'api.example.com', 'dns_status': 'resolved'},
                {'subdomain': 'dev.example.com', 'dns_status': 'resolved'}
            ],
            'sources': {'otx': 2},
            'errors': [],
            'elapsed': 1.2
        }

        stdout_buf = io.StringIO()
        with patch('sys.stdout', stdout_buf):
            main(["-d", "example.com", "-s", "otx", "-silent"])

        output_lines = stdout_buf.getvalue().strip().splitlines()
        self.assertEqual(output_lines, ['api.example.com', 'dev.example.com'])

    def test_check_network_connectivity(self):
        mock_session = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_session.head.return_value = mock_resp

        with patch('enumerator.request_utils.get_session', return_value=mock_session):
            res = check_network_connectivity(test_endpoints=[('MockDNS', 'https://mock.dns')])
            self.assertTrue(res['online'])
            self.assertEqual(res['tested_endpoint'], 'MockDNS')

    @patch('enumerator.cli.run_cli_scan')
    def test_tool_exclusions_and_amass_separation(self, mock_run):
        mock_run.return_value = {
            'domain': 'example.com',
            'subdomains': [],
            'results': [],
            'sources': {},
            'errors': [],
            'elapsed': 0.1
        }

        # 1. Default should exclude amass and subfinder_all
        main(["-d", "example.com", "-silent"])
        called_sources = mock_run.call_args.kwargs['sources']
        self.assertNotIn('amass', called_sources)
        self.assertNotIn('subfinder_all', called_sources)
        self.assertIn('subfinder', called_sources)
        self.assertIn('crtsh', called_sources)

        # 2. Exclude via -x subfinder,urlscan
        main(["-d", "example.com", "-x", "subfinder,urlscan", "-silent"])
        called_sources = mock_run.call_args.kwargs['sources']
        self.assertNotIn('subfinder', called_sources)
        self.assertNotIn('urlscan', called_sources)
        self.assertIn('crtsh', called_sources)

        # 3. Exclude via individual flag --no-crtsh
        main(["-d", "example.com", "--no-crtsh", "--no-sslmate", "-silent"])
        called_sources = mock_run.call_args.kwargs['sources']
        self.assertNotIn('crtsh', called_sources)
        self.assertNotIn('sslmate', called_sources)
        self.assertIn('subfinder', called_sources)

        # 4. Explicitly include amass via --amass
        main(["-d", "example.com", "--amass", "-silent"])
        called_sources = mock_run.call_args.kwargs['sources']
        self.assertIn('amass', called_sources)

        # 5. Exclude via alias names (crt.sh, urlscan.io, certspotter)
        main(["-d", "example.com", "-x", "crt.sh,urlscan.io,certspotter", "-silent"])
        called_sources = mock_run.call_args.kwargs['sources']
        self.assertNotIn('crtsh', called_sources)
        self.assertNotIn('urlscan', called_sources)
        self.assertNotIn('sslmate', called_sources)
        self.assertIn('subfinder', called_sources)

    def test_excluded_tools_never_invoked(self):
        """Verify that when a tool is excluded, its underlying provider function is NEVER executed."""
        called = []

        def fake_provider(tool_name):
            def _inner(domain):
                called.append(tool_name)
                return [f"found.{domain}"], None, 1
            return _inner

        mock_providers = {
            'subfinder': fake_provider('subfinder'),
            'crtsh': fake_provider('crtsh'),
            'sslmate': fake_provider('sslmate'),
            'rapiddns': fake_provider('rapiddns'),
            'hackertarget': fake_provider('hackertarget'),
            'otx': fake_provider('otx'),
            'urlscan': fake_provider('urlscan'),
            'amass': fake_provider('amass'),
        }

        with patch('enumerator.cli.PROVIDERS', mock_providers):
            # Exclude subfinder and crtsh
            data = run_cli_scan(
                domain="example.com",
                sources=["sslmate", "otx"],  # subfinder, crtsh, amass excluded
                silent=True
            )
            # Only sslmate and otx should be called!
            self.assertIn('sslmate', called)
            self.assertIn('otx', called)
            self.assertNotIn('subfinder', called)
            self.assertNotIn('crtsh', called)
            self.assertNotIn('amass', called)

    @patch('enumerator.cli.dns_brute_force')
    def test_cli_scan_active_dns_integration(self, mock_dns_brute):
        mock_dns_brute.return_value = (['brute1.example.com', 'brute2.example.com'], None, 2)
        data = run_cli_scan(
            domain="example.com",
            sources=[],
            active_dns=True,
            wordlist_size="1000",
            active_threads=200,
            silent=True
        )
        mock_dns_brute.assert_called_once_with(
            domain="example.com",
            wordlist=None,
            max_workers=200,
            wordlist_size="1000",
            log_callback=None,
            verbose=False
        )
        self.assertIn('brute1.example.com', data['subdomains'])
        self.assertIn('brute2.example.com', data['subdomains'])
        self.assertEqual(data['sources'].get('active-dns'), 2)
        self.assertEqual(data['errors'], [])

    @patch('enumerator.cli.scan_permutations')
    def test_cli_scan_permutations_integration(self, mock_scan_perm):
        mock_scan_perm.return_value = {
            'results': [
                {'host': 'dev.api.example.com', 'status': 'resolved', 'alive': True, 'ips': ['1.1.1.1']}
            ]
        }
        with patch('enumerator.cli.PROVIDERS', {'otx': lambda d: (['api.example.com'], None, 1)}):
            data = run_cli_scan(
                domain="example.com",
                sources=["otx"],
                run_permutations=True,
                silent=True
            )
            self.assertIn('dev.api.example.com', data['subdomains'])
            self.assertEqual(data['errors'], [])

    @patch('enumerator.cli.probe_hosts')
    @patch('enumerator.cli.audit_hosts')
    @patch('enumerator.cli.mine_archive_urls')
    def test_cli_scan_archive_and_auditing_order(self, mock_archive, mock_audit, mock_probe):
        mock_archive.return_value = {
            'urls': ['https://archived.example.com/test'],
            'historical_subdomains': ['archived.example.com']
        }
        mock_audit.return_value = [{'host': 'archived.example.com', 'status': 'safe'}]
        mock_probe.return_value = [{'host': 'archived.example.com', 'status_code': 200}]

        data = run_cli_scan(
            domain="example.com",
            sources=[],
            mine_archives=True,
            audit_cnames=True,
            probe_http=True,
            silent=True
        )
        self.assertIn('archived.example.com', data['subdomains'])
        # Verify that archived subdomain was passed to both audit_hosts and probe_hosts
        audited_hosts = mock_audit.call_args[0][0]
        self.assertIn('archived.example.com', audited_hosts)
        probed_hosts = mock_probe.call_args[0][0]
        self.assertIn('archived.example.com', probed_hosts)
