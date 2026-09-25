"""
SubZero CLI - Advanced OSINT & Active Reconnaissance Platform
Terminal Command Line Interface for Cybersecurity Professionals.
Developed by: Gulam Khan
"""
__author__ = "Gulam Khan"
__version__ = "2.2.0"

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Set, Dict, Any

from enumerator.providers import (
    DEFAULT_PROVIDER_ORDER,
    DEFAULT_PASSIVE_PROVIDERS,
    TOOL_ALIASES,
    PROVIDERS,
    resolve_binary,
)
from enumerator.normalizer import normalize_subdomains, valid_domain
from enumerator.active_scanner import dns_brute_force
from enumerator.dns_resolver import check_domain_multi_resolver, PUBLIC_RESOLVERS
from enumerator.ip_intel import classify_ips
from enumerator.http_prober import probe_hosts
from enumerator.cname_auditor import audit_hosts
from enumerator.archive_miner import mine_archive_urls
from enumerator.permutation_engine import generate_permutations
from enumerator.request_utils import check_network_connectivity
from enumerator.tls_scraper import scrape_tls_sans
from enumerator.wildcard_detector import detect_wildcard_dns, is_wildcard_false_positive
from enumerator.origin_verifier import verify_origin_candidates
from enumerator.ptr_sweeper import sweep_ips_for_ptrs
from enumerator.shodan_free import harvest_shodan_internetdb
from enumerator.nested_engine import discover_nested_subdomains


# ---------------------------------------------------------------------------
# ANSI Terminal Colors
# ---------------------------------------------------------------------------
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.MAGENTA = ''
        cls.BLUE = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.RESET = ''


BANNER = r"""
  ███████╗██╗   ██╗██████╗ ███████╗███████╗██████╗  ██████╗ 
  ██╔════╝██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
  ███████╗██║   ██║██████╔╝  ███╔╝ █████╗  ██████╔╝██║   ██║
  ╚════██║██║   ██║██╔══██╗ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
  ███████║╚██████╔╝██████╔╝███████╗███████╗██║  ██║╚██████╔╝
  ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
     Next-Gen OSINT & DNS Reconnaissance • CLI Edition
     Developed by Gulam Khan | Fast • Resilient • Pipeable
"""


def print_banner(silent: bool = False):
    if silent:
        return
    sys.stderr.write(f"{Colors.CYAN}{BANNER}{Colors.RESET}\n")
    sys.stderr.flush()


def log_info(msg: str, silent: bool = False):
    if not silent:
        sys.stderr.write(f"{Colors.CYAN}[*]{Colors.RESET} {msg}\n")
        sys.stderr.flush()


def log_success(msg: str, silent: bool = False):
    if not silent:
        sys.stderr.write(f"{Colors.GREEN}[+]{Colors.RESET} {msg}\n")
        sys.stderr.flush()


def log_warn(msg: str, silent: bool = False):
    if not silent:
        sys.stderr.write(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}\n")
        sys.stderr.flush()


def log_error(msg: str, silent: bool = False):
    if not silent:
        sys.stderr.write(f"{Colors.RED}[-]{Colors.RESET} {msg}\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Engine / Provider Introspection
# ---------------------------------------------------------------------------
PROVIDER_META = {
    'subfinder': {'type': 'CLI Binary', 'speed': 'High', 'desc': 'ProjectDiscovery passive subdomain discovery binary'},
    'subfinder_all': {'type': 'CLI Binary (Deep)', 'speed': 'Medium', 'desc': 'Subfinder with all 52 external OSINT sources'},
    'amass': {'type': 'CLI Binary (Deep)', 'speed': 'Slow', 'desc': 'OWASP Amass passive in-depth network mapper'},
    'crtsh': {'type': 'API / HTTP', 'speed': 'High', 'desc': 'Certificate Transparency log database search'},
    'sslmate': {'type': 'API / HTTP', 'speed': 'High', 'desc': 'CertSpotter CT log stream API'},
    'rapiddns': {'type': 'Web Scraping', 'speed': 'High', 'desc': 'RapidDNS public subdomain database'},
    'hackertarget': {'type': 'API / HTTP', 'speed': 'High', 'desc': 'HackerTarget host search engine'},
    'otx': {'type': 'API / HTTP', 'speed': 'High', 'desc': 'AlienVault OTX passive DNS indicators'},
    'urlscan': {'type': 'API / HTTP', 'speed': 'High', 'desc': 'URLScan.io historical scan records'},
}


def list_sources_table():
    print(f"\n{Colors.BOLD}{Colors.CYAN}SubZero — Available Reconnaissance Sources:{Colors.RESET}\n")
    print(f"{'Source':<16} {'Type':<22} {'Speed':<10} {'Status':<14} {'Description'}")
    print("-" * 90)
    for name in DEFAULT_PROVIDER_ORDER:
        meta = PROVIDER_META.get(name, {'type': 'Provider', 'speed': 'Medium', 'desc': ''})
        if 'Binary' in meta['type']:
            bin_name = 'subfinder' if 'subfinder' in name else 'amass'
            found = resolve_binary(bin_name)
            status = f"{Colors.GREEN}Installed{Colors.RESET}" if found else f"{Colors.YELLOW}Not in PATH{Colors.RESET}"
        else:
            status = f"{Colors.GREEN}Ready (HTTP){Colors.RESET}"

        print(f"{name:<16} {meta['type']:<22} {meta['speed']:<10} {status:<23} {meta['desc']}")
    print()


# ---------------------------------------------------------------------------
# Core Reconnaissance Execution
# ---------------------------------------------------------------------------
def run_cli_scan(
    domain: str,
    sources: List[str],
    active_dns: bool = False,
    wordlist_size: str = "5000",
    active_threads: int = 500,
    resolve_dns: bool = False,
    selected_resolver: str = "all",
    audit_cnames: bool = False,
    probe_http: bool = False,
    ip_intel: bool = False,
    mine_archives: bool = False,
    run_permutations: bool = False,
    tls_san: bool = False,
    wildcard: bool = False,
    verify_origin: bool = False,
    ptr_sweep: bool = False,
    run_nested: bool = False,
    shodan_free: bool = True,
    silent: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    domain = domain.strip().lower().rstrip('.')
    if not valid_domain(domain):
        log_error(f"Invalid domain format: {domain}", silent)
        return {'domain': domain, 'subdomains': [], 'results': [], 'errors': ["Invalid domain format"]}

    start_time = time.time()
    log_info(f"Target: {Colors.BOLD}{domain}{Colors.RESET}", silent)
    log_info(f"Active engines: {', '.join(sources) + (', active-dns' if active_dns else '')}", silent)

    found_by: Dict[str, Set[str]] = {}
    source_counts: Dict[str, int] = {}
    errors: List[str] = []

    def _execute_provider(name: str):
        t0 = time.time()
        try:
            values, err, cnt = PROVIDERS[name](domain)
            dur = round(time.time() - t0, 2)
            if verbose:
                if err:
                    log_warn(f"[{name}] {err} ({dur}s)", silent)
                else:
                    log_info(f"[{name}] Completed ({dur}s) - Found {cnt} subdomains", silent)
            return name, values, err, cnt
        except Exception as exc:
            return name, [], str(exc), 0

    # Passive Enumeration Pool
    total_workers = min(len(sources), 8) or 1
    with ThreadPoolExecutor(max_workers=total_workers) as pool:
        futures = [pool.submit(_execute_provider, name) for name in sources]
        for future in as_completed(futures):
            name, values, err, cnt = future.result()
            source_counts[name] = cnt
            if err:
                errors.append(f"{name}: {err}")
            for host in normalize_subdomains(values, domain):
                found_by.setdefault(host, set()).add(name)

    # Active DNS Brute-Forcing (if requested)
    if active_dns:
        log_info(f"Starting active DNS wordlist brute-forcing ({wordlist_size} prefixes, {active_threads} threads)...", silent)
        try:
            active_vals, active_err, active_cnt = dns_brute_force(
                domain=domain,
                wordlist=None,
                concurrency=active_threads,
                wordlist_name=wordlist_size,
                log_callback=(lambda m: log_info(f"[DNS-BRUTE] {m}", silent)) if verbose else None,
                verbose=verbose
            )
            source_counts['active-dns'] = active_cnt
            if active_err:
                errors.append(f"active-dns: {active_err}")
            for host in normalize_subdomains(active_vals, domain):
                found_by.setdefault(host, set()).add('active-dns')
            log_success(f"Active DNS brute force discovered {active_cnt} subdomains", silent)
        except Exception as exc:
            errors.append(f"active-dns: {exc}")
            log_error(f"Active DNS brute-forcing encountered an error: {exc}", silent)

    # Permutations (if requested)
    if run_permutations and found_by:
        log_info("Generating dynamic permutations and mutations on discovered subdomains...", silent)
        try:
            perm_hosts = generate_permutations(domain, list(found_by.keys()), max_results=300)
            log_info(f"Generated {len(perm_hosts)} permutations; resolving against public DNS...", silent)
            with ThreadPoolExecutor(max_workers=16) as pool:
                res_futures = {pool.submit(check_domain_multi_resolver, h, selected_resolver): h for h in perm_hosts}
                perm_resolved = 0
                for f in as_completed(res_futures):
                    h = res_futures[f]
                    res = f.result()
                    if res.get('status') == 'resolved':
                        found_by.setdefault(h, set()).add('permutations')
                        perm_resolved += 1
            log_success(f"Permutations uncovered {perm_resolved} live subdomains", silent)
        except Exception as exc:
            errors.append(f"permutations: {exc}")

    # Wildcard DNS Detection (if requested)
    wc_info = {'is_wildcard': False, 'wildcard_ips': [], 'wildcard_cnames': []}
    if wildcard:
        log_info(f"Checking for wildcard DNS catch-all (*.{domain})...", silent)
        try:
            wc_info = detect_wildcard_dns(domain, timeout=2.0)
            if wc_info.get('is_wildcard'):
                log_warn(f"Wildcard DNS detected (*.{domain}) -> IPs: {', '.join(wc_info['wildcard_ips'])}", silent)
            else:
                log_info(f"No wildcard DNS detected for {domain}", silent)
        except Exception as exc:
            errors.append(f"wildcard_detector: {exc}")

    # DNS Resolution Validation (if requested)
    dns_records: Dict[str, Dict[str, Any]] = {}
    if (resolve_dns or tls_san or ptr_sweep) and found_by:
        res_label = selected_resolver.upper() if selected_resolver != 'all' else 'Tier-1 Multi-Resolvers'
        log_info(f"Resolving {len(found_by)} subdomains via {res_label}...", silent)
        with ThreadPoolExecutor(max_workers=60) as pool:
            futures = {pool.submit(check_domain_multi_resolver, host, selected_resolver): host for host in found_by}
            for future in as_completed(futures):
                host = futures[future]
                dns_records[host] = future.result()

    # Direct TLS SAN Certificate Scraping (if requested)
    if tls_san and dns_records:
        resolved_ips = list(dict.fromkeys(ip for rec in dns_records.values() for ip in rec.get('ips', []) if ip))
        if resolved_ips:
            log_info(f"Probing direct TLS SAN certificates across {len(resolved_ips[:40])} live IPs (ports 443 & 8443)...", silent)
            try:
                tls_subs = scrape_tls_sans(resolved_ips[:40], domain, ports=[443, 8443], max_workers=12, timeout=2.5)
                new_tls = [s for s in tls_subs if s not in found_by and s != domain]
                if new_tls:
                    log_success(f"TLS SAN scraper uncovered {len(new_tls)} certificate hostnames", silent)
                    for s in new_tls:
                        found_by.setdefault(s, set()).add('tls-san')
                    if resolve_dns:
                        with ThreadPoolExecutor(max_workers=min(40, len(new_tls))) as pool:
                            fut_map = {pool.submit(check_domain_multi_resolver, s, selected_resolver): s for s in new_tls}
                            for f in as_completed(fut_map):
                                dns_records[fut_map[f]] = f.result()
            except Exception as exc:
                errors.append(f"tls_san: {exc}")

    # Reverse DNS (PTR) Subnet Sweeper (if requested)
    if ptr_sweep and dns_records:
        candidate_ips = list(dict.fromkeys(ip for rec in dns_records.values() for ip in rec.get('ips', []) if ip))
        if candidate_ips:
            log_info("Sweeping /24 subnets via Reverse DNS (PTR)...", silent)
            try:
                ptr_res = sweep_ips_for_ptrs(candidate_ips[:5], domain, sweep_surrounding=True, window=3, max_workers=15)
                new_ptrs = [s for s in ptr_res.get('discovered_subdomains', []) if s not in found_by and s != domain]
                if new_ptrs:
                    log_success(f"PTR subnet sweep uncovered {len(new_ptrs)} reverse DNS hostnames", silent)
                    for s in new_ptrs:
                        found_by.setdefault(s, set()).add('ptr-sweep')
                    if resolve_dns:
                        with ThreadPoolExecutor(max_workers=min(8, len(new_ptrs))) as pool:
                            fut_map = {pool.submit(check_domain_multi_resolver, s, selected_resolver): s for s in new_ptrs}
                            for f in as_completed(fut_map):
                                dns_records[fut_map[f]] = f.result()
            except Exception as exc:
                errors.append(f"ptr_sweep: {exc}")

    # Shodan InternetDB Harvest (100% Free, Zero Key Required)
    if shodan_free and dns_records:
        live_ips = list(dict.fromkeys(ip for rec in dns_records.values() for ip in rec.get('ips', []) if ip))
        if live_ips:
            log_info(f"Querying Shodan InternetDB across {len(live_ips[:35])} live IPs (100% free)...", silent)
            try:
                shodan_res = harvest_shodan_internetdb(live_ips[:35], domain, max_workers=15, timeout=3.0)
                shodan_subs = shodan_res.get('subdomains', [])
                new_shodan = [s for s in shodan_subs if s not in found_by and s != domain]
                if new_shodan:
                    log_success(f"Shodan InternetDB uncovered {len(new_shodan)} hostnames", silent)
                    for s in new_shodan:
                        found_by.setdefault(s, set()).add('shodan-free')
                    if resolve_dns:
                        with ThreadPoolExecutor(max_workers=min(12, len(new_shodan))) as pool:
                            fut_map = {pool.submit(check_domain_multi_resolver, s, selected_resolver): s for s in new_shodan}
                            for f in as_completed(fut_map):
                                dns_records[fut_map[f]] = f.result()
            except Exception as exc:
                errors.append(f"shodan_free: {exc}")

    # Nested & Multi-Tenant Recursive Engine
    if (run_nested or active_dns) and found_by:
        log_info("Mining multi-level tenant sub-zones for nested asset discovery...", silent)
        try:
            nested_subs = discover_nested_subdomains(
                domain,
                list(found_by.keys()),
                max_candidates=1000,
                max_workers=60,
                dns_resolver=selected_resolver,
                log_cb=(lambda m: log_info(m, silent)) if verbose else None
            )
            new_nested = [s for s in nested_subs if s not in found_by and s != domain]
            if new_nested:
                log_success(f"Nested engine uncovered {len(new_nested)} multi-level live subdomains", silent)
                for s in new_nested:
                    found_by.setdefault(s, set()).add('nested-engine')
                if resolve_dns:
                    with ThreadPoolExecutor(max_workers=min(40, len(new_nested))) as pool:
                        fut_map = {pool.submit(check_domain_multi_resolver, s, selected_resolver): s for s in new_nested}
                        for f in as_completed(fut_map):
                            dns_records[fut_map[f]] = f.result()
        except Exception as exc:
            errors.append(f"nested_engine: {exc}")


    # CNAME Takeover Audit (if requested)
    cname_results: List[Dict[str, Any]] = []
    if audit_cnames and found_by:
        log_info(f"Auditing {len(found_by)} subdomains for dangling CNAME takeovers...", silent)
        try:
            cname_results = audit_hosts(list(found_by.keys()), max_workers=20)
            vulnerable = [c for c in cname_results if c.get('status') == 'dangling']
            if vulnerable:
                for v in vulnerable:
                    log_warn(f"POTENTIAL TAKEOVER: {v['host']} -> {v.get('cname')} ({v.get('service')})", silent)
            else:
                log_info("No dangling CNAME takeovers identified.", silent)
        except Exception as exc:
            errors.append(f"cname_auditor: {exc}")

    # HTTP Alive Prober (if requested)
    probe_results: Dict[str, Dict[str, Any]] = {}
    if probe_http and found_by:
        log_info(f"Probing HTTP/HTTPS services across {len(found_by)} hosts...", silent)
        try:
            probes = probe_hosts(list(found_by.keys()), max_workers=25, timeout=5.0)
            for p in probes:
                probe_results[p['host']] = p
        except Exception as exc:
            errors.append(f"http_prober: {exc}")

    # Archive Mining (if requested)
    archive_urls: List[str] = []
    if mine_archives:
        log_info(f"Mining historical endpoints from Wayback Machine and AlienVault...", silent)
        try:
            archive_data = mine_archive_urls(domain)
            archive_urls = archive_data.get('urls') or archive_data.get('sample_urls', [])
            log_success(f"Archived URLs harvested: {len(archive_urls)} endpoints", silent)
            hist_subs = archive_data.get('historical_subdomains', [])
            new_hist = [hs for hs in hist_subs if hs != domain and hs not in found_by]
            if new_hist:
                log_success(f"Archive mining uncovered {len(new_hist)} historical subdomains", silent)
                for hs in new_hist:
                    found_by.setdefault(hs, set()).add('archive-miner')
                if resolve_dns:
                    with ThreadPoolExecutor(max_workers=min(20, len(new_hist))) as pool:
                        fut_map = {pool.submit(check_domain_multi_resolver, s, selected_resolver): s for s in new_hist}
                        for f in as_completed(fut_map):
                            dns_records[fut_map[f]] = f.result()
        except Exception as exc:
            errors.append(f"archive_miner: {exc}")

    # Build Structured Results
    results = []
    for host in sorted(found_by.keys()):
        item: Dict[str, Any] = {
            'subdomain': host,
            'sources': sorted(list(found_by[host])),
            'confidence': 'high' if len(found_by[host]) > 1 else 'single-source',
        }
        if host in dns_records:
            dns_info = dns_records[host]
            status = dns_info.get('status', 'unresolved')
            item['dns_status'] = status
            item['dns_resolver'] = dns_info.get('resolver', '')
            ips = dns_info.get('ips', [])
            cname = dns_info.get('cname', '')
            item['ips'] = ips
            item['cname'] = cname
            if wildcard:
                item['is_wildcard_catchall'] = is_wildcard_false_positive(ips, cname, wc_info)
            if ip_intel and (ips or cname):
                intel = classify_ips(ips, cname=cname)
                item['ip_intel'] = intel
                item['primary_ip'] = intel.get('primary_ip', '')
                item['waf_provider'] = intel.get('waf_provider', 'Direct Server')
                item['is_origin'] = intel.get('is_origin', True)
                item['is_cdn'] = intel.get('is_cdn', False)
                item['country_name'] = intel.get('country_name', 'Global')
                item['country_code'] = intel.get('country_code', '')
                item['country_flag'] = intel.get('country_flag', '🌐')

        if host in probe_results:
            pr = probe_results[host]
            item['http_status'] = pr.get('status_code')
            item['http_url'] = pr.get('url')
            item['http_title'] = pr.get('title')
            item['http_server'] = pr.get('server')

        results.append(item)

    # True Origin IP Active Verification (if requested)
    if verify_origin and results:
        candidate_origin_ips = list(dict.fromkeys(r.get('primary_ip') for r in results if r.get('is_origin') and r.get('primary_ip')))
        if candidate_origin_ips:
            log_info(f"Actively verifying True Origin IPs against WAF bypass for {len(candidate_origin_ips[:10])} candidates...", silent)
            try:
                ver_map = verify_origin_candidates(candidate_origin_ips[:10], domain, max_workers=8, timeout=3.0)
                for r in results:
                    pip = r.get('primary_ip')
                    if pip in ver_map and ver_map[pip].get('is_confirmed_origin'):
                        r['is_confirmed_origin'] = True
                        r['confirmed_origin'] = ver_map[pip]
                        log_success(f"Confirmed True Origin IP (WAF Bypass): {pip} for {r['subdomain']}", silent)
            except Exception as exc:
                errors.append(f"verify_origin: {exc}")

    elapsed = round(time.time() - start_time, 2)
    return {
        'domain': domain,
        'subdomains': sorted(list(found_by.keys())),
        'results': results,
        'sources': source_counts,
        'errors': errors,
        'elapsed': elapsed,
        'cname_audits': cname_results,
        'archive_urls': archive_urls,
    }


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------
def write_outputs(
    scan_data: Dict[str, Any],
    txt_path: str = None,
    json_path: str = None,
    csv_path: str = None,
    only_resolved: bool = False,
):
    results = scan_data.get('results', [])
    if only_resolved:
        results = [r for r in results if r.get('dns_status') == 'resolved']

    # Text output
    if txt_path:
        with open(txt_path, 'w', encoding='utf-8') as f:
            for item in results:
                f.write(f"{item['subdomain']}\n")

    # JSON output
    if json_path:
        export_payload = {
            'target': scan_data.get('domain'),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'author': 'Gulam Khan',
            'elapsed_seconds': scan_data.get('elapsed'),
            'total_subdomains': len(results),
            'subdomains': [r['subdomain'] for r in results],
            'details': results,
            'source_statistics': scan_data.get('sources', {}),
            'errors': scan_data.get('errors', []),
            'cname_audits': scan_data.get('cname_audits', []),
            'archive_urls': scan_data.get('archive_urls', []),
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(export_payload, f, indent=2)

    # CSV output
    if csv_path:
        with open(csv_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Subdomain', 'Sources', 'DNS Status', 'IP Addresses',
                'WAF / CDN Provider', 'HTTP Status', 'HTTP Title', 'HTTP Server'
            ])
            for r in results:
                writer.writerow([
                    r.get('subdomain', ''),
                    '; '.join(r.get('sources', [])),
                    r.get('dns_status', 'not-checked'),
                    '; '.join(r.get('ips', [])),
                    r.get('waf_provider', ''),
                    r.get('http_status', ''),
                    r.get('http_title', ''),
                    r.get('http_server', ''),
                ])


def display_terminal_summary(scan_data: Dict[str, Any], only_resolved: bool = False):
    results = scan_data.get('results', [])
    if only_resolved:
        results = [r for r in results if r.get('dns_status') == 'resolved']

    resolved_count = sum(1 for r in results if r.get('dns_status') == 'resolved')
    cdn_count = sum(1 for r in results if r.get('is_cdn'))
    origin_count = sum(1 for r in results if r.get('is_origin') and r.get('dns_status') == 'resolved')
    confirmed_origin_count = sum(1 for r in results if r.get('is_confirmed_origin'))
    wildcard_catchall_count = sum(1 for r in results if r.get('is_wildcard_catchall'))

    sys.stderr.write(f"\n{Colors.BOLD}{Colors.CYAN}══════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
    sys.stderr.write(f"  {Colors.BOLD}SubZero Reconnaissance Summary — {scan_data.get('domain')}{Colors.RESET}\n")
    sys.stderr.write(f"{Colors.BOLD}{Colors.CYAN}══════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
    sys.stderr.write(f"  Total Subdomains Discovered : {Colors.GREEN}{len(results)}{Colors.RESET}\n")
    if any('dns_status' in r for r in results):
        sys.stderr.write(f"  DNS Active / Alive Hosts    : {Colors.CYAN}{resolved_count}{Colors.RESET} / {len(results)}\n")
    if cdn_count or origin_count:
        sys.stderr.write(f"  Direct Origin Servers       : {Colors.YELLOW}{origin_count}{Colors.RESET}\n")
        sys.stderr.write(f"  Cloudflare / CDN Edge IPs   : {Colors.BLUE}{cdn_count}{Colors.RESET}\n")
    if confirmed_origin_count:
        sys.stderr.write(f"  🔥 Verified True Origin IPs : {Colors.GREEN}{confirmed_origin_count}{Colors.RESET} (WAF Bypass Verified)\n")
    if wildcard_catchall_count:
        sys.stderr.write(f"  ⚠️ Wildcard Catchalls Filtered: {Colors.YELLOW}{wildcard_catchall_count}{Colors.RESET}\n")
    sys.stderr.write(f"  Execution Time              : {scan_data.get('elapsed')}s\n")

    # Source breakdown
    sources = scan_data.get('sources', {})
    if sources:
        sys.stderr.write(f"\n  {Colors.BOLD}Source Yield Breakdown:{Colors.RESET}\n")
        for src, cnt in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            sys.stderr.write(f"    • {src:<15}: {Colors.GREEN}{cnt}{Colors.RESET}\n")

    # Notices
    errors = scan_data.get('errors', [])
    if errors:
        sys.stderr.write(f"\n  {Colors.YELLOW}External Engine Notices ({len(errors)}):{Colors.RESET}\n")
        for err in errors:
            sys.stderr.write(f"    {Colors.YELLOW}!{Colors.RESET} {err}\n")

    sys.stderr.write(f"{Colors.BOLD}{Colors.CYAN}══════════════════════════════════════════════════════════════════════{Colors.RESET}\n\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# CLI Argument Parser & Entrypoint
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subzero",
        description="SubZero — Next-Gen OSINT & Active Reconnaissance Platform (CLI Edition) by Gulam Khan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  subzero -d example.com -silent
  subzero -d example.com -silent | httpx -title -status-code
  subzero -d example.com -s crtsh,sslmate,otx -r --only-resolved -o live_subs.txt
  subzero -dL domains.txt -a -w 5000 -r --probe -oJ output.json
  subzero -d target.com -all --cname --ip-intel -oCSV audit.csv
  subzero --check-network
        """
    )

    target_group = parser.add_argument_group("TARGET SELECTION")
    target_group.add_argument("-d", "--domain", dest="domain", help="Target root domain to enumerate (e.g. example.com)")
    target_group.add_argument("-dL", "-l", "--list", dest="list", help="Path to file containing target domains (one per line)")

    source_group = parser.add_argument_group("RECON ENGINES & EXCLUSIONS")
    source_group.add_argument(
        "-s", "--sources", dest="sources",
        help="Comma-separated passive sources to execute (default: all fast passive sources)"
    )
    source_group.add_argument(
        "-x", "--exclude", "--skip", "-es", "--exclude-sources", dest="exclude_sources",
        help="Comma-separated tool names to exclude/remove (e.g. -x subfinder,urlscan)"
    )
    source_group.add_argument(
        "--amass", dest="amass", action="store_true",
        help="Explicitly enable OWASP Amass (kept separate by default)"
    )
    source_group.add_argument(
        "-all", "--deep", dest="deep", action="store_true",
        help="Enable deep, high-exhaustion passive engines (subfinder_all, amass)"
    )
    source_group.add_argument(
        "-ls", "--list-sources", dest="list_sources", action="store_true",
        help="Display all available reconnaissance sources and their status"
    )

    # Individual disable flags to easily skip any tool by name
    tool_toggle_group = parser.add_argument_group("INDIVIDUAL TOOL TOGGLE FLAGS")
    tool_toggle_group.add_argument("--no-subfinder", dest="no_subfinder", action="store_true", help="Do not call subfinder")
    tool_toggle_group.add_argument("--no-crtsh", dest="no_crtsh", action="store_true", help="Do not call crt.sh")
    tool_toggle_group.add_argument("--no-sslmate", dest="no_sslmate", action="store_true", help="Do not call SSLMate CertSpotter")
    tool_toggle_group.add_argument("--no-rapiddns", dest="no_rapiddns", action="store_true", help="Do not call RapidDNS")
    tool_toggle_group.add_argument("--no-hackertarget", dest="no_hackertarget", action="store_true", help="Do not call HackerTarget")
    tool_toggle_group.add_argument("--no-otx", dest="no_otx", action="store_true", help="Do not call AlienVault OTX")
    tool_toggle_group.add_argument("--no-urlscan", dest="no_urlscan", action="store_true", help="Do not call URLScan.io")

    active_group = parser.add_argument_group("ACTIVE BRUTE FORCE & PERMUTATIONS")
    active_group.add_argument("-a", "--active", dest="active", action="store_true", help="Enable active DNS wordlist brute forcing")
    active_group.add_argument(
        "-w", "--wordlist", dest="wordlist", default="5000",
        help="Wordlist size ('100', '1000', '5000', '20000') or path to custom wordlist file (default: 5000)"
    )
    active_group.add_argument("-t", "--threads", dest="threads", type=int, default=500, help="Concurrency for active scanning (default: 500)")
    active_group.add_argument("--permute", dest="permute", action="store_true", help="Mutate discovered subdomains with permutation engine")
    active_group.add_argument("--nested", dest="nested", action="store_true", help="Mine multi-tenant naming conventions & recursive sub-zones")

    dns_group = parser.add_argument_group("DNS RESOLUTION & FILTERING")
    dns_group.add_argument("-r", "--resolve", dest="resolve", action="store_true", help="Resolve subdomains across Tier-1 public multi-resolvers")
    dns_group.add_argument(
        "--resolver", dest="resolver", default="all",
        help="Specific DNS resolver to test against ('cloudflare', 'google', 'quad9', 'opendns', or 'all')"
    )
    dns_group.add_argument("--only-resolved", dest="only_resolved", action="store_true", help="Filter output to strictly live/resolved subdomains")

    security_group = parser.add_argument_group("SECURITY AUDITING & ENRICHMENT")
    security_group.add_argument("--cname", dest="cname", action="store_true", help="Audit for dangling CNAME records (subdomain takeover)")
    security_group.add_argument("--probe", dest="probe", action="store_true", help="Probe HTTP/HTTPS alive status, page title, and server headers")
    security_group.add_argument("--ip-intel", dest="ip_intel", action="store_true", help="Classify IPs as Direct Origin server vs Cloudflare/CDN/WAF")
    security_group.add_argument("--archive", dest="archive", action="store_true", help="Mine historical URLs from Wayback Machine & AlienVault")
    security_group.add_argument("--tls-san", dest="tls_san", action="store_true", help="Direct TLS SAN Certificate Scraper across port 443 of resolved IPs")
    security_group.add_argument("--wildcard", dest="wildcard", action="store_true", help="Detect DNS wildcard catch-all (*.domain) and flag false positives")
    security_group.add_argument("--verify-origin", dest="verify_origin", action="store_true", help="Actively probe candidate Origin IPs (Host header) to verify True Origin / WAF bypass")
    security_group.add_argument("--ptr-sweep", dest="ptr_sweep", action="store_true", help="Reverse DNS (PTR) subnet sweeper on /24 ranges of candidate IPs")
    security_group.add_argument("--no-shodan-free", dest="no_shodan_free", action="store_true", help="Disable automatic Shodan InternetDB harvesting")


    target_group.add_argument("-i", "--interactive", "--wizard", dest="interactive", action="store_true", help="Launch interactive step-by-step Cyber Recon Wizard to select tools & options")

    output_group = parser.add_argument_group("OUTPUT & PIPING")
    output_group.add_argument("-o", "--output", dest="output", help="Plaintext output file path (one subdomain per line)")
    output_group.add_argument("-oJ", "--json", dest="json", help="Structured JSON output file path")
    output_group.add_argument("-oCSV", "--csv", dest="csv", help="CSV output file path")
    output_group.add_argument("-silent", "-q", "--quiet", dest="silent", action="store_true", help="Clean stdout output (only subdomains, pipe-friendly)")
    output_group.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose diagnostic logs")
    output_group.add_argument("--no-color", dest="no_color", action="store_true", help="Disable ANSI terminal colors")

    diag_group = parser.add_argument_group("DIAGNOSTICS & SYSTEM")
    diag_group.add_argument("--check-network", dest="check_network", action="store_true", help="Check internet connectivity and OSINT reachability")
    diag_group.add_argument("-V", "--version", action="version", version=f"SubZero v{__version__} by {__author__}")

    return parser


def run_interactive_wizard():
    print_banner(silent=False)
    sys.stderr.write(f"\n{Colors.BOLD}{Colors.GREEN}══════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
    sys.stderr.write(f"  {Colors.BOLD}⚡ SubZero Interactive Cyber Recon Wizard{Colors.RESET}\n")
    sys.stderr.write(f"  Developed by Gulam Khan — Configure tools & scan targets easily\n")
    sys.stderr.write(f"{Colors.BOLD}{Colors.GREEN}══════════════════════════════════════════════════════════════════════{Colors.RESET}\n\n")
    sys.stderr.flush()

    # 1. Target Domain
    while True:
        try:
            domain = input(f"{Colors.BOLD}{Colors.CYAN}[?] Enter Target Domain (e.g. example.com): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            sys.exit(0)
        if domain and valid_domain(domain):
            break
        print(f"{Colors.RED}[!] Please enter a valid domain name (e.g. target.com).{Colors.RESET}")

    DEFAULT_PASSIVE_TOOLS = list(DEFAULT_PASSIVE_PROVIDERS)

    # 2. Tool / Engine Selection
    print(f"\n{Colors.BOLD}{Colors.CYAN}[?] Default Passive Recon Tools (Enabled):{Colors.RESET}")
    for i, t in enumerate(DEFAULT_PASSIVE_TOOLS, 1):
        meta = PROVIDER_META.get(t, {})
        print(f"  [{i}] {t:<14} [{Colors.GREEN}ON{Colors.RESET}] - {meta.get('desc', '')}")
    print(f"  [8] {'amass':<14} [{Colors.YELLOW}SEPARATE / OFF by default{Colors.RESET}] - OWASP Amass deep scanner")

    print(f"\n{Colors.BOLD}[?] Kisi tool ko remove / band karna hai?{Colors.RESET}")
    print("    • Tool ka naam ya number likhein jise nahi chalana (e.g. 'urlscan, hackertarget' ya '1,7')")
    print("    • Baki sab tools chalu rakhne ke liye direct [ENTER] press karein")
    exclude_input = input(f"{Colors.BOLD}{Colors.CYAN}Remove tools (optional): {Colors.RESET}").strip().lower()

    tool_number_map = {str(i): name for i, name in enumerate(DEFAULT_PASSIVE_TOOLS, 1)}
    tool_number_map['8'] = 'amass'

    excluded_tools = set()
    if exclude_input and exclude_input != 'none':
        for piece in exclude_input.replace(' ', ',').split(','):
            piece = piece.strip().lower()
            if not piece:
                continue
            if piece in tool_number_map:
                excluded_tools.add(tool_number_map[piece])
            else:
                alias = TOOL_ALIASES.get(piece, piece)
                if alias in PROVIDERS or alias in DEFAULT_PASSIVE_PROVIDERS:
                    excluded_tools.add(alias)
                else:
                    print(f"  {Colors.YELLOW}[!] Tool '{piece}' not recognized (ignored){Colors.RESET}")

    if excluded_tools:
        print(f"  {Colors.YELLOW}[*] Removed tool(s) [Inhe bilkul call nahi kiya jayega]: {', '.join(sorted(excluded_tools))}{Colors.RESET}")

    selected_sources = [s for s in DEFAULT_PASSIVE_TOOLS if s not in excluded_tools]

    # Amass separate prompt
    amass_ans = input(f"\n{Colors.BOLD}[?] OWASP Amass (deep slow scanner) chalu karna hai? (y/n) [default: n]: {Colors.RESET}").strip().lower()
    if amass_ans in ('y', 'yes') and 'amass' not in excluded_tools:
        selected_sources.append('amass')
        print(f"  {Colors.GREEN}[+] Amass enabled.{Colors.RESET}")
    else:
        print(f"  {Colors.YELLOW}[*] Amass alag rakha gaya hai (Disabled).{Colors.RESET}")

    print(f"\n  {Colors.BOLD}Selected Engines ({len(selected_sources)}):{Colors.RESET} {Colors.GREEN}{', '.join(selected_sources) if selected_sources else 'None'}{Colors.RESET}")

    # 3. Active DNS Brute-Forcing
    active_dns = False
    wordlist_size = "5000"
    active_ans = input(f"\n{Colors.BOLD}[?] Enable Active DNS Wordlist Brute Force? (y/n) [default: n]: {Colors.RESET}").strip().lower()
    if active_ans in ('y', 'yes'):
        active_dns = True
        print("  Select wordlist size:")
        print("    [1] 100 prefixes (~2 sec)")
        print("    [2] 1,000 prefixes (~5 sec)")
        print("    [3] 5,000 prefixes (~15 sec) [Recommended]")
        print("    [4] 20,000 prefixes (~45 sec)")
        wl_choice = input("  Choose size [1-4] (default: 3): ").strip() or "3"
        wl_map = {"1": "100", "2": "1000", "3": "5000", "4": "20000"}
        wordlist_size = wl_map.get(wl_choice, "5000")

    # 4. Multi-Resolver DNS Integrity
    resolve_dns = True
    only_resolved = False
    dns_ans = input(f"\n{Colors.BOLD}[?] Verify DNS Resolution across Tier-1 Resolvers (Cloudflare, Google, Quad9)? (y/n) [default: y]: {Colors.RESET}").strip().lower()
    if dns_ans in ('n', 'no'):
        resolve_dns = False
    else:
        resolve_dns = True
        only_ans = input("  Only display & export subdomains that are confirmed alive/resolved? (y/n) [default: n]: ").strip().lower()
        if only_ans in ('y', 'yes'):
            only_resolved = True

    # 5. Security Auditing Modules
    print(f"\n{Colors.BOLD}[?] Select Security Auditing Modules:{Colors.RESET}")
    cname_ans = input("  • Audit for Dangling CNAME Takeovers? (y/n) [default: y]: ").strip().lower()
    audit_cnames = cname_ans not in ('n', 'no')

    probe_ans = input("  • Probe HTTP/HTTPS Web Services (Status, Title, Server)? (y/n) [default: y]: ").strip().lower()
    probe_http = probe_ans not in ('n', 'no')

    ip_ans = input("  • IP Intelligence (Cloudflare vs Direct Origin Server)? (y/n) [default: y]: ").strip().lower()
    ip_intel = ip_ans not in ('n', 'no')

    archive_ans = input("  • Mine Historical Archive URLs (Wayback Machine & AlienVault)? (y/n) [default: n]: ").strip().lower()
    mine_archives = archive_ans in ('y', 'yes')

    # 6. Output Files
    print(f"\n{Colors.BOLD}[?] Select Output File Export:{Colors.RESET}")
    print("  [1] All Formats (TXT + JSON + CSV) [Recommended]")
    print("  [2] Plaintext only (.txt)")
    print("  [3] JSON report only (.json)")
    print("  [4] Spreadsheet CSV only (.csv)")
    print("  [5] Display in terminal only (No file export)")
    out_choice = input("Choose option [1-5] (default: 1): ").strip() or "1"

    safe_domain = domain.replace('.', '_')
    txt_file = None
    json_file = None
    csv_file = None

    if out_choice in ("1", "2"):
        txt_file = f"{safe_domain}_subdomains.txt"
    if out_choice in ("1", "3"):
        json_file = f"{safe_domain}_recon.json"
    if out_choice in ("1", "4"):
        csv_file = f"{safe_domain}_recon.csv"

    print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Configuration saved! Launching SubZero Reconnaissance...{Colors.RESET}\n")

    # Run scan
    scan_data = run_cli_scan(
        domain=domain,
        sources=selected_sources,
        active_dns=active_dns,
        wordlist_size=wordlist_size,
        active_threads=500,
        resolve_dns=resolve_dns or only_resolved,
        selected_resolver="all",
        audit_cnames=audit_cnames,
        probe_http=probe_http,
        ip_intel=ip_intel,
        mine_archives=mine_archives,
        run_permutations=False,
        silent=False,
        verbose=True,
    )

    # Output subdomains to stdout
    results = scan_data.get('results', [])
    if only_resolved:
        results = [r for r in results if r.get('dns_status') == 'resolved']

    for item in results:
        print(item['subdomain'])
        sys.stdout.flush()

    # Write output files
    if txt_file or json_file or csv_file:
        write_outputs(
            scan_data=scan_data,
            txt_path=txt_file,
            json_path=json_file,
            csv_path=csv_file,
            only_resolved=only_resolved
        )
        if txt_file:
            log_success(f"Plaintext subdomains saved to: {Colors.BOLD}{txt_file}{Colors.RESET}")
        if json_file:
            log_success(f"Structured JSON report saved to: {Colors.BOLD}{json_file}{Colors.RESET}")
        if csv_file:
            log_success(f"Audit spreadsheet saved to: {Colors.BOLD}{csv_file}{Colors.RESET}")

    display_terminal_summary(scan_data, only_resolved=only_resolved)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        if args.no_color:
            Colors.disable()

    # Network pre-flight check
    if args.check_network:
        print_banner(silent=False)
        log_info("Running network connectivity and DNS diagnostic pre-flight...", silent=False)
        net_status = check_network_connectivity()
        if net_status.get('online'):
            log_success(f"Internet connectivity: ACTIVE (verified via {net_status.get('tested_endpoint')})", silent=False)
            sys.exit(0)
        else:
            log_error(f"Internet connectivity: FAILED or BLOCKED", silent=False)
            for err in net_status.get('errors', []):
                log_warn(f"  • {err}", silent=False)
            log_warn(f"Advice: {net_status.get('advice')}", silent=False)
            sys.exit(1)

    # Source listing
    if args.list_sources:
        print_banner(silent=False)
        list_sources_table()
        sys.exit(0)

    # Collect target domains
    # Launch interactive wizard if explicitly requested
    if args.interactive:
        run_interactive_wizard()
        return

    # Collect target domains
    targets: List[str] = []
    if args.domain:
        targets.append(args.domain.strip())
    elif args.list:
        p = Path(args.list)
        if not p.is_file():
            log_error(f"Target list file not found: {args.list}", args.silent)
            sys.exit(1)
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        try:
            if not sys.stdin.isatty():
                # Read from pipeline stdin (e.g. echo example.com | python cli.py -silent)
                for line in sys.stdin:
                    line_str = line.strip()
                    if line_str and not line_str.startswith('#'):
                        targets.append(line_str)
        except (OSError, ValueError):
            pass

    # If launched with no targets in an interactive terminal, launch wizard
    try:
        is_interactive_terminal = sys.stdin.isatty()
    except Exception:
        is_interactive_terminal = False

    if not targets and is_interactive_terminal:
        run_interactive_wizard()
        return

    if not targets:
        print_banner(silent=args.silent)
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Default passive tools (Amass is separate and kept off by default)
    selected_sources = []
    if args.sources:
        for s in args.sources.split(','):
            s_name = s.strip().lower()
            alias = TOOL_ALIASES.get(s_name, s_name)
            if alias in PROVIDERS:
                selected_sources.append(alias)
            else:
                log_warn(f"Unknown source '{s_name}' ignored.", args.silent)
    else:
        selected_sources = list(DEFAULT_PASSIVE_PROVIDERS)

    # Amass is kept separate by default, only added if explicitly passed via --amass or -all/--deep
    if (getattr(args, 'amass', False) or args.deep) and 'amass' not in selected_sources:
        selected_sources.append('amass')
    if args.deep and 'subfinder_all' not in selected_sources:
        selected_sources.append('subfinder_all')

    # Collect any tool names to remove / exclude
    excluded = set()
    if args.exclude_sources:
        raw_items = args.exclude_sources if isinstance(args.exclude_sources, list) else [args.exclude_sources]
        for entry in raw_items:
            for x in entry.replace(' ', ',').split(','):
                x_clean = x.strip().lower()
                if x_clean:
                    alias = TOOL_ALIASES.get(x_clean, x_clean)
                    excluded.add(alias)

    # Check individual toggle flags (--no-subfinder, --no-urlscan, etc.)
    for tool in DEFAULT_PROVIDER_ORDER:
        flag_name = f"no_{tool.replace('-', '_')}"
        if getattr(args, flag_name, False):
            excluded.add(tool)

    # Filter out excluded tools completely so they are NEVER called
    selected_sources = [s for s in selected_sources if s not in excluded]

    if excluded and not args.silent:
        log_info(f"Excluded engine(s) [will NOT be called]: {', '.join(sorted(excluded))}", args.silent)

    print_banner(silent=args.silent)

    # Execute recon for each target
    for target in targets:
        scan_data = run_cli_scan(
            domain=target,
            sources=selected_sources,
            active_dns=args.active,
            wordlist_size=args.wordlist,
            active_threads=args.threads,
            resolve_dns=args.resolve or args.only_resolved or args.tls_san or args.ptr_sweep,
            selected_resolver=args.resolver,
            audit_cnames=args.cname,
            probe_http=args.probe,
            ip_intel=args.ip_intel or args.verify_origin,
            mine_archives=args.archive,
            run_permutations=args.permute,
            tls_san=args.tls_san,
            wildcard=args.wildcard,
            verify_origin=args.verify_origin,
            ptr_sweep=args.ptr_sweep,
            run_nested=args.nested,
            shodan_free=not args.no_shodan_free,
            silent=args.silent,
            verbose=args.verbose,
        )

        # Output subdomains to stdout
        results = scan_data.get('results', [])
        if args.only_resolved:
            results = [r for r in results if r.get('dns_status') == 'resolved']

        for item in results:
            print(item['subdomain'])
            sys.stdout.flush()

        # Write requested output files
        if args.output or args.json or args.csv:
            write_outputs(
                scan_data=scan_data,
                txt_path=args.output,
                json_path=args.json,
                csv_path=args.csv,
                only_resolved=args.only_resolved
            )
            if not args.silent:
                if args.output:
                    log_success(f"Plaintext results exported to: {args.output}", args.silent)
                if args.json:
                    log_success(f"JSON results exported to: {args.json}", args.silent)
                if args.csv:
                    log_success(f"CSV results exported to: {args.csv}", args.silent)

        if not args.silent:
            display_terminal_summary(scan_data, only_resolved=args.only_resolved)


if __name__ == "__main__":
    main()
