"""
SubZero - Fast OSINT & Active DNS Reconnaissance Engine
Developed by: Gulam
Version: 2.2.0
"""
__author__ = "Gulam"
__version__ = "2.2.0"

import atexit
import copy
import csv
import io
import json
import os
import sys
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from flask import Flask, jsonify, render_template, request, Response, send_file
from enumerator.providers import DEFAULT_PROVIDER_ORDER, DEFAULT_PASSIVE_PROVIDERS, TOOL_ALIASES, PROVIDERS
from enumerator.normalizer import normalize_subdomains, valid_domain, clean
from enumerator.active_scanner import dns_brute_force
from enumerator.history_store import save_scan_history, get_recent_scans, get_domain_scans, compute_diff
from enumerator.http_prober import probe_hosts
from enumerator.dns_resolver import check_domain_multi_resolver
from enumerator.ip_intel import classify_ips
from enumerator.tls_scraper import scrape_tls_sans
from enumerator.wildcard_detector import detect_wildcard_dns, is_wildcard_false_positive
from enumerator.origin_verifier import verify_origin_candidates
from enumerator.ptr_sweeper import sweep_ips_for_ptrs

app = Flask(__name__)

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Global Thread Pool Executors
SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=2)
BATCH_EXECUTOR = ThreadPoolExecutor(max_workers=2)
JOBS = {}
JOBS_LOCK = threading.RLock()
CACHE = {}
CACHE_TTL_SECONDS = 600
MAX_JOB_AGE_SECONDS = 1800  # 30 minutes


def _cleanup_old_jobs():
    """Periodically remove completed/cancelled jobs older than MAX_JOB_AGE_SECONDS
    and expired cache entries. Runs every 5 minutes as a daemon thread."""
    while True:
        time.sleep(300)
        now = time.time()
        with JOBS_LOCK:
            to_delete = [
                jid for jid, job in JOBS.items()
                if job['status'] in ('completed', 'cancelled')
                and now - job.get('created_at', now) > MAX_JOB_AGE_SECONDS
            ]
            for jid in to_delete:
                del JOBS[jid]
            expired_keys = [k for k, v in CACHE.items() if now - v[0] > CACHE_TTL_SECONDS]
            for k in expired_keys:
                del CACHE[k]

threading.Thread(target=_cleanup_old_jobs, daemon=True, name='job-cleanup').start()


def _shutdown_executors():
    """Gracefully shutdown thread pool executors on process exit."""
    try:
        SCAN_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    try:
        BATCH_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass

atexit.register(_shutdown_executors)


def _add_log(job, msg):
    ts = time.strftime('%H:%M:%S')
    entry = f'[{ts}] {msg}'
    print(entry, flush=True)
    with JOBS_LOCK:
        if 'logs' not in job:
            job['logs'] = []
        job['logs'].append(entry)
        job['total_log_count'] = job.get('total_log_count', 0) + 1
        if len(job['logs']) > 10000:
            job['logs'] = job['logs'][-5000:]


def _job_view(job, include_results=True, since=0):
    all_logs = job.get('logs', [])
    data = {
        'id': job['id'], 'domain': job['domain'], 'status': job['status'],
        'developed_by': 'Gulam',
        'progress': job['progress'], 'sources': job['sources'], 'errors': job['errors'],
        'dns_validation': job['dns_validation'], 'active_dns': job.get('active_dns', False),
        'selected_resolver': job.get('selected_resolver', 'all'),
        'cached': job['cached'],
        'main_domain': job.get('main_domain') or {
            'domain': job['domain'],
            'subdomain': job['domain'],
            'dns': 'not-checked',
            'dns_ips': [],
            'waf_provider': 'Direct Server'
        },
        'logs': all_logs[since:] if since < len(all_logs) else [],
        'total_logs': job.get('total_log_count', len(all_logs)),
        'wildcard_dns': job.get('wildcard_dns'),
    }
    if include_results and job['status'] == 'completed':
        data['results'] = job['results']
    return data


def _enrich_subdomain_record(item: Dict[str, Any], dns_res: Dict[str, Any], wc_info: Dict[str, Any]) -> None:
    """Enriches a subdomain result item with DNS resolution and IP intelligence data."""
    item['dns'] = dns_res.get('status', 'not-checked')
    item['dns_resolver'] = dns_res.get('resolver', '')
    item['dns_summary'] = dns_res.get('summary', '')
    ips = dns_res.get('ips', [])
    cname = dns_res.get('cname', '')
    item['dns_ips'] = ips
    item['cname'] = cname
    item['is_wildcard_catchall'] = is_wildcard_false_positive(ips, cname, wc_info)
    if ips or cname:
        intel = classify_ips(ips, cname=cname)
        item['ip_intel'] = intel
        item['primary_ip'] = intel.get('primary_ip', '')
        item['waf_provider'] = intel.get('waf_provider', 'Direct Server')
        item['is_origin'] = intel.get('is_origin', True)
        item['is_cdn'] = intel.get('is_cdn', False)
        item['country_name'] = intel.get('country_name', 'Global')
        item['country_code'] = intel.get('country_code', '')
        item['country_flag'] = intel.get('country_flag', '🌐')


def _resolve_and_enrich_hosts(
    hosts: List[str],
    source_tag: str,
    selected_res: str,
    wc_info: Dict[str, Any],
    found_by: Dict[str, Set[str]],
    results: List[Dict[str, Any]],
    job: Dict[str, Any],
) -> None:
    """Concurrently resolves newly discovered hosts (e.g. from TLS-SAN or PTR sweeps) and enriches results."""
    _add_log(job, f"[{source_tag.upper()}] Verifying DNS resolution for {len(hosts)} new host(s)...")
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(hosts)))) as pool:
        futures = {pool.submit(check_domain_multi_resolver, s, selected_res): s for s in hosts}
        for future in as_completed(futures):
            s = futures[future]
            found_by.setdefault(s, set()).add(source_tag)
            item = {
                'subdomain': s,
                'sources': [source_tag],
                'confidence': 'single-source',
                'dns': 'not-checked',
            }
            try:
                dns_res = future.result()
                _enrich_subdomain_record(item, dns_res, wc_info)
            except Exception:
                item['dns'] = 'not-checked'
            results.append(item)


def _run_scan(job_id, selected):
    with JOBS_LOCK:
        job = JOBS[job_id]
        if job['cancelled']:
            return
        active_dns = job.get('active_dns', False)
        total_sources = len(selected) + (1 if active_dns else 0)
        job.update(status='running', progress=f'Querying {total_sources} source(s)')

    _add_log(job, f"[*] SubZero v2.2 • Developed by Gulam Khan")
    _add_log(job, f"[*] Starting reconnaissance job for: {job['domain']}")
    _add_log(job, f"[*] Selected engines: {', '.join(selected + (['active-dns'] if active_dns else []))}")

    def _execute_provider(name):
        _add_log(job, f"[{name}] Starting query worker...")
        t0 = time.time()
        try:
            values, err, cnt = PROVIDERS[name](job['domain'])
            dur = round(time.time() - t0, 2)
            if err:
                _add_log(job, f"[{name}] Finished ({dur}s) with notice: {err} | Found {cnt}")
            else:
                _add_log(job, f"[{name}] Finished successfully ({dur}s) | Found {cnt} subdomains")
            for val in values[:25]:
                _add_log(job, f"[{name}] Discovered -> {val}")
            if len(values) > 25:
                _add_log(job, f"[{name}] ... and {len(values) - 25} more subdomains")
            return values, err, cnt
        except Exception as exc:
            dur = round(time.time() - t0, 2)
            _add_log(job, f"[{name}] Exception after {dur}s: {exc}")
            return [], str(exc), 0

    found_by, counts, errors = {}, {}, []
    with ThreadPoolExecutor(max_workers=min(6, total_sources)) as pool:
        futures = {pool.submit(_execute_provider, name): name for name in selected}
        if active_dns:
            futures[pool.submit(
                dns_brute_force,
                job['domain'],
                None,
                500,
                job.get('active_wordlist', '5000'),
                lambda m: _add_log(job, f"{m}"),
                job.get('verbose_dns', True)
            )] = 'active-dns'
        for future in as_completed(futures):
            name = futures[future]
            try:
                values, error, count = future.result()
            except Exception as exc:
                values, error, count = [], f'{type(exc).__name__}: {exc}', 0
            counts[name] = count
            for host in normalize_subdomains(values, job['domain']):
                found_by.setdefault(host, set()).add(name)
            if error and not values:
                errors.append(f'{name}: {error}')
            with JOBS_LOCK:
                if job['cancelled']:
                    _add_log(job, "[!] Scan was cancelled by user.")
                    return
                job['progress'] = f'Finished {len(counts)}/{total_sources} sources'

    _add_log(job, f"[*] Merging & de-duplicating subdomains across all engines...")
    dns = {}
    selected_res = job.get('selected_resolver', 'all')

    # 1. Fast, guaranteed audit of Main Target Domain (Apex / Root Domain)
    main_target = clean(job['domain'])
    main_ips = []
    main_cname = ''
    main_summary = ''
    main_resolver = 'System DNS'

    try:
        import socket
        _, _, resolved_ips = socket.gethostbyname_ex(main_target)
        if resolved_ips:
            main_ips = list(dict.fromkeys(resolved_ips))
            main_summary = f'Live via System DNS -> {main_ips[0]}'
    except Exception:
        pass

    if job.get('dns_validation'):
        try:
            main_dns = check_domain_multi_resolver(main_target, selected_res)
            if main_dns.get('status') == 'resolved':
                main_ips = main_dns.get('ips', main_ips)
                main_cname = main_dns.get('cname', '')
                main_summary = main_dns.get('summary', main_summary)
                main_resolver = main_dns.get('resolver', main_resolver)
        except Exception:
            pass

    main_item = {
        'domain': main_target,
        'subdomain': main_target,
        'is_main_domain': True,
        'sources': ['Target Apex'],
        'confidence': 'main-target',
        'dns': 'resolved' if main_ips else 'unresolved',
        'dns_resolver': main_resolver,
        'dns_ips': main_ips,
        'cname': main_cname,
        'dns_summary': main_summary,
    }
    if main_ips or main_cname:
        main_intel = classify_ips(main_ips, cname=main_cname)
        main_item['ip_intel'] = main_intel
        main_item['primary_ip'] = main_intel.get('primary_ip', main_ips[0] if main_ips else '')
        main_item['waf_provider'] = main_intel.get('waf_provider', 'Direct Server')
        main_item['is_origin'] = main_intel.get('is_origin', True)
        main_item['is_cdn'] = main_intel.get('is_cdn', False)

    if main_item.get('primary_ip'):
        waf_label = main_item.get('waf_provider', 'Direct Server')
        _add_log(job, f"[*] [MAIN TARGET DOMAIN] {main_target} -> IP: {main_item['primary_ip']} | WAF Protection: {waf_label}")
    job['main_domain'] = main_item
    job['main_domain_intel'] = main_item

    # 2. Check for Wildcard DNS (*.target.com)
    wc_info = {'is_wildcard': False, 'wildcard_ips': [], 'wildcard_cnames': []}
    if job.get('dns_validation') or job.get('active_dns'):
        wc_info = detect_wildcard_dns(main_target, timeout=1.5)
        if wc_info.get('is_wildcard'):
            _add_log(job, f"[!] NOTICE: Wildcard DNS (*.{main_target}) is ACTIVE -> IPs: {', '.join(wc_info['wildcard_ips'])}. False-positive catchall filtering enabled.")
    job['wildcard_dns'] = wc_info

    # 3. Audit All Discovered Subdomains
    if job['dns_validation']:
        if selected_res and selected_res != 'all':
            _add_log(job, f"[*] Verifying DNS resolution specifically via {selected_res.upper()} for {len(found_by)} unique hosts...")
        else:
            _add_log(job, f"[*] Verifying DNS resolution across Tier-1 resolvers (Cloudflare, Google, OpenDNS, Quad9, AdGuard, Control D, Level3) for {len(found_by)} unique hosts...")
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(check_domain_multi_resolver, host, selected_res): host for host in found_by}
            for future in as_completed(futures):
                host = futures[future]
                res_info = future.result()
                dns[host] = res_info
                if res_info.get('status') == 'resolved':
                    resolver_label = res_info.get('resolver', 'Public DNS')
                    ip_part = f" -> {res_info['ips'][0]}" if res_info.get('ips') else ""
                    _add_log(job, f"[DNS-CHECK] {host} -> [RESOLVED] via {resolver_label}{ip_part}")
                else:
                    tested_cnt = res_info.get('tested_count', len(res_info.get('checked_resolvers', [])))
                    mode_label = f"via {selected_res.upper()}" if (selected_res and selected_res != 'all') else f"across all {tested_cnt} resolvers"
                    _add_log(job, f"[DNS-CHECK] {host} -> [DEAD] (Confirmed {mode_label})")

    results = []
    for host in sorted(found_by):
        if host == main_target:
            continue
        item = {
            'subdomain': host,
            'sources': sorted(found_by[host]),
            'confidence': 'high' if len(found_by[host]) > 1 else 'single-source',
            'dns': dns[host].get('status', 'unresolved') if host in dns else 'not-checked'
        }
        if host in dns:
            _enrich_subdomain_record(item, dns[host], wc_info)
        results.append(item)

    # 4. Advanced Discovery & Intelligence Post-Processing
    if job['dns_validation'] and results:
        # A. TLS SAN Certificate Scraping across resolved IPs
        all_resolved_ips = list(set(ip for r in results for ip in r.get('dns_ips', []) if ip))
        if all_resolved_ips:
            _add_log(job, f"[*] Probing TLS SAN certificates across {len(all_resolved_ips[:15])} live IP(s)...")
            try:
                tls_subs = scrape_tls_sans(all_resolved_ips[:15], main_target, max_workers=10, timeout=2.5)
                new_tls = [s for s in tls_subs if s not in found_by and s != main_target]
                if new_tls:
                    _add_log(job, f"[TLS-SAN] Discovered {len(new_tls)} hidden host(s) on direct SSL certificates: {', '.join(new_tls[:5])}")
                    _resolve_and_enrich_hosts(new_tls, 'tls-san', selected_res, wc_info, found_by, results, job)
            except Exception as e:
                _add_log(job, f"[!] TLS probe notice: {e}")

        # B. Confirmed True Origin IP (WAF Bypass) Active Verification
        candidate_origin_ips = list(set(r.get('primary_ip') for r in results if r.get('is_origin') and r.get('primary_ip')))
        if candidate_origin_ips:
            _add_log(job, f"[*] Actively verifying True Origin IPs against WAF bypass for {len(candidate_origin_ips[:10])} candidate(s)...")
            try:
                ver_map = verify_origin_candidates(candidate_origin_ips[:10], main_target, max_workers=8, timeout=3.0)
                for r in results:
                    pip = r.get('primary_ip')
                    if pip in ver_map and ver_map[pip].get('is_confirmed_origin'):
                        r['is_confirmed_origin'] = True
                        r['confirmed_origin'] = ver_map[pip]
                        _add_log(job, f"[ORIGIN-CONFIRMED] 🔥 {pip} ({r['subdomain']}) verified as True Origin Server (WAF Bypass)!")
            except Exception as e:
                _add_log(job, f"[!] Origin verification notice: {e}")

        # C. Reverse DNS (PTR) Subnet Sweep
        if candidate_origin_ips:
            _add_log(job, f"[*] Running reverse DNS (PTR) sweep on origin subnets...")
            try:
                ptr_res = sweep_ips_for_ptrs(candidate_origin_ips[:5], main_target, sweep_surrounding=True, window=3, max_workers=15)
                ptr_subs = ptr_res.get('discovered_subdomains', [])
                new_ptrs = [s for s in ptr_subs if s not in found_by and s != main_target]
                if new_ptrs:
                    _add_log(job, f"[PTR-SWEEP] Discovered {len(new_ptrs)} reverse DNS hostname(s): {', '.join(new_ptrs[:5])}")
                    _resolve_and_enrich_hosts(new_ptrs, 'ptr-sweep', selected_res, wc_info, found_by, results, job)
            except Exception as e:
                _add_log(job, f"[!] PTR sweep notice: {e}")

    with JOBS_LOCK:
        if job['cancelled']:
            return
        job.update(status='completed', progress='Completed', sources=counts, errors=errors, results=results)
        CACHE[job['cache_key']] = (time.time(), copy.deepcopy(results), counts.copy(), errors.copy(), copy.deepcopy(main_item))
        save_scan_history(job['id'], job['domain'], results, counts)
    _add_log(job, f"[SUCCESS] Scan completed! Found {len(results)} total unique subdomains.")


@app.get('/')
def index():
    return render_template('index.html')


@app.get('/api/info')
def api_info():
    """Returns project architecture and author metadata."""
    return jsonify({
        'name': 'SubZero',
        'version': '2.2.0',
        'author': 'Gulam Khan',
        'role': 'Founder & Lead Architect',
        'license': 'MIT',
        'repository': 'https://github.com/gulamkhan07/subdomain_finder_pro',
        'status': 'online',
        'description': 'Enterprise-Grade OSINT Reconnaissance, Multi-Resolver DNS Integrity, Permutations Engine, Wayback URL Miner & Cloud Asset Auditor.'
    })


@app.post('/api/scan')
def scan():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    if not valid_domain(domain):
        return jsonify(error='Enter a valid root domain, e.g. example.com'), 400

    requested = data.get('sources')
    if requested is None:
        requested = list(DEFAULT_PASSIVE_PROVIDERS)
    if isinstance(requested, str):
        requested = [requested]
    requested = [TOOL_ALIASES.get(s.strip().lower(), s.strip().lower()) for s in requested if isinstance(s, str)]

    exclude_list = data.get('exclude') or data.get('exclude_sources') or []
    if isinstance(exclude_list, str):
        exclude_list = [x.strip().lower() for x in exclude_list.replace(' ', ',').split(',') if x.strip()]
    exclude_set = {TOOL_ALIASES.get(x, x) for x in exclude_list if isinstance(x, str)}

    selected = [name for name in DEFAULT_PROVIDER_ORDER if name in requested and name not in exclude_set]
    active_dns = bool(data.get('active_dns'))
    active_wordlist = str(data.get('active_wordlist') or '5000').strip()
    verbose_dns = bool(data.get('verbose_dns', True))

    if not selected and not active_dns:
        return jsonify(error='Select at least one discovery source or enable active DNS brute-force.'), 400

    validate_dns = bool(data.get('validate_dns'))
    selected_resolver = str(data.get('dns_resolver') or data.get('selected_resolver') or 'all').strip().lower()
    cache_key = (domain, tuple(selected), validate_dns, active_dns, active_wordlist, selected_resolver)
    now = time.time()
    with JOBS_LOCK:
        job = {
            'id': uuid.uuid4().hex, 'domain': domain, 'status': 'queued', 'progress': 'Queued',
            'sources': {}, 'errors': [], 'results': [], 'dns_validation': validate_dns,
            'active_dns': active_dns, 'active_wordlist': active_wordlist, 'verbose_dns': verbose_dns,
            'selected_resolver': selected_resolver,
            'cancelled': False, 'cached': False, 'cache_key': cache_key, 'logs': [],
            'total_log_count': 0, 'created_at': time.time(),
            'main_domain': None,
        }
        cached = CACHE.get(cache_key)
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            cached_main = cached[4] if len(cached) > 4 else None
            job.update(status='completed', progress='Completed (cached)', results=copy.deepcopy(cached[1]),
                       sources=cached[2].copy(), errors=cached[3].copy(), cached=True,
                       main_domain=copy.deepcopy(cached_main))
        JOBS[job['id']] = job

    if job['status'] != 'completed':
        SCAN_EXECUTOR.submit(_run_scan, job['id'], selected)
    return jsonify(_job_view(job)), 202


@app.get('/api/scan/<job_id>')
def scan_status(job_id):
    since = request.args.get('since', 0, type=int)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify(error='Scan job not found.'), 404
        return jsonify(_job_view(job, since=since))


@app.post('/api/scan/<job_id>/cancel')
def cancel_scan(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify(error='Scan job not found.'), 404
        if job['status'] not in ('completed', 'cancelled'):
            job.update(cancelled=True, status='cancelled', progress='Cancellation requested.')
        return jsonify(_job_view(job))

def _completed_job(job_id):
    """Helper to retrieve a completed scan job by ID."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None, (jsonify(error='Scan job not found.'), 404)
        if job['status'] != 'completed':
            return None, (jsonify(error='Scan is not complete yet.'), 409)
        return job, None


@app.get('/api/results.txt')
def results_txt():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    raw = request.args.get('raw', '').lower() in ('1', 'true', 'yes')
    header = "" if raw else f"# SubZero • Developed by Gulam Khan\n# Target: {job['domain']} • Total Found: {len(job['results'])}\n\n"
    body = header + '\n'.join(row['subdomain'] for row in job['results'])
    return Response(body + ('\n' if body else ''), mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}_subdomains.txt'})

@app.get('/api/results/ips.txt')
def results_ips_txt():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    all_ips = set()
    for row in job.get('results', []):
        for ip in row.get('dns_ips', []):
            if ip and ip.strip():
                all_ips.add(ip.strip())
    sorted_ips = sorted(all_ips)
    raw = request.args.get('raw', '').lower() in ('1', 'true', 'yes')
    header = "" if raw else f"# SubZero • Developed by Gulam Khan\n# Target: {job['domain']} • Unique Resolved IPs: {len(sorted_ips)}\n\n"
    body = header + '\n'.join(sorted_ips)
    return Response(body + ('\n' if body else ''), mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}_unique_ips.txt'})

@app.get('/api/results.csv')
def results_csv():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    raw = request.args.get('raw', '').lower() in ('1', 'true', 'yes')
    out = io.StringIO(); w = csv.writer(out)
    if not raw:
        w.writerow(['# SubZero', 'Developed by Gulam Khan', f'Target: {job["domain"]}'])
    w.writerow(['subdomain', 'sources', 'confidence', 'dns', 'primary_ip', 'waf_provider', 'is_origin', 'dns_resolver', 'dns_ips'])
    w.writerows([[
        row['subdomain'],
        ', '.join(row['sources']),
        row['confidence'],
        row['dns'],
        row.get('primary_ip', ''),
        row.get('waf_provider', ''),
        'YES (Origin 🔥)' if row.get('is_origin') else ('NO (CDN/WAF)' if row.get('is_cdn') else 'Unknown'),
        row.get('dns_resolver', ''),
        ', '.join(row.get('dns_ips', []))
    ] for row in job['results']])
    return Response(out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}_subdomains.csv'})


@app.get('/api/results.json')
def results_json():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    return Response(json.dumps(_job_view(job), indent=2), mimetype='application/json')


@app.get('/api/results.html')
def results_html():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    results = job['results']
    resolved_count = sum(1 for r in results if r.get('dns') == 'resolved')
    high_conf_count = sum(1 for r in results if r.get('confidence') == 'high')
    try:
        rendered = render_template(
            'report_template.html',
            domain=job['domain'],
            main_domain=job.get('main_domain'),
            results=results,
            total_count=len(results),
            resolved_count=resolved_count,
            high_conf_count=high_conf_count,
            sources_count=len(job.get('sources') or {}),
            active_dns=job.get('active_dns', False),
            scan_date=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        )
    except Exception:
        # Graceful fallback if report_template.html is missing
        return jsonify(error='HTML report template not available. Use JSON or CSV export instead.'), 501
    return Response(
        rendered,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename={job["domain"]}_recon_report.html'}
    )


# =========================================================================
# SCAN HISTORY & DIFF CHANGE TRACKING
# =========================================================================

@app.get('/api/history')
def api_history():
    scans = get_recent_scans(limit=50)
    return jsonify(scans=scans, developed_by='Gulam')


@app.get('/api/history/<domain>')
def api_domain_history(domain):
    scans = get_domain_scans(domain)
    return jsonify(domain=domain, scans=scans, developed_by='Gulam')


@app.get('/api/history/diff')
def api_history_diff():
    old_id = request.args.get('old', '') or request.args.get('scan_a', '')
    new_id = request.args.get('new', '') or request.args.get('scan_b', '')
    if not old_id or not new_id:
        return jsonify(error='Specify both old and new scan IDs to compare.'), 400
    diff = compute_diff(old_id, new_id)
    return jsonify(diff)


# =========================================================================
# MULTI-DOMAIN BATCH QUEUE SCANNER
# =========================================================================

BATCH_JOBS = {}
BATCH_LOCK = threading.RLock()


def _run_batch(batch_id, domains, config):
    for idx, domain in enumerate(domains):
        with BATCH_LOCK:
            batch = BATCH_JOBS.get(batch_id)
            if not batch or batch['cancelled']:
                return
            batch['current_target'] = domain
            batch['current_index'] = idx + 1
            batch['progress'] = f'Scanning {idx + 1}/{len(domains)}: {domain}'

        sub_job_id = uuid.uuid4().hex
        selected = config.get('sources')
        if not selected:
            selected = list(DEFAULT_PROVIDER_ORDER)
        active_dns = bool(config.get('active_dns', False))
        active_wordlist = str(config.get('active_wordlist', '5000'))
        validate_dns = bool(config.get('validate_dns', False))
        selected_resolver = str(config.get('dns_resolver') or config.get('selected_resolver') or 'all').strip().lower()

        with JOBS_LOCK:
            job = {
                'id': sub_job_id, 'domain': domain, 'status': 'running',
                'progress': 'Batch scanning...', 'sources': {}, 'errors': [], 'results': [],
                'dns_validation': validate_dns, 'active_dns': active_dns,
                'active_wordlist': active_wordlist, 'verbose_dns': False,
                'selected_resolver': selected_resolver,
                'cancelled': False, 'cached': False,
                'cache_key': (domain, tuple(selected), validate_dns, active_dns, active_wordlist, selected_resolver),
                'logs': [], 'total_log_count': 0,
            }
            JOBS[sub_job_id] = job

        _run_scan(sub_job_id, selected)

        with JOBS_LOCK:
            fin = JOBS.get(sub_job_id)
            cnt = len(fin.get('results', [])) if fin else 0

        with BATCH_LOCK:
            if batch_id in BATCH_JOBS:
                BATCH_JOBS[batch_id]['targets'][domain] = {
                    'job_id': sub_job_id,
                    'status': 'completed',
                    'count': cnt
                }

    with BATCH_LOCK:
        if batch_id in BATCH_JOBS:
            BATCH_JOBS[batch_id]['status'] = 'completed'
            BATCH_JOBS[batch_id]['progress'] = f'All {len(domains)} targets scanned successfully.'


@app.post('/api/batch/start')
def batch_start():
    data = request.get_json(silent=True) or {}
    raw_domains = data.get('domains') or []
    if isinstance(raw_domains, str):
        raw_domains = [d.strip() for d in raw_domains.replace(',', '\n').splitlines() if d.strip()]

    valid_targets = []
    for d in raw_domains:
        d = d.strip().lower().rstrip('.')
        if valid_domain(d) and d not in valid_targets:
            valid_targets.append(d)

    if not valid_targets:
        return jsonify(error='Provide at least one valid root domain (e.g. example.com).'), 400
    if len(valid_targets) > 25:
        return jsonify(error='Batch limit is 25 domains per run.'), 400

    batch_id = uuid.uuid4().hex
    batch = {
        'id': batch_id,
        'batch_id': batch_id,
        'domains': valid_targets,
        'total_targets': len(valid_targets),
        'current_index': 0,
        'current_target': None,
        'status': 'queued',
        'progress': f'Queued {len(valid_targets)} targets',
        'cancelled': False,
        'targets': {},
        'developed_by': 'Gulam'
    }
    with BATCH_LOCK:
        BATCH_JOBS[batch_id] = batch

    BATCH_EXECUTOR.submit(_run_batch, batch_id, valid_targets, data)
    return jsonify(batch), 202


@app.get('/api/batch/<batch_id>')
def batch_status(batch_id):
    with BATCH_LOCK:
        batch = BATCH_JOBS.get(batch_id)
        if not batch:
            return jsonify(error='Batch job not found.'), 404

        total_found = sum(t.get('count', 0) for t in batch.get('targets', {}).values())
        domains_list = []
        for d in batch['domains']:
            tgt = batch.get('targets', {}).get(d)
            if tgt:
                domains_list.append({
                    'domain': d,
                    'status': tgt.get('status', 'completed'),
                    'subdomain_count': tgt.get('count', 0),
                    'job_id': tgt.get('job_id')
                })
            elif d == batch.get('current_target'):
                domains_list.append({
                    'domain': d,
                    'status': 'scanning',
                    'subdomain_count': 0,
                    'job_id': None
                })
            else:
                domains_list.append({
                    'domain': d,
                    'status': 'queued',
                    'subdomain_count': 0,
                    'job_id': None
                })

        resp = copy.deepcopy(batch)
        resp['batch_id'] = batch_id
        resp['total_domains'] = len(batch['domains'])
        resp['completed_count'] = len(batch.get('targets', {}))
        resp['total_subdomains_found'] = total_found
        resp['domains'] = domains_list
        return jsonify(resp)


@app.post('/api/batch/<batch_id>/cancel')
def batch_cancel(batch_id):
    with BATCH_LOCK:
        batch = BATCH_JOBS.get(batch_id)
        if not batch:
            return jsonify(error='Batch job not found.'), 404
        batch['cancelled'] = True
        batch['status'] = 'cancelled'
    # Also cancel the currently running sub-scan job (if any)
    with BATCH_LOCK:
        current_target = batch.get('current_target')
    if current_target:
        with JOBS_LOCK:
            for jid, job in JOBS.items():
                if job.get('domain') == current_target and job.get('status') not in ('completed', 'cancelled'):
                    job.update(cancelled=True, status='cancelled', progress='Cancelled via batch cancel.')
                    break
    with BATCH_LOCK:
        return jsonify(batch)


# =========================================================================
# ON-DEMAND SEPARATE LIVE HTTP PROBER
# =========================================================================

@app.post('/api/probe')
def api_probe():
    data = request.get_json(silent=True) or {}
    hosts = data.get('hosts') or data.get('subdomains') or []
    if isinstance(hosts, str):
        hosts = [h.strip() for h in hosts.replace(',', '\n').splitlines() if h.strip()]
    hosts = [h.strip().lower() for h in hosts if h.strip()][:300]
    if not hosts:
        return jsonify(error='Provide at least one subdomain to probe.'), 400

    timeout = float(data.get('timeout', 4.0))
    concurrency = int(data.get('concurrency', 30))
    specific_resolver = data.get('dns_resolver') or data.get('selected_resolver')
    probed = probe_hosts(hosts, max_workers=concurrency, timeout=timeout, specific_resolver=specific_resolver)
    alive_count = sum(1 for p in probed if p.get('alive'))
    return jsonify({
        'developed_by': 'Gulam',
        'total_probed': len(probed),
        'alive_count': alive_count,
        'results': probed
    })


# =========================================================================
# DEFENSIVE DNS ASSET INTEGRITY & DANGLING CNAME AUDITOR
# =========================================================================

from enumerator.cname_auditor import audit_hosts

@app.post('/api/audit/cname')
def api_audit_cname():
    data = request.get_json(silent=True) or {}
    hosts = data.get('hosts') or data.get('subdomains') or []
    if isinstance(hosts, str):
        hosts = [h.strip() for h in hosts.replace(',', '\n').splitlines() if h.strip()]
    hosts = [h.strip().lower() for h in hosts if h.strip()][:250]
    if not hosts:
        return jsonify(error='Provide at least one subdomain to audit.'), 400

    results = audit_hosts(hosts, max_workers=20)
    dangling_count = sum(1 for r in results if r.get('status') == 'dangling')
    cname_count = sum(1 for r in results if r.get('status') in ('dangling', 'info'))

    return jsonify({
        'developed_by': 'Gulam',
        'total_audited': len(results),
        'dangling_count': dangling_count,
        'cname_count': cname_count,
        'results': results
    })


# =========================================================================
# SUBDOMAIN PERMUTATION & MUTATION ENGINE (OPTION 1)
# =========================================================================

from enumerator.permutation_engine import generate_permutations, scan_permutations

@app.post('/api/permutations/generate')
def api_permutations_generate():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain (e.g. example.com).'), 400

    seeds = data.get('seeds') or []
    if isinstance(seeds, str):
        seeds = [s.strip() for s in seeds.replace(',', '\n').splitlines() if s.strip()]
    custom_words = data.get('custom_words') or []
    if isinstance(custom_words, str):
        custom_words = [w.strip() for w in custom_words.replace(',', '\n').splitlines() if w.strip()]
    limit = min(int(data.get('limit', 300)), 1000)

    candidates = generate_permutations(domain, seeds, custom_words=custom_words, max_candidates=limit)
    return jsonify({
        'developed_by': 'Gulam',
        'domain': domain,
        'total_candidates': len(candidates),
        'candidates': candidates
    })


@app.post('/api/permutations/scan')
def api_permutations_scan():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain (e.g. example.com).'), 400

    seeds = data.get('seeds') or []
    if isinstance(seeds, str):
        seeds = [s.strip() for s in seeds.replace(',', '\n').splitlines() if s.strip()]
    custom_words = data.get('custom_words') or []
    if isinstance(custom_words, str):
        custom_words = [w.strip() for w in custom_words.replace(',', '\n').splitlines() if w.strip()]
    limit = min(int(data.get('limit', 250)), 500)
    concurrency = min(int(data.get('concurrency', 25)), 50)
    resolver = data.get('dns_resolver') or data.get('selected_resolver')

    res = scan_permutations(domain, seeds, custom_words=custom_words, max_candidates=limit, max_workers=concurrency, specific_resolver=resolver)
    return jsonify(res)


# =========================================================================
# HISTORICAL ARCHIVE & WAYBACK URL MINER (OPTION 2)
# =========================================================================

from enumerator.archive_miner import mine_archive_urls

@app.post('/api/archive/mine')
def api_archive_mine():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain (e.g. example.com).'), 400

    limit = min(int(data.get('limit', 2500)), 5000)
    timeout = min(int(data.get('timeout', 10)), 20)

    res = mine_archive_urls(domain, limit=limit, timeout=timeout)
    return jsonify(res)


# =========================================================================
# INTERACTIVE ATTACK SURFACE GRAPH DATA GENERATOR
# =========================================================================

def _categorize_subdomain(sub: str, root: str) -> str:
    prefix = sub[:-len(root)].rstrip('.') if sub.endswith(root) else sub
    prefix = prefix.lower()
    if any(k in prefix for k in ['api', 'v1', 'v2', 'v3', 'grpc', 'graphql', 'rest', 'gw', 'gateway', 'ws']):
        return 'api'
    if any(k in prefix for k in ['dev', 'stage', 'staging', 'test', 'qa', 'beta', 'demo', 'sandbox', 'preview']):
        return 'dev'
    if any(k in prefix for k in ['auth', 'login', 'sso', 'admin', 'vpn', 'corp', 'internal', 'mail', 'smtp', 'secure']):
        return 'auth'
    if any(k in prefix for k in ['www', 'app', 'portal', 'web', 'dashboard', 'shop', 'blog', 'store', 'site']):
        return 'web'
    return 'infra'


@app.post('/api/graph/data')
def api_graph_data():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or 'target.com').strip().lower()
    subdomains = data.get('subdomains') or []
    if isinstance(subdomains, str):
        subdomains = [s.strip() for s in subdomains.replace(',', '\n').splitlines() if s.strip()]

    unique_subs = sorted(set(s.strip().lower() for s in subdomains if s.strip()))[:300]

    nodes = [
        {
            'id': domain,
            'name': domain,
            'full_name': domain,
            'category': 'root',
            'type': 'root',
            'val': 24,
            'color': '#00f2fe'
        }
    ]
    links = []

    category_counts = {'api': 0, 'dev': 0, 'auth': 0, 'web': 0, 'infra': 0}
    category_colors = {
        'api': '#38bdf8',
        'dev': '#c084fc',
        'auth': '#fbbf24',
        'web': '#34d399',
        'infra': '#94a3b8'
    }

    for sub in unique_subs:
        if sub == domain:
            continue
        cat = _categorize_subdomain(sub, domain)
        category_counts[cat] = category_counts.get(cat, 0) + 1

        prefix = sub[:-len(domain)].rstrip('.') if sub.endswith(domain) else sub
        display_label = prefix if prefix else sub

        nodes.append({
            'id': sub,
            'name': display_label,
            'full_name': sub,
            'category': cat,
            'val': 9,
            'color': category_colors.get(cat, '#94a3b8')
        })
        links.append({
            'source': domain,
            'target': sub
        })

    return jsonify({
        'developed_by': 'Gulam',
        'domain': domain,
        'total_nodes': len(nodes),
        'category_counts': category_counts,
        'nodes': nodes,
        'links': links
    })


# _completed_job() is now defined earlier (before /api/results.txt) for clarity


def _generate_project_zip(output_path: Path):
    project_dir = Path(__file__).resolve().parent
    exclude_dirs = {'__pycache__', '.git', '.runtime', '.pytest_cache', '.venv'}
    exclude_extensions = {'.pyc', '.pyo', '.zip'}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_zip = output_path.with_suffix('.tmp')
    with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                if any(f.endswith(ext) for ext in exclude_extensions):
                    continue
                file_path = Path(root) / f
                arcname = file_path.relative_to(project_dir.parent)
                zf.write(file_path, arcname)
    if output_path.exists():
        try:
            output_path.unlink()
        except Exception:
            pass
    temp_zip.replace(output_path)


def _is_zip_stale(zip_path: Path, project_dir: Path) -> bool:
    """Checks whether the cached zip is missing or older than any source file in the project."""
    if not zip_path.is_file():
        return True
    try:
        zip_mtime = zip_path.stat().st_mtime
        exclude_dirs = {'__pycache__', '.git', '.runtime', '.pytest_cache', '.venv'}
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                if f.endswith(('.py', '.html', '.css', '.js', '.md', '.bat', '.sh', '.txt')):
                    if (Path(root) / f).stat().st_mtime > zip_mtime:
                        return True
        return False
    except Exception:
        return True


@app.get('/api/download/zip')
def download_project_zip():
    """Provides instant one-click download of the complete project as a zip file with latest changes."""
    project_dir = Path(__file__).resolve().parent
    zip_path = project_dir.parent / 'SubZero_Pro_by_Gulam_Khan.zip'
    if _is_zip_stale(zip_path, project_dir):
        _generate_project_zip(zip_path)
    return send_file(
        str(zip_path),
        mimetype='application/zip',
        as_attachment=True,
        download_name='SubZero_Pro_by_Gulam_Khan.zip'
    )


if __name__ == '__main__':
    # Auto-check and download external tools (Subfinder, Amass, SecLists wordlists) if missing
    def _auto_check_tools():
        try:
            from install_tools import install, BIN_DIR, PROJECT_ROOT
            ext = '.exe' if sys.platform.startswith('win') else ''
            subfinder_bin = os.path.join(BIN_DIR, f'subfinder{ext}')
            wordlist_5k = os.path.join(PROJECT_ROOT, 'wordlists', 'subdomains_5000.txt')
            if not os.path.isfile(subfinder_bin) or not os.path.isfile(wordlist_5k):
                print("[*] First-time setup detected: Downloading discovery binaries & wordlists...")
                install(verbose=True)
        except Exception:
            pass

    threading.Thread(target=_auto_check_tools, daemon=True).start()

    print("[*] SubZero v2.2 running on http://127.0.0.1:5000 (Decoupled Zero-Lag Engine)")
    app.run(host='127.0.0.1', port=5000, debug=False)

