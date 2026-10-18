"""
SubZero Results Export Blueprint.
Handles TXT, CSV, JSON, HTML report, and 1:1 Shodan schema exports.
"""
__author__ = "SubZero Community"

import csv
import io
import json
import time
from typing import Any, Dict

from flask import Blueprint, jsonify, render_template, request, Response

from services.job_manager import JOBS, JOBS_LOCK, _completed_job, _job_view
from services.filter_service import _filter_results
from enumerator.shodan_exporter import export_shodan_format
from enumerator.ip_intel import classify_ips
from enumerator.history_store import _get_conn

export_bp = Blueprint('export', __name__)


@export_bp.get('/api/results.txt')
def results_txt():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    status_filter = (request.args.get('status') or request.args.get('filter') or 'all').strip().lower()
    query = request.args.get('q', '').strip()
    results = _filter_results(job.get('results', []), status_filter, query)
    raw = request.args.get('raw', '').lower() in ('1', 'true', 'yes')
    filter_label = f" ({status_filter.upper()})" if status_filter in ('live', 'dead') else ""
    header = "" if raw else f"# SubZero • Target: {job['domain']} • Total Found{filter_label}: {len(results)}\n\n"
    body = header + '\n'.join(row['subdomain'] for row in results)
    filename_suffix = f"_{status_filter}" if status_filter in ('live', 'dead') else ""
    return Response(body + ('\n' if body else ''), mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}{filename_suffix}_subdomains.txt'})


@export_bp.get('/api/results/ips.txt')
def results_ips_txt():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    status_filter = (request.args.get('status') or request.args.get('filter') or 'all').strip().lower()
    query = request.args.get('q', '').strip()
    results = _filter_results(job.get('results', []), status_filter, query)
    all_ips = set()
    for row in results:
        for ip in row.get('dns_ips', []):
            if ip and ip.strip():
                all_ips.add(ip.strip())
    sorted_ips = sorted(all_ips)
    raw = request.args.get('raw', '').lower() in ('1', 'true', 'yes')
    filter_label = f" ({status_filter.upper()})" if status_filter in ('live', 'dead') else ""
    header = "" if raw else f"# SubZero • Target: {job['domain']} • Unique Resolved IPs{filter_label}: {len(sorted_ips)}\n\n"
    body = header + '\n'.join(sorted_ips)
    filename_suffix = f"_{status_filter}" if status_filter in ('live', 'dead') else ""
    return Response(body + ('\n' if body else ''), mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}{filename_suffix}_unique_ips.txt'})


@export_bp.get('/api/results.csv')
def results_csv():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    status_filter = (request.args.get('status') or request.args.get('filter') or 'all').strip().lower()
    query = request.args.get('q', '').strip()
    results = _filter_results(job.get('results', []), status_filter, query)
    raw = request.args.get('raw', '').lower() in ('1', 'true', 'yes')
    out = io.StringIO()
    w = csv.writer(out)
    if not raw:
        filter_note = f' [Filter: {status_filter.upper()}]' if status_filter in ('live', 'dead') else ''
        w.writerow(['# SubZero', f'Target: {job["domain"]}{filter_note}'])
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
    ] for row in results])
    filename_suffix = f"_{status_filter}" if status_filter in ('live', 'dead') else ""
    return Response(out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}{filename_suffix}_subdomains.csv'})


@export_bp.get('/api/results.json')
def results_json():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    status_filter = (request.args.get('status') or request.args.get('filter') or 'all').strip().lower()
    query = request.args.get('q', '').strip()
    results = _filter_results(job.get('results', []), status_filter, query)
    job_view = _job_view(job)
    job_view['results'] = results
    job_view['total_subdomains'] = len(results)
    if status_filter in ('live', 'dead'):
        job_view['status_filter'] = status_filter
    filename_suffix = f"_{status_filter}" if status_filter in ('live', 'dead') else ""
    return Response(json.dumps(job_view, indent=2), mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename={job["domain"]}{filename_suffix}_subdomains.json'})


@export_bp.get('/api/results/shodan.json')
def results_shodan_json():
    """Exports scan results formatted in exact 1:1 Shodan Domain API JSON schema."""
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    status_filter = (request.args.get('status') or request.args.get('filter') or 'all').strip().lower()
    query = request.args.get('q', '').strip()
    results = _filter_results(job.get('results', []), status_filter, query)

    shodan_data = export_shodan_format(
        job['domain'],
        results,
        apex_records=job.get('apex_records')
    )
    filename_suffix = f"_{status_filter}" if status_filter in ('live', 'dead') else ""
    return Response(
        json.dumps(shodan_data, indent=4),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={job["domain"]}{filename_suffix}_shodan.json'}
    )


@export_bp.get('/api/shodan/domain')
def api_shodan_domain():
    """
    Shodan-compatible domain reconnaissance endpoint.
    Accepts ?job=<job_id> or ?domain=<domain_name>.
    Returns 1:1 identical Shodan Domain API response.
    """
    job_id = request.args.get('job', '').strip()
    domain = request.args.get('domain', '').strip().lower()

    if job_id:
        job, error = _completed_job(job_id)
        if error:
            return error
        shodan_data = export_shodan_format(
            job['domain'],
            job.get('results', []),
            apex_records=job.get('apex_records')
        )
        return jsonify(shodan_data)

    if not domain:
        return jsonify(error="Query parameter 'domain' or 'job' is required"), 400

    with JOBS_LOCK:
        matched_job = None
        for j in reversed(list(JOBS.values())):
            if j.get('domain') == domain and j.get('status') == 'completed':
                matched_job = j
                break

    if matched_job:
        shodan_data = export_shodan_format(
            matched_job['domain'],
            matched_job.get('results', []),
            apex_records=matched_job.get('apex_records')
        )
        return jsonify(shodan_data)

    shodan_data = export_shodan_format(domain, results=[], include_live_apex=True)
    return jsonify(shodan_data)


@export_bp.get('/dns/domain/<domain>')
@export_bp.get('/api/dns/domain/<domain>')
def shodan_domain_direct(domain: str):
    """
    1:1 drop-in replacement endpoint for Shodan's Domain API:
    https://api.shodan.io/dns/domain/{domain}
    Allows client backends to point directly to SubZero without URL rewriting.
    """
    clean_domain = (domain or '').strip().lower().rstrip('.')
    if not clean_domain:
        return jsonify(error="Domain is required"), 400

    # 1. Check in-memory completed jobs
    with JOBS_LOCK:
        matched_job = None
        for j in reversed(list(JOBS.values())):
            if j.get('domain') == clean_domain and j.get('status') == 'completed':
                matched_job = j
                break

    if matched_job:
        shodan_data = export_shodan_format(
            matched_job['domain'],
            matched_job.get('results', []),
            apex_records=matched_job.get('apex_records')
        )
        return jsonify(shodan_data)

    # 2. Check persistent scan history database
    try:
        with _get_conn() as conn:
            row = conn.execute(
                'SELECT id, domain, subdomains_json FROM scan_history WHERE domain = ? ORDER BY timestamp DESC LIMIT 1',
                (clean_domain,)
            ).fetchone()
            if row:
                subs = json.loads(row['subdomains_json'] or '[]')
                results = [{'subdomain': s} for s in subs]
                shodan_data = export_shodan_format(clean_domain, results=results, include_live_apex=True)
                return jsonify(shodan_data)
    except Exception:
        pass

    # 3. Live authoritative apex DNS fallback
    shodan_data = export_shodan_format(clean_domain, results=[], include_live_apex=True)
    return jsonify(shodan_data)


@export_bp.get('/api/results.html')
def results_html():
    job, error = _completed_job(request.args.get('job', ''))
    if error:
        return error
    status_filter = (request.args.get('status') or request.args.get('filter') or 'all').strip().lower()
    query = request.args.get('q', '').strip()
    results = _filter_results(job.get('results', []), status_filter, query)
    resolved_count = sum(1 for r in results if r.get('dns') == 'resolved')
    high_conf_count = sum(1 for r in results if r.get('confidence') == 'high')

    # Ensure WAF and origin classifications are populated for all records
    for r in results:
        ips = r.get('dns_ips') or ([r['primary_ip']] if r.get('primary_ip') else [])
        if ips and ('waf_provider' not in r or not r.get('waf_provider')):
            intel = classify_ips(ips, cname=r.get('cname', ''))
            r['waf_provider'] = intel.get('waf_provider', '')
            r['is_cdn'] = intel.get('is_cdn', False)
            r['is_origin'] = intel.get('is_origin', False)
            r['badge_type'] = intel.get('badge_type', '')

    main_domain = job.get('main_domain')
    if main_domain and (main_domain.get('primary_ip') or main_domain.get('dns_ips')) and not main_domain.get('waf_provider'):
        m_ips = [main_domain['primary_ip']] if main_domain.get('primary_ip') else main_domain.get('dns_ips', [])
        m_intel = classify_ips(m_ips, cname=main_domain.get('cname', ''))
        main_domain['waf_provider'] = m_intel.get('waf_provider', '')
        main_domain['is_cdn'] = m_intel.get('is_cdn', False)
        main_domain['is_origin'] = m_intel.get('is_origin', False)

    try:
        rendered = render_template(
            'report_template.html',
            domain=job['domain'],
            main_domain=main_domain,
            results=results,
            total_count=len(results),
            resolved_count=resolved_count,
            high_conf_count=high_conf_count,
            sources_count=len(job.get('sources') or {}),
            active_dns=job.get('active_dns', False),
            scan_date=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        )
    except Exception:
        return jsonify(error='HTML report template not available. Use JSON or CSV export instead.'), 501
    filename_suffix = f"_{status_filter}" if status_filter in ('live', 'dead') else ""
    return Response(
        rendered,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename={job["domain"]}{filename_suffix}_recon_report.html'}
    )
