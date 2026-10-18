"""
SubZero Scan & Core API Routes Blueprint.
Handles index UI serving, info endpoint, scan initiation, polling status, and job cancellation.
"""
__author__ = "SubZero Community"

import copy
import sys
import time
from typing import List
import uuid

from flask import Blueprint, jsonify, render_template, request

from services.job_manager import (
    JOBS,
    JOBS_LOCK,
    CACHE,
    CACHE_TTL_SECONDS,
    _ensure_cleanup_thread,
    _job_view,
    _completed_job,
)
from services.scan_engine import SCAN_EXECUTOR, _run_scan
from enumerator.normalizer import valid_domain
from enumerator.providers import (
    DEFAULT_PROVIDER_ORDER,
    DEFAULT_PASSIVE_PROVIDERS,
    TOOL_ALIASES,
)

scan_bp = Blueprint('scan', __name__)


@scan_bp.get('/')
def index():
    return render_template('index.html')


@scan_bp.get('/api/info')
def api_info():
    """Returns project architecture and author metadata."""
    return jsonify({
        'name': 'SubZero',
        'version': '2.2.0',
        'author': 'SubZero Community',
        'role': 'Open Source Community',
        'license': 'MIT',
        'repository': 'https://github.com/gulamkhan07/subdomain_finder_pro',
        'status': 'online',
        'description': 'Enterprise-Grade OSINT Reconnaissance, Multi-Resolver DNS Integrity, Permutations Engine, Wayback URL Miner & Cloud Asset Auditor.'
    })


@scan_bp.post('/api/scan')
def scan():
    _ensure_cleanup_thread()
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    if not valid_domain(domain):
        return jsonify(error='Enter a valid root domain, e.g. example.com'), 400

    provider_order = getattr(sys.modules.get('app'), 'DEFAULT_PROVIDER_ORDER', DEFAULT_PROVIDER_ORDER)
    passive_providers = getattr(sys.modules.get('app'), 'DEFAULT_PASSIVE_PROVIDERS', DEFAULT_PASSIVE_PROVIDERS)
    tool_aliases = getattr(sys.modules.get('app'), 'TOOL_ALIASES', TOOL_ALIASES)

    requested = data.get('sources')
    if requested is None:
        requested = list(passive_providers)
    if isinstance(requested, str):
        requested = [requested]
    requested = [tool_aliases.get(s.strip().lower(), s.strip().lower()) for s in requested if isinstance(s, str)]

    exclude_list = data.get('exclude') or data.get('exclude_sources') or []
    if isinstance(exclude_list, str):
        exclude_list = [x.strip().lower() for x in exclude_list.replace(' ', ',').split(',') if x.strip()]
    exclude_set = {tool_aliases.get(x, x) for x in exclude_list if isinstance(x, str)}

    selected = [name for name in provider_order if name in requested and name not in exclude_set]
    active_dns = bool(data.get('active_dns'))
    active_wordlist = str(data.get('active_wordlist') or '5000').strip()
    verbose_dns = bool(data.get('verbose_dns', True))
    dns_rate_limit = int(data.get('dns_rate_limit') or 150)

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
            'dns_rate_limit': dns_rate_limit,
            'selected_resolver': selected_resolver,
            'cancelled': False, 'cached': False, 'cache_key': cache_key, 'logs': [],
            'total_log_count': 0, 'created_at': time.time(),
            'main_domain': None,
        }
        cached = CACHE.get(cache_key)
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            cached_main = cached[4] if len(cached) > 4 else None
            cached_wc = cached[5] if len(cached) > 5 else None
            cached_axfr = cached[6] if len(cached) > 6 else None
            job.update(status='completed', progress='Completed (cached)', results=copy.deepcopy(cached[1]),
                       sources=cached[2].copy(), errors=cached[3].copy(), cached=True,
                       main_domain=copy.deepcopy(cached_main),
                       wildcard_dns=copy.deepcopy(cached_wc),
                       axfr_audit=copy.deepcopy(cached_axfr))
        JOBS[job['id']] = job

    if job['status'] != 'completed':
        SCAN_EXECUTOR.submit(_run_scan, job['id'], selected)
    return jsonify(_job_view(job)), 202


@scan_bp.get('/api/scan/<job_id>')
@scan_bp.get('/api/status/<job_id>')
def scan_status(job_id):
    since = request.args.get('since', 0, type=int)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            job, _ = _completed_job(job_id)
        if not job:
            return jsonify(error='Scan job not found.'), 404
        return jsonify(_job_view(job, since=since))


@scan_bp.post('/api/scan/<job_id>/cancel')
def cancel_scan(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify(error='Scan job not found.'), 404
        if job.get('status') not in ('completed', 'cancelled'):
            job.update(cancelled=True, status='cancelled', progress='Cancellation requested.')
        return jsonify(_job_view(job))
