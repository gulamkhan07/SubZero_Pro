"""
SubZero Security Auditing Blueprint.
Handles HTTP Prober, Dangling CNAME Takeover Auditor, and Zone Transfer (AXFR) Checker.
"""
__author__ = "SubZero Community"

import sys
from flask import Blueprint, jsonify, request

from services.job_manager import PROJECT_META
from enumerator.http_prober import probe_hosts
from enumerator.cname_auditor import audit_hosts
from enumerator.axfr_auditor import check_zone_transfer
from enumerator.normalizer import valid_domain

audit_bp = Blueprint('audit', __name__)


@audit_bp.post('/api/probe')
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
    rate_limit = data.get('rate_limit')
    if rate_limit is None:
        rate_limit = 15.0
    else:
        try:
            rate_limit = float(rate_limit)
        except (ValueError, TypeError):
            rate_limit = 15.0

    import sys
    probe_fn = getattr(sys.modules.get('app'), 'probe_hosts', probe_hosts)
    probed = probe_fn(
        hosts,
        max_workers=concurrency,
        timeout=timeout,
        specific_resolver=specific_resolver,
        rate_limit=rate_limit if rate_limit > 0 else None
    )
    alive_count = sum(1 for p in probed if p.get('alive'))
    return jsonify({
        'developed_by': PROJECT_META['developed_by'],
        'total_probed': len(probed),
        'alive_count': alive_count,
        'results': probed
    })


@audit_bp.post('/api/audit/cname')
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
        'developed_by': PROJECT_META['developed_by'],
        'total_audited': len(results),
        'dangling_count': dangling_count,
        'cname_count': cname_count,
        'results': results
    })


@audit_bp.post('/api/audit/axfr')
def api_audit_axfr():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain (e.g. example.com).'), 400

    timeout = float(data.get('timeout', 2.5))
    import sys
    axfr_fn = getattr(sys.modules.get('app'), 'check_zone_transfer', check_zone_transfer)
    res = axfr_fn(domain, timeout=timeout)
    return jsonify(res)
