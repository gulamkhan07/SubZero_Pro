"""
SubZero Advanced Attack Surface Blueprint.
Handles permutations, nested sub-zone discovery, and free Shodan InternetDB intelligence.
"""
__author__ = "SubZero Community"

import sys
from flask import Blueprint, jsonify, request

from services.job_manager import PROJECT_META
from enumerator.normalizer import valid_domain
from enumerator.permutation_engine import generate_permutations, scan_permutations
from enumerator.nested_engine import discover_nested_subdomains, extract_subzones, mine_nested_patterns
from enumerator.shodan_free import harvest_shodan_internetdb

advanced_bp = Blueprint('advanced', __name__)


@advanced_bp.post('/api/permutations/generate')
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
        'developed_by': PROJECT_META['developed_by'],
        'domain': domain,
        'total_candidates': len(candidates),
        'candidates': candidates
    })


@advanced_bp.post('/api/permutations/scan')
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


@advanced_bp.post('/api/nested/subzones')
def api_nested_subzones():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    hosts = data.get('hosts') or []
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain.'), 400
    subzones = extract_subzones(hosts, domain)
    candidates = mine_nested_patterns(hosts, domain, max_candidates=100)
    return jsonify({
        'domain': domain,
        'subzones': [{'subzone': sz, 'count': cnt} for sz, cnt in subzones],
        'sample_candidates': candidates[:50],
        'total_subzones': len(subzones)
    })


@advanced_bp.post('/api/nested/scan')
def api_nested_scan():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    hosts = data.get('hosts') or []
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain.'), 400
    limit = min(int(data.get('limit', 500)), 1500)
    concurrency = min(int(data.get('concurrency', 25)), 50)
    resolver = data.get('dns_resolver') or data.get('selected_resolver') or 'all'

    live_hosts = discover_nested_subdomains(
        domain, hosts, max_candidates=limit, max_workers=concurrency, dns_resolver=resolver
    )
    return jsonify({
        'domain': domain,
        'total_discovered': len(live_hosts),
        'subdomains': sorted(live_hosts)
    })


@advanced_bp.post('/api/shodan/free')
def api_shodan_free():
    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower().rstrip('.')
    ips = data.get('ips') or []
    if not domain or not valid_domain(domain):
        return jsonify(error='Provide a valid root domain.'), 400
    harvest_fn = getattr(sys.modules.get('app'), 'harvest_shodan_internetdb', harvest_shodan_internetdb)
    res = harvest_fn(ips, domain)
    return jsonify(res)


