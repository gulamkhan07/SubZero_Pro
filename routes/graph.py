"""
SubZero Attack Surface Graph Data Blueprint.
Categorizes discovered subdomains and computes topology node/link graph structures.
"""
__author__ = "SubZero Community"

from flask import Blueprint, jsonify, request

from services.job_manager import PROJECT_META

graph_bp = Blueprint('graph', __name__)


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


@graph_bp.post('/api/graph/data')
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
        'developed_by': PROJECT_META['developed_by'],
        'domain': domain,
        'total_nodes': len(nodes),
        'category_counts': category_counts,
        'nodes': nodes,
        'links': links
    })
