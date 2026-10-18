"""
SubZero Scan History and Change Diff Blueprint.
Tracks historical discovery results and calculates delta additions/removals.
"""
__author__ = "SubZero Community"

from flask import Blueprint, jsonify, request

from services.job_manager import PROJECT_META
from enumerator.history_store import get_recent_scans, get_domain_scans, compute_diff

history_bp = Blueprint('history', __name__)


@history_bp.get('/api/history')
def api_history():
    domain = request.args.get('domain')
    scans = get_recent_scans(limit=50, domain=domain)
    return jsonify(scans=scans, developed_by=PROJECT_META['developed_by'])


@history_bp.get('/api/history/<domain>')
def api_domain_history(domain: str):
    scans = get_domain_scans(domain)
    return jsonify(domain=domain, scans=scans, developed_by=PROJECT_META['developed_by'])


@history_bp.get('/api/history/diff')
def api_history_diff():
    old_id = request.args.get('old', '') or request.args.get('scan_a', '')
    new_id = request.args.get('new', '') or request.args.get('scan_b', '')
    if not old_id or not new_id:
        return jsonify(error='Specify both old and new scan IDs to compare.'), 400
    diff = compute_diff(old_id, new_id)
    return jsonify(diff)
