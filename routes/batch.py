"""
SubZero Multi-Domain Batch Queue Blueprint.
Handles batch initialization, status polling, cancellation, subdomains export, and live verification.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import sys
from typing import Any, Dict, List
import uuid

from flask import Blueprint, jsonify, request

from services.job_manager import JOBS, JOBS_LOCK, PROJECT_META
from services.batch_manager import (
    BATCH_JOBS,
    BATCH_LOCK,
    BATCH_EXECUTOR,
    _run_batch,
    _get_or_restore_batch,
)
from enumerator.normalizer import valid_domain
from enumerator.http_prober import probe_hosts
from enumerator.dns_resolver import check_domain_multi_resolver
from enumerator.ip_intel import classify_ips

batch_bp = Blueprint('batch', __name__)


@batch_bp.post('/api/batch/start')
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
        'developed_by': PROJECT_META['developed_by']
    }
    with BATCH_LOCK:
        BATCH_JOBS[batch_id] = batch

    executor = getattr(sys.modules.get('app'), 'BATCH_EXECUTOR', BATCH_EXECUTOR)
    executor.submit(_run_batch, batch_id, valid_targets, data)
    return jsonify(batch), 202


@batch_bp.get('/api/batch/<batch_id>')
def batch_status(batch_id: str):
    batch = _get_or_restore_batch(batch_id)
    if not batch:
        return jsonify(error='Batch job not found.'), 404

    with BATCH_LOCK:
        total_found = sum(t.get('count', 0) for t in batch.get('targets', {}).values())
        domains_list = []
        for d in batch['domains']:
            tgt = batch.get('targets', {}).get(d)
            if tgt:
                live_count = tgt.get('count', 0)
                tgt_status = tgt.get('status', 'completed')
                if tgt_status == 'scanning':
                    with JOBS_LOCK:
                        live_job = JOBS.get(tgt.get('job_id'))
                        if live_job:
                            live_count = len(live_job.get('results', [])) or live_job.get('live_count', 0)
                domains_list.append({
                    'domain': d,
                    'status': tgt_status,
                    'subdomain_count': live_count,
                    'job_id': tgt.get('job_id')
                })
            elif d == batch.get('current_target'):
                live_cnt = 0
                c_jid = batch.get('current_job_id')
                if c_jid:
                    with JOBS_LOCK:
                        live_job = JOBS.get(c_jid)
                        if live_job:
                            live_cnt = len(live_job.get('results', [])) or live_job.get('live_count', 0)
                domains_list.append({
                    'domain': d,
                    'status': 'scanning',
                    'subdomain_count': live_cnt,
                    'job_id': c_jid
                })
            else:
                domains_list.append({
                    'domain': d,
                    'status': 'queued',
                    'subdomain_count': 0,
                    'job_id': None
                })

        total_found = sum(d_item.get('subdomain_count', 0) for d_item in domains_list)
        actual_completed = sum(
            1 for d_item in domains_list
            if d_item.get('status') == 'completed'
        )

        resp = copy.deepcopy(batch)
        resp['batch_id'] = batch.get('id', batch_id)
        resp['total_domains'] = len(batch['domains'])
        resp['completed_count'] = actual_completed
        resp['total_subdomains_found'] = total_found
        resp['current_domain'] = batch.get('current_target') or ''
        resp['domains'] = domains_list
        return jsonify(resp)


@batch_bp.post('/api/batch/<batch_id>/cancel')
def batch_cancel(batch_id: str):
    with BATCH_LOCK:
        batch = BATCH_JOBS.get(batch_id)
        if not batch:
            return jsonify(error='Batch job not found.'), 404
        batch['cancelled'] = True
        batch['status'] = 'cancelled'
        current_target = batch.get('current_target')
        batch_snapshot = copy.deepcopy(batch)

    if current_target:
        with JOBS_LOCK:
            for jid, job in JOBS.items():
                if job.get('domain') == current_target and job.get('status') not in ('completed', 'cancelled'):
                    job.update(cancelled=True, status='cancelled', progress='Cancelled via batch cancel.')
                    break
    return jsonify(batch_snapshot)


@batch_bp.get('/api/batch/<batch_id>/subdomains')
def batch_subdomains(batch_id: str):
    batch = _get_or_restore_batch(batch_id)
    if not batch:
        return jsonify(error='Batch job not found.'), 404

    with BATCH_LOCK:
        targets = copy.deepcopy(batch.get('targets', {}))
        current_target = batch.get('current_target')
        current_job_id = batch.get('current_job_id')

    all_hosts = set()
    live_hosts = set()
    dead_hosts = set()
    details = []
    seen_details = set()
    per_target = {}

    target_jobs = []
    for d, info in targets.items():
        jid = info.get('job_id')
        if jid:
            target_jobs.append((d, jid))
    if current_target and current_job_id and not any(t[0] == current_target for t in target_jobs):
        target_jobs.append((current_target, current_job_id))

    with JOBS_LOCK:
        for domain, jid in target_jobs:
            job = JOBS.get(jid)
            if not job:
                continue
            res_list = job.get('results', [])
            per_target[domain] = []
            for item in res_list:
                sub = (item.get('subdomain') or item.get('domain') or '').strip().lower()
                if not sub:
                    continue
                all_hosts.add(sub)
                per_target[domain].append(sub)
                dns_status = item.get('dns', 'not-checked')
                if dns_status == 'resolved':
                    live_hosts.add(sub)
                elif dns_status == 'unresolved':
                    dead_hosts.add(sub)
                if sub not in seen_details:
                    seen_details.add(sub)
                    details.append(copy.deepcopy(item))

    sorted_all = sorted(all_hosts)
    sorted_live = sorted(live_hosts)
    sorted_dead = sorted(dead_hosts)

    return jsonify({
        'batch_id': batch_id,
        'total_subdomains': len(sorted_all),
        'live_count': len(sorted_live),
        'dead_count': len(sorted_dead),
        'subdomains': sorted_all,
        'live_subdomains': sorted_live,
        'dead_subdomains': sorted_dead,
        'per_target': per_target,
        'details': details
    })


@batch_bp.post('/api/batch/live-check')
def batch_live_check():
    data = request.get_json(silent=True) or {}
    raw_hosts = data.get('hosts') or data.get('subdomains') or []
    if isinstance(raw_hosts, str):
        raw_hosts = [h.strip() for h in raw_hosts.replace(',', '\n').splitlines() if h.strip()]

    hosts = []
    seen = set()
    for h in raw_hosts:
        if isinstance(h, str):
            clean_h = h.strip().lower().rstrip('.')
            if clean_h and clean_h not in seen:
                seen.add(clean_h)
                hosts.append(clean_h)

    hosts = hosts[:1000]
    if not hosts:
        return jsonify(error='Provide at least one subdomain to check for live status.'), 400

    mode = str(data.get('mode') or 'dns').strip().lower()
    resolver = str(data.get('resolver') or data.get('dns_resolver') or 'all').strip().lower()
    timeout = float(data.get('timeout', 1.8))
    concurrency = min(int(data.get('concurrency', 40)), 60)

    if mode == 'http':
        probe_fn = getattr(sys.modules.get('app'), 'probe_hosts', probe_hosts)
        rate_limit = data.get('rate_limit') or data.get('probe_rate')
        probe_kwargs = {'max_workers': concurrency, 'timeout': timeout, 'specific_resolver': resolver}
        if rate_limit:
            try:
                probe_kwargs['rate_limit'] = float(rate_limit)
            except (ValueError, TypeError):
                pass
        probed = probe_fn(hosts, **probe_kwargs)
        live_results = []
        dead_results = []
        unique_ips = set()
        for p in probed:
            ip = p.get('ip')
            if ip:
                unique_ips.add(ip)
            is_live = bool(p.get('alive') or (p.get('status_code') and p.get('status_code') > 0) or p.get('dns_status') == 'resolved')
            p['is_live'] = is_live
            if is_live:
                live_results.append(p)
            else:
                dead_results.append(p)

        return jsonify({
            'status': 'completed',
            'mode': 'http',
            'total': len(probed),
            'live_count': len(live_results),
            'dead_count': len(dead_results),
            'unique_ips': sorted(unique_ips),
            'live_hosts': [p['host'] for p in live_results],
            'dead_hosts': [p['host'] for p in dead_results],
            'results': live_results + dead_results
        })

    # Default Mode: Fast Multi-Resolver DNS verification
    results = []
    live_hosts = []
    dead_hosts = []
    unique_ips = set()

    resolver_fn = getattr(sys.modules.get('app'), 'check_domain_multi_resolver', check_domain_multi_resolver)
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_to_host = {
            pool.submit(resolver_fn, host, resolver, timeout): host
            for host in hosts
        }
        for fut in as_completed(future_to_host):
            host = future_to_host[fut]
            try:
                dns_info = fut.result()
            except Exception as ex:
                dns_info = {
                    'status': 'unresolved',
                    'alive': False,
                    'resolver': None,
                    'ips': [],
                    'cname': '',
                    'summary': f'Lookup exception: {ex}'
                }

            is_live = bool(dns_info.get('status') == 'resolved' or dns_info.get('alive'))
            ips = dns_info.get('ips', [])
            cname = dns_info.get('cname', '')
            res_label = dns_info.get('resolver', 'Public DNS')

            for ip in ips:
                unique_ips.add(ip)

            intel = classify_ips(ips, cname=cname) if ips or cname else {}
            waf_label = intel.get('waf_provider', '')
            badge_type = intel.get('badge_type', '')

            item = {
                'host': host,
                'subdomain': host,
                'alive': is_live,
                'status': 'resolved' if is_live else 'unresolved',
                'ips': ips,
                'primary_ip': ips[0] if ips else '',
                'cname': cname,
                'resolver': res_label,
                'summary': dns_info.get('summary', ''),
                'waf_provider': waf_label,
                'waf_badge': badge_type,
                'is_cdn': intel.get('is_cdn', False)
            }
            results.append(item)
            if is_live:
                live_hosts.append(host)
            else:
                dead_hosts.append(host)

    results.sort(key=lambda x: (0 if x['alive'] else 1, x['host']))
    live_hosts.sort()
    dead_hosts.sort()

    return jsonify({
        'status': 'completed',
        'mode': 'dns',
        'resolver': resolver,
        'total': len(hosts),
        'live_count': len(live_hosts),
        'dead_count': len(dead_hosts),
        'unique_ips': sorted(unique_ips),
        'live_hosts': live_hosts,
        'dead_hosts': dead_hosts,
        'results': results
    })
