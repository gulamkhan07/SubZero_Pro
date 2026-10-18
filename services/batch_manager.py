"""
SubZero Batch Scan Queue & Restoration Service.
Coordinates multi-target automated sequential scanning and history retrieval.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

from services.job_manager import JOBS, JOBS_LOCK, PROJECT_META
from services.scan_engine import _run_scan, _CPU_COUNT
from enumerator.providers import DEFAULT_PROVIDER_ORDER, DEFAULT_PASSIVE_PROVIDERS, TOOL_ALIASES
from enumerator.history_store import get_conn

BATCH_JOBS: Dict[str, Dict[str, Any]] = {}
BATCH_LOCK = threading.RLock()
BATCH_EXECUTOR = ThreadPoolExecutor(max_workers=min(2, _CPU_COUNT))


def _run_batch(batch_id: str, domains: List[str], config: Dict[str, Any]) -> None:
    """Executes a sequential batch reconnaissance job across multiple root domains."""
    for idx, domain in enumerate(domains):
        with BATCH_LOCK:
            batch = BATCH_JOBS.get(batch_id)
            if not batch or batch.get('cancelled'):
                return
            batch['status'] = 'running'
            batch['current_target'] = domain
            batch['current_index'] = idx + 1
            batch['progress'] = f'Scanning {idx + 1}/{len(domains)}: {domain}'

        sub_job_id = uuid.uuid4().hex
        with BATCH_LOCK:
            batch = BATCH_JOBS.get(batch_id)
            if batch:
                batch['current_job_id'] = sub_job_id
                if 'targets' not in batch:
                    batch['targets'] = {}
                batch['targets'][domain] = {
                    'job_id': sub_job_id,
                    'status': 'scanning',
                    'count': 0
                }

        requested = config.get('sources')
        if requested is None:
            selected = list(DEFAULT_PROVIDER_ORDER)
        else:
            if isinstance(requested, str):
                requested = [requested]
            requested = [TOOL_ALIASES.get(s.strip().lower(), s.strip().lower()) for s in requested if isinstance(s, str)]
            selected = [name for name in DEFAULT_PROVIDER_ORDER if name in requested]

        active_dns = bool(config.get('active_dns', False))
        active_wordlist = str(config.get('active_wordlist', '5000')).strip()
        if not selected and not active_dns:
            selected = list(DEFAULT_PASSIVE_PROVIDERS)

        validate_dns = bool(config.get('validate_dns', False))
        dns_rate_limit = int(config.get('dns_rate_limit') or 150)
        selected_resolver = str(config.get('dns_resolver') or config.get('selected_resolver') or 'all').strip().lower()

        with JOBS_LOCK:
            job = {
                'id': sub_job_id, 'domain': domain, 'status': 'running',
                'progress': 'Batch scanning...', 'sources': {}, 'errors': [], 'results': [],
                'dns_validation': validate_dns, 'active_dns': active_dns,
                'active_wordlist': active_wordlist, 'verbose_dns': False,
                'dns_rate_limit': dns_rate_limit,
                'selected_resolver': selected_resolver,
                'cancelled': False, 'cached': False,
                'cache_key': (domain, tuple(selected), validate_dns, active_dns, active_wordlist, selected_resolver),
                'logs': [], 'total_log_count': 0,
                'created_at': time.time(),
            }
            JOBS[sub_job_id] = job

        try:
            import sys
            run_scan_fn = getattr(sys.modules.get('app'), '_run_scan', _run_scan)
            run_scan_fn(sub_job_id, selected)
        except Exception as exc:
            print(f"[BATCH ERROR] Scan for {domain} crashed: {type(exc).__name__}: {exc}", flush=True)
            with JOBS_LOCK:
                failed_job = JOBS.get(sub_job_id)
                if failed_job and failed_job['status'] != 'completed':
                    failed_job.update(status='completed', progress='Completed (partial)',
                                      errors=failed_job.get('errors', []) + [f'Engine error: {exc}'])

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


def _get_or_restore_batch(batch_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active batch from memory or restores a recent batch from SQLite history."""
    with BATCH_LOCK:
        batch = BATCH_JOBS.get(batch_id)
        if batch:
            return batch
        if batch_id in ('latest', 'latest_batch') and BATCH_JOBS:
            return list(BATCH_JOBS.values())[-1]

    # Try restoring recent batch from SQLite history
    try:
        with get_conn() as conn:
            rows = conn.execute('''
                SELECT domain, id, count, subdomains_json
                FROM scan_history
                WHERE domain != 'example.com'
                GROUP BY domain
                ORDER BY MAX(timestamp) DESC
                LIMIT 5
            ''').fetchall()
            if rows:
                target_rows = rows[:3]
                domains = [r['domain'] for r in target_rows]
                restored_id = batch_id if batch_id not in ('latest', 'latest_batch') else 'latest_batch'
                targets = {}
                total_cnt = 0
                for r in target_rows:
                    d = r['domain']
                    jid = r['id']
                    cnt = r['count']
                    total_cnt += cnt
                    targets[d] = {'job_id': jid, 'status': 'completed', 'count': cnt}
                    with JOBS_LOCK:
                        if jid not in JOBS:
                            subs = json.loads(r['subdomains_json'])
                            JOBS[jid] = {
                                'id': jid,
                                'domain': d,
                                'status': 'completed',
                                'progress': 'Completed',
                                'cancelled': False,
                                'results': [{'subdomain': s, 'dns': 'not-checked'} for s in subs],
                                'main_domain': None,
                            }

                restored_batch = {
                    'id': restored_id,
                    'batch_id': restored_id,
                    'domains': domains,
                    'status': 'completed',
                    'progress': f'All {len(domains)} targets scanned successfully.',
                    'total_subdomains_found': total_cnt,
                    'completed_count': len(domains),
                    'total_domains': len(domains),
                    'targets': targets,
                    'cancelled': False,
                    'developed_by': PROJECT_META['developed_by']
                }
                with BATCH_LOCK:
                    BATCH_JOBS[restored_id] = restored_batch
                    BATCH_JOBS['latest'] = restored_batch
                    BATCH_JOBS['latest_batch'] = restored_batch
                return restored_batch
    except Exception:
        pass
    return None
