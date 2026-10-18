"""
SubZero State & Job Management Service.
Centralized, thread-safe in-memory job store, cache, and history restoration.
"""
__author__ = "SubZero Community"

import json
import threading
import time
from typing import Any, Dict, Optional, Tuple
from flask import jsonify

from enumerator.history_store import prune_old_history, get_conn

__version__ = "2.2.0"

# ---------------------------------------------------------------------------
# Project-wide metadata — single source of truth for API responses
# ---------------------------------------------------------------------------
PROJECT_META = {
    'developed_by': 'SubZero Community',
    'version': __version__,
}

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.RLock()
CACHE: Dict[Tuple, Tuple] = {}
CACHE_TTL_SECONDS = 600
MAX_JOB_AGE_SECONDS = 1800  # 30 minutes
_stop_cleanup = threading.Event()
_cleanup_thread_started = False


def _cleanup_old_jobs() -> None:
    """Periodically remove completed/cancelled jobs older than MAX_JOB_AGE_SECONDS
    and expired cache entries. Runs every 5 minutes as a daemon thread.
    Uses threading.Event for graceful shutdown instead of bare while True."""
    while not _stop_cleanup.wait(300):
        now = time.time()
        with JOBS_LOCK:
            to_delete = [
                jid for jid, job in JOBS.items()
                if job.get('status') in ('completed', 'cancelled')
                and now - job.get('created_at', now) > MAX_JOB_AGE_SECONDS
            ]
            for jid in to_delete:
                del JOBS[jid]
            expired_keys = [k for k, v in CACHE.items() if now - v[0] > CACHE_TTL_SECONDS]
            for k in expired_keys:
                del CACHE[k]
        # Prune old scan history entries to prevent unbounded DB growth
        try:
            prune_old_history(max_age_days=90, max_rows=500)
        except Exception:
            pass


def _ensure_cleanup_thread() -> None:
    """Ensures the background job cleanup daemon thread is running."""
    global _cleanup_thread_started
    if not _cleanup_thread_started:
        _cleanup_thread_started = True
        threading.Thread(target=_cleanup_old_jobs, daemon=True, name='job-cleanup').start()


def _add_log(job: Dict[str, Any], msg: str) -> None:
    """Appends a timestamped log line to a job record and prints to stdout safely."""
    ts = time.strftime('%H:%M:%S')
    entry = f'[{ts}] {msg}'
    try:
        print(entry, flush=True)
    except UnicodeEncodeError:
        try:
            safe_entry = entry.encode('ascii', errors='backslashreplace').decode('ascii')
            print(safe_entry, flush=True)
        except Exception:
            pass
    except Exception:
        pass
    with JOBS_LOCK:
        if 'logs' not in job:
            job['logs'] = []
        job['logs'].append(entry)
        job['total_log_count'] = job.get('total_log_count', 0) + 1
        if len(job['logs']) > 10000:
            job['logs'] = job['logs'][-5000:]


def _job_view(job: Dict[str, Any], include_results: bool = True, since: int = 0) -> Dict[str, Any]:
    """Generates a serialized view of a job for JSON API status responses."""
    all_logs = job.get('logs', [])
    data = {
        'id': job['id'], 'domain': job['domain'], 'status': job['status'],
        'developed_by': PROJECT_META['developed_by'],
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
        'axfr_audit': job.get('axfr_audit'),
    }
    if include_results and job.get('status') == 'completed':
        data['results'] = job.get('results', [])
    return data


def _completed_job(job_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Any]]:
    """Helper to retrieve a completed scan job by ID, with SQLite history fallback."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            if job['status'] != 'completed':
                return None, (jsonify(error='Scan is not complete yet.'), 409)
            return job, None

    # Check SQLite database for past scan history
    try:
        with get_conn() as conn:
            try:
                row = conn.execute(
                    'SELECT id, domain, count, sources_json, subdomains_json, results_json, main_domain_json FROM scan_history WHERE id = ?',
                    (job_id,)
                ).fetchone()
            except Exception:
                try:
                    row = conn.execute(
                        'SELECT id, domain, count, sources_json, subdomains_json, results_json FROM scan_history WHERE id = ?',
                        (job_id,)
                    ).fetchone()
                except Exception:
                    row = conn.execute(
                        'SELECT id, domain, count, sources_json, subdomains_json FROM scan_history WHERE id = ?',
                        (job_id,)
                    ).fetchone()

            if row:
                sources = json.loads(row['sources_json'] or '{}')
                src_list = list(sources.keys()) if sources else ['History']
                raw_results = None
                try:
                    if 'results_json' in row.keys() and row['results_json']:
                        raw_results = json.loads(row['results_json'])
                except Exception:
                    raw_results = None

                main_dom = None
                try:
                    if 'main_domain_json' in row.keys() and row['main_domain_json']:
                        main_dom = json.loads(row['main_domain_json'])
                except Exception:
                    main_dom = None

                if raw_results and isinstance(raw_results, list) and len(raw_results) > 0 and isinstance(raw_results[0], dict):
                    results = raw_results
                else:
                    subs = json.loads(row['subdomains_json'] or '[]')
                    results = [
                        {
                            'subdomain': s,
                            'sources': src_list,
                            'confidence': 'high',
                            'dns': 'not-checked',
                            'dns_ips': [],
                            'cname': ''
                        }
                        for s in subs
                    ]
                restored = {
                    'id': row['id'],
                    'domain': row['domain'],
                    'status': 'completed',
                    'progress': 'Completed',
                    'results': results,
                    'sources': sources,
                    'errors': [],
                    'cached': True,
                    'cancelled': False,
                    'dns_validation': False,
                    'created_at': time.time(),
                    'logs': [],
                    'main_domain': main_dom,
                }
                with JOBS_LOCK:
                    JOBS[job_id] = restored
                return restored, None
    except Exception:
        pass

    return None, (jsonify(error='Scan job not found.'), 404)
