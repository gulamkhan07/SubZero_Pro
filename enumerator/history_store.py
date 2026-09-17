"""
Scan History & Diff Change Tracking Store.
Maintains persistent timeline of subdomain scans and calculates delta additions/removals.
Developed by: Gulam
"""
__author__ = "Gulam"

import json
import os
from pathlib import Path
import sqlite3
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = PROJECT_ROOT / '.runtime'
DB_PATH = RUNTIME_DIR / 'history.db'


from contextlib import contextmanager

@contextmanager
def _get_conn():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA busy_timeout=5000;')
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with _get_conn() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                timestamp REAL NOT NULL,
                formatted_date TEXT NOT NULL,
                count INTEGER NOT NULL,
                sources_json TEXT NOT NULL,
                subdomains_json TEXT NOT NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON scan_history(domain)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp DESC)')


def save_scan_history(job_id: str, domain: str, results: list, sources: dict):
    init_db()
    ts = time.time()
    formatted = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    subdomains = [r.get('subdomain', '') if isinstance(r, dict) else str(r) for r in results]
    subdomains = sorted(set(s for s in subdomains if s))

    try:
        with _get_conn() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO scan_history
                (id, domain, timestamp, formatted_date, count, sources_json, subdomains_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                job_id,
                domain.strip().lower().rstrip('.'),
                ts,
                formatted,
                len(subdomains),
                json.dumps(sources or {}),
                json.dumps(subdomains)
            ))
    except Exception as e:
        print(f"[!] Warning: Failed to save scan history: {e}", flush=True)


def get_recent_scans(limit=50, domain: str = None) -> list:
    init_db()
    if isinstance(limit, str):
        domain = limit
        limit = 50
    try:
        with _get_conn() as conn:
            if domain:
                d = domain.strip().lower().rstrip('.')
                rows = conn.execute('''
                    SELECT id, domain, timestamp, formatted_date, count, sources_json
                    FROM scan_history
                    WHERE domain = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (d, int(limit))).fetchall()
            else:
                rows = conn.execute('''
                    SELECT id, domain, timestamp, formatted_date, count, sources_json
                    FROM scan_history
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (int(limit),)).fetchall()

            return [
                {
                    'id': r['id'],
                    'domain': r['domain'],
                    'timestamp': r['timestamp'],
                    'formatted_date': r['formatted_date'],
                    'count': r['count'],
                    'sources': json.loads(r['sources_json'] or '{}'),
                    'sources_used': list((json.loads(r['sources_json'] or '{}')).keys()),
                    'result_count': r['count']
                }
                for r in rows
            ]
    except Exception as e:
        print(f"[!] Error fetching recent scans: {e}", flush=True)
        return []


def get_domain_scans(domain: str) -> list:
    return get_recent_scans(limit=100, domain=domain)


def compute_diff(old_scan_id: str, new_scan_id: str) -> dict:
    init_db()
    try:
        with _get_conn() as conn:
            old_row = conn.execute('SELECT * FROM scan_history WHERE id = ?', (old_scan_id,)).fetchone()
            new_row = conn.execute('SELECT * FROM scan_history WHERE id = ?', (new_scan_id,)).fetchone()

            if not old_row or not new_row:
                return {'error': 'One or both scan snapshots not found.'}

            old_subs = set(json.loads(old_row['subdomains_json'] or '[]'))
            new_subs = set(json.loads(new_row['subdomains_json'] or '[]'))

            added = sorted(new_subs - old_subs)
            removed = sorted(old_subs - new_subs)
            persisted = sorted(old_subs & new_subs)

            return {
                'domain': new_row['domain'],
                'old_scan': {
                    'id': old_row['id'],
                    'date': old_row['formatted_date'],
                    'count': old_row['count']
                },
                'new_scan': {
                    'id': new_row['id'],
                    'date': new_row['formatted_date'],
                    'count': new_row['count']
                },
                'added_count': len(added),
                'removed_count': len(removed),
                'persisted_count': len(persisted),
                'counts': {
                    'added': len(added),
                    'removed': len(removed),
                    'unchanged': len(persisted)
                },
                'added': added,
                'removed': removed,
                'persisted': persisted,
                'unchanged': persisted
            }
    except Exception as e:
        return {'error': f'Diff computation failed: {e}'}

