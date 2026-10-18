"""
SubZero - Fast OSINT & Active DNS Reconnaissance Engine
Version: 2.2.0

Modular Application Entry Point.
Coordinates Flask configuration, Blueprint routing, and background services.
"""
__author__ = "SubZero Community"
__version__ = "2.2.0"

import atexit
import logging
import os
import sys
import threading
from pathlib import Path

# Configure standard streams to handle Unicode gracefully on Windows consoles
for stream_name in ('stdout', 'stderr'):
    stream = getattr(sys, stream_name, None)
    if stream and hasattr(stream, 'reconfigure'):
        try:
            stream.reconfigure(encoding='utf-8', errors='backslashreplace')
        except Exception:
            pass

from flask import Flask

# Import Services & Centralized State
from services.job_manager import (
    PROJECT_META,
    JOBS,
    JOBS_LOCK,
    CACHE,
    CACHE_TTL_SECONDS,
    MAX_JOB_AGE_SECONDS,
    _cleanup_old_jobs,
    _ensure_cleanup_thread,
    _add_log,
    _job_view,
    _completed_job,
)
from services.scan_engine import (
    SCAN_EXECUTOR,
    _CPU_COUNT,
    _enrich_subdomain_record,
    _resolve_and_enrich_hosts,
    _run_scan,
)
from services.batch_manager import (
    BATCH_JOBS,
    BATCH_LOCK,
    BATCH_EXECUTOR,
    _run_batch,
    _get_or_restore_batch,
)
from services.filter_service import (
    _is_result_live,
    _is_result_dead,
    _filter_results,
)
from enumerator.dns_resolver import check_domain_multi_resolver
from enumerator.http_prober import probe_hosts
from enumerator.axfr_auditor import check_zone_transfer
from enumerator.shodan_free import harvest_shodan_internetdb
from enumerator.providers import PROVIDERS, DEFAULT_PROVIDER_ORDER, DEFAULT_PASSIVE_PROVIDERS, TOOL_ALIASES

# Import Route Blueprints
from routes.scan import scan_bp
from routes.export import export_bp
from routes.history import history_bp
from routes.batch import batch_bp
from routes.audit import audit_bp
from routes.advanced import advanced_bp
from routes.graph import graph_bp
from routes.download import download_bp

logger = logging.getLogger('subzero')

# Initialize Flask Application
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True


@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


# Register Modular Route Blueprints
app.register_blueprint(scan_bp)
app.register_blueprint(export_bp)
app.register_blueprint(history_bp)
app.register_blueprint(batch_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(advanced_bp)
app.register_blueprint(graph_bp)
app.register_blueprint(download_bp)


def _shutdown_executors():
    """Gracefully shutdown thread pool executors on process exit."""
    try:
        SCAN_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    try:
        BATCH_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass


atexit.register(_shutdown_executors)


if __name__ == '__main__':
    # Auto-check and download external tools (Subfinder, Amass, SecLists wordlists) if missing
    def _auto_check_tools():
        try:
            from install_tools import install, BIN_DIR, PROJECT_ROOT
            ext = '.exe' if sys.platform.startswith('win') else ''
            subfinder_bin = os.path.join(BIN_DIR, f'subfinder{ext}')
            wordlist_5k = os.path.join(PROJECT_ROOT, 'wordlists', 'subdomains_5000.txt')
            if not os.path.isfile(subfinder_bin) or not os.path.isfile(wordlist_5k):
                print("[*] First-time setup detected: Downloading discovery binaries & wordlists...")
                install(verbose=True)
        except Exception:
            pass

    threading.Thread(target=_auto_check_tools, daemon=True).start()

    print("[*] SubZero v2.2 running on http://127.0.0.1:5000 (Modular Decoupled Engine)")
    app.run(host='127.0.0.1', port=5000, debug=False)
