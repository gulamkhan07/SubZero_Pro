"""
Shared HTTP Request Utilities with Rate Limiting & Retry Logic.
Provides exponential backoff with jitter, session pooling, and per-provider throttling.
Developed by: Gulam
"""
__author__ = "Gulam"

import random
import time
import threading

import requests
import requests.adapters

# ---------------------------------------------------------------------------
# Singleton requests.Session with connection pooling
# ---------------------------------------------------------------------------
_session = None
_session_lock = threading.Lock()

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
]


def get_session() -> requests.Session:
    """Thread-safe singleton session with connection pooling."""
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                s = requests.Session()
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=100,
                    pool_maxsize=100,
                    max_retries=0,  # We handle retries manually
                )
                s.mount('http://', adapter)
                s.mount('https://', adapter)
                _session = s
    return _session


def random_user_agent() -> str:
    """Return a random User-Agent header to reduce fingerprinting blocks."""
    return random.choice(USER_AGENTS)


# ---------------------------------------------------------------------------
# Per-provider throttling via monotonic timestamps
# ---------------------------------------------------------------------------
_provider_timestamps: dict = {}
_throttle_lock = threading.Lock()


def throttle(provider: str, min_interval: float = 1.0):
    """Enforce minimum interval between requests to the same provider without blocking other providers."""
    wait = 0.0
    with _throttle_lock:
        last = _provider_timestamps.get(provider, 0.0)
        now = time.monotonic()
        diff = now - last
        if diff < min_interval:
            wait = min_interval - diff
            _provider_timestamps[provider] = now + wait
        else:
            _provider_timestamps[provider] = now

    if wait > 0:
        time.sleep(wait)


# ---------------------------------------------------------------------------
# Per-provider error diagnostics tracking
# ---------------------------------------------------------------------------
_provider_last_errors: dict = {}
_error_lock = threading.Lock()


def get_provider_last_error(provider: str) -> str:
    """Returns the most recent detailed failure reason recorded for a provider."""
    with _error_lock:
        return _provider_last_errors.get(provider, '')


def set_provider_last_error(provider: str, error_msg: str):
    """Sets the most recent failure reason recorded for a provider."""
    with _error_lock:
        _provider_last_errors[provider] = error_msg


def _diagnose_exception(exc: Exception, timeout: float = 15.0) -> str:
    """Translates raw python requests/socket exceptions into clear, actionable messages."""
    msg = str(exc)
    exc_type = type(exc).__name__

    if isinstance(exc, requests.exceptions.SSLError) or 'SSLError' in exc_type:
        return "SSL certificate verification failed (check corporate proxy / CA store)"
    if isinstance(exc, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.Timeout)):
        return f"Connection timed out after {int(timeout)}s (high latency or firewall dropped packet)"
    if isinstance(exc, requests.exceptions.ConnectionError):
        lower_msg = msg.lower()
        if 'getaddrinfo failed' in lower_msg or 'nameresolutionerror' in lower_msg or 'dns' in lower_msg:
            return "DNS name resolution failed (check internet connection / DNS resolver)"
        if 'connection refused' in lower_msg:
            return "Connection refused by remote host"
        if 'connection reset' in lower_msg:
            return "Connection reset by peer / firewall"
        return "Network connection failed (unreachable host)"
    return f"Request error ({exc_type}): {msg[:120]}"


# ---------------------------------------------------------------------------
# Retry with exponential backoff + jitter
# ---------------------------------------------------------------------------

def retry_request(
    url: str,
    provider: str,
    *,
    method: str = 'GET',
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 15.0,
    timeout: float = 15.0,
    headers: dict = None,
    params: dict = None,
    min_interval: float = 0.5,
    raise_on_failure: bool = False,
):
    """
    HTTP request with exponential backoff + jitter and per-provider throttling.

    - On 200: returns Response immediately.
    - On 429 / 5xx: retries with exponential backoff + 30% jitter.
    - On other 4xx: returns Response without retry (client error).
    - On network/timeout errors: retries with backoff.
    - After all retries exhausted: returns None (or raises if raise_on_failure).
    """
    session = get_session()
    if headers is None:
        headers = {}
    if 'User-Agent' not in headers:
        headers['User-Agent'] = random_user_agent()

    last_exc = None
    last_diagnostic = ""

    for attempt in range(max_retries):
        throttle(provider, min_interval)
        try:
            if method.upper() == 'GET':
                resp = session.get(url, headers=headers, params=params, timeout=timeout)
            else:
                resp = session.request(method, url, headers=headers, params=params, timeout=timeout)

            if resp.status_code == 200:
                set_provider_last_error(provider, '')
                return resp

            if resp.status_code == 429:
                last_diagnostic = "API rate limit reached (HTTP 429 Too Many Requests)"
                delay = min(base_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(delay + jitter)
                continue

            if resp.status_code in (500, 502, 503, 504):
                last_diagnostic = f"Remote server temporarily unavailable (HTTP {resp.status_code})"
                delay = min(base_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(delay + jitter)
                continue

            # Other status codes (301, 403, 404 etc) — return as-is, no retry
            if resp.status_code == 403:
                last_diagnostic = "Access forbidden / Cloudflare challenge (HTTP 403)"
            elif resp.status_code == 404:
                last_diagnostic = "Target resource not found (HTTP 404)"
            else:
                last_diagnostic = f"Remote returned HTTP {resp.status_code}"
            set_provider_last_error(provider, last_diagnostic)
            return resp

        except requests.Timeout as exc:
            last_exc = exc
            last_diagnostic = _diagnose_exception(exc, timeout)
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay + random.uniform(0, 1))

        except requests.ConnectionError as exc:
            last_exc = exc
            last_diagnostic = _diagnose_exception(exc, timeout)
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay + random.uniform(0, 1))

        except requests.RequestException as exc:
            last_exc = exc
            last_diagnostic = _diagnose_exception(exc, timeout)
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay + random.uniform(0, 1))

    if last_diagnostic:
        set_provider_last_error(provider, last_diagnostic)

    if raise_on_failure and last_exc:
        raise last_exc
    return None


# ---------------------------------------------------------------------------
# Network Connectivity Pre-flight Diagnostic
# ---------------------------------------------------------------------------

def check_network_connectivity(test_endpoints=None, timeout: float = 3.5) -> dict:
    """
    Checks if this host has active internet connectivity and working DNS.
    Tests reachability against resilient public endpoints.
    """
    if test_endpoints is None:
        test_endpoints = [
            ('Cloudflare Public DNS', 'https://1.1.1.1'),
            ('Google Public DNS', 'https://8.8.8.8'),
            ('Quad9 DNS', 'https://9.9.9.9'),
        ]

    session = get_session()
    errors = []

    for name, endpoint in test_endpoints:
        try:
            r = session.head(endpoint, timeout=timeout, headers={'User-Agent': random_user_agent()})
            if r.status_code in (200, 301, 302, 400, 403, 405):
                return {'online': True, 'tested_endpoint': name, 'status': 'connected'}
        except Exception as exc:
            errors.append(f"{name}: {_diagnose_exception(exc, timeout)}")

    return {
        'online': False,
        'status': 'offline_or_blocked',
        'errors': errors,
        'advice': "Check your internet connection, WiFi, proxy settings, or firewall."
    }

