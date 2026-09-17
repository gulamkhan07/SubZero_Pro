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
    """Enforce minimum interval between requests to the same provider."""
    with _throttle_lock:
        last = _provider_timestamps.get(provider, 0.0)
        now = time.monotonic()
        wait = min_interval - (now - last)
        if wait > 0:
            time.sleep(wait)
        _provider_timestamps[provider] = time.monotonic()


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
    for attempt in range(max_retries):
        throttle(provider, min_interval)
        try:
            if method.upper() == 'GET':
                resp = session.get(url, headers=headers, params=params, timeout=timeout)
            else:
                resp = session.request(method, url, headers=headers, params=params, timeout=timeout)

            if resp.status_code == 200:
                return resp

            if resp.status_code == 429:
                # Rate limited — back off aggressively
                delay = min(base_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(delay + jitter)
                continue

            if resp.status_code in (500, 502, 503, 504):
                delay = min(base_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.3)
                time.sleep(delay + jitter)
                continue

            # Other status codes (301, 403, 404 etc) — return as-is, no retry
            return resp

        except requests.Timeout:
            last_exc = requests.Timeout(f'{provider} request timed out (attempt {attempt + 1})')
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay + random.uniform(0, 1))

        except requests.ConnectionError:
            last_exc = requests.ConnectionError(f'{provider} connection failed (attempt {attempt + 1})')
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay + random.uniform(0, 1))

        except requests.RequestException as exc:
            last_exc = exc
            delay = min(base_delay * (2 ** attempt), max_delay)
            time.sleep(delay + random.uniform(0, 1))

    if raise_on_failure and last_exc:
        raise last_exc
    return None
