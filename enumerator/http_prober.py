"""
On-Demand Live HTTP / Web Service Status & Enterprise WAF Prober.
Strictly decoupled from pure DNS discovery. Checks live status codes, server headers,
WAF signatures (Cloudflare, AWS, Azure, Google Cloud Armor, Akamai, F5, Imperva, etc.),
titles, and latency.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional
import requests
import urllib3
from enumerator.ip_intel import detect_waf_from_http, classify_ips, classify_ip

# Suppress insecure HTTPS warning for internal/self-signed certs during probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Rotating modern browser User-Agents to prevent bot signature detection
BROWSER_USER_AGENTS: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
]

PROBE_HEADERS = {
    'User-Agent': BROWSER_USER_AGENTS[0],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1'
}


def _get_probe_headers() -> Dict[str, str]:
    """Generates realistic HTTP request headers with randomized User-Agent rotation."""
    headers = dict(PROBE_HEADERS)
    headers['User-Agent'] = random.choice(BROWSER_USER_AGENTS)
    return headers


class _HttpRateLimiter:
    """
    Thread-safe token-bucket rate limiter with randomized micro-jitter and
    adaptive WAF cooldown backoff.

    Attributes:
        rate: Maximum requests per second (QPS cap).
        jitter: If True, applies +/-20% random variance to break robotic cadence.
        cooldown_seconds: Sleep duration upon detecting HTTP 429 or WAF challenge block.
    """

    def __init__(self, rate: float = 15.0, jitter: bool = True, cooldown_seconds: float = 4.0):
        self._rate = max(float(rate), 0.5)
        self._base_interval = 1.0 / self._rate
        self._jitter = bool(jitter)
        self._cooldown_seconds = max(float(cooldown_seconds), 1.0)
        self._lock = threading.Lock()
        self._last_time = time.monotonic()
        self._cooldown_until = 0.0
        self._backoff_count = 0

    def acquire(self) -> None:
        """Blocks until a token is available, observing any active cooldown and applying jitter."""
        with self._lock:
            now = time.monotonic()
            # If in adaptive cooldown, pause until cooldown expires
            if now < self._cooldown_until:
                sleep_cooldown = self._cooldown_until - now
                time.sleep(sleep_cooldown)
                now = time.monotonic()
                self._last_time = now

            interval = self._base_interval
            if self._jitter:
                # +/-20% randomized variance to blur robotic cadence
                interval *= random.uniform(0.80, 1.20)

            wait = interval - (now - self._last_time)
            if wait > 0:
                time.sleep(wait)
            self._last_time = time.monotonic()

    def report_throttle(self) -> None:
        """Called when a worker encounters an HTTP 429 or WAF block.
        Synchronizes an immediate cooldown across all worker threads.
        """
        with self._lock:
            now = time.monotonic()
            self._backoff_count += 1
            multiplier = min(1.0 + (self._backoff_count * 0.5), 3.0)
            self._cooldown_until = max(self._cooldown_until, now + (self._cooldown_seconds * multiplier))


def _resolve_host_ip(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if infos:
            for family, _, _, _, sockaddr in infos:
                if family == socket.AF_INET:
                    return sockaddr[0]
            return infos[0][4][0]
    except Exception:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _probe_single_host(
    host: str,
    timeout: float = 3.0,
    specific_resolver: str = None,
    known_ip: str = "",
    rate_limiter: Optional[_HttpRateLimiter] = None
) -> dict:
    host = host.strip().lower()
    if not host:
        return {}

    # Quick IP resolution for WAF / origin matching (use known_ip from DNS if provided)
    resolved_ip = known_ip or _resolve_host_ip(host)
    ip_classification = classify_ip(resolved_ip) if resolved_ip else None

    # Try HTTPS first, fallback to HTTP
    endpoints = [f"https://{host}", f"http://{host}"]
    last_err = None

    for url in endpoints:
        r = None
        if rate_limiter is not None:
            rate_limiter.acquire()
        t_start = time.perf_counter()
        try:
            r = requests.get(
                url,
                headers=_get_probe_headers(),
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                stream=True
            )
            elapsed_ms = int((time.perf_counter() - t_start) * 1000)

            # Read at most first 32KB for title and WAF extraction to keep RAM usage minimal
            body_chunk = ""
            try:
                chunk = next(r.iter_content(32768), b"")
                if isinstance(chunk, bytes):
                    body_chunk = chunk.decode('utf-8', errors='ignore')
                elif isinstance(chunk, str):
                    body_chunk = chunk
            except Exception:
                body_chunk = getattr(r, 'text', '')[:32768] if hasattr(r, 'text') else ""

            title = ""
            if body_chunk:
                m = re.search(r'<title[^>]*>(.*?)</title>', body_chunk, re.IGNORECASE | re.DOTALL)
                if m:
                    title = ' '.join(m.group(1).split()).strip()[:90]

            server = ''
            headers_dict = dict(r.headers) if hasattr(r, 'headers') and r.headers else {}
            if headers_dict:
                server = (headers_dict.get('Server') or headers_dict.get('server') or '').strip()[:40]

            status = r.status_code
            final_url = r.url
            hist_list = getattr(r, 'history', None)
            redirect_chain = [getattr(hist, 'url', str(hist)) for hist in hist_list] if isinstance(hist_list, (list, tuple)) else []

            # Check if redirected to a third-party host (Phase 18)
            from urllib.parse import urlparse
            final_host = (urlparse(final_url).hostname or "").lower()
            orig_host = host.lower()
            is_third_party_redirect = bool(final_host and not (final_host == orig_host or final_host.endswith(f".{orig_host}") or orig_host.endswith(f".{final_host}")))

            # Multi-tier WAF analysis: HTTP headers/body signatures + IP CIDR
            # If third-party redirected, check initial response to avoid attributing external provider WAF
            if is_third_party_redirect and isinstance(hist_list, (list, tuple)) and hist_list:
                first_h = hist_list[0]
                init_headers = dict(first_h.headers) if hasattr(first_h, 'headers') and isinstance(getattr(first_h, 'headers', None), (dict, list)) else {}
                init_status = getattr(first_h, 'status_code', 0)
                waf_info = detect_waf_from_http(init_headers, "", init_status)
            else:
                waf_info = detect_waf_from_http(headers_dict, body_chunk, status)

            waf_detected = False
            waf_provider = ""
            waf_badge = "waf"
            waf_evidence = ""

            if waf_info:
                waf_detected = True
                waf_provider = waf_info['waf_provider']
                waf_badge = waf_info['badge_type']
                waf_evidence = waf_info.get('evidence', '')
            elif ip_classification and ip_classification.get('is_cdn'):
                waf_detected = True
                waf_provider = ip_classification['waf_provider']
                waf_badge = ip_classification['badge_type']
                waf_evidence = f"IP Range Match ({resolved_ip})"

            # If server is empty but WAF is detected, display the WAF platform
            display_server = server
            if not display_server or display_server in ('—', 'Hidden'):
                if waf_detected:
                    display_server = waf_provider
            elif waf_detected and waf_badge != 'origin' and waf_provider.lower() not in display_server.lower():
                display_server = f"{display_server} ({waf_provider})"

            # If WAF rate limit (429) or challenge (403) detected, notify rate limiter to back off
            if rate_limiter is not None and (status == 429 or (status == 403 and waf_detected)):
                rate_limiter.report_throttle()

            return {
                'host': host,
                'subdomain': host,
                'alive': True,
                'status_code': status,
                'title': title or '—',
                'server': display_server or '—',
                'waf_detected': waf_detected,
                'waf_provider': waf_provider,
                'waf_badge': waf_badge,
                'waf_evidence': waf_evidence,
                'ip': resolved_ip,
                'response_time_ms': elapsed_ms,
                'url': final_url,
                'protocol': 'https' if final_url.startswith('https') else 'http',
                'redirect_chain': redirect_chain,
                'error': None
            }
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            last_err = 'Connection Refused'
            continue
        except requests.exceptions.Timeout:
            last_err = 'Connection Timeout'
            continue
        except Exception as e:
            last_err = str(e)[:50]
            continue
        finally:
            if r is not None:
                try:
                    r.close()
                except Exception:
                    pass

    # HTTP failed; check DNS status across multi-resolvers to determine if domain is truly dead
    dns_info = {}
    try:
        from enumerator.dns_resolver import check_domain_multi_resolver
        dns_info = check_domain_multi_resolver(host, specific_resolver=specific_resolver)
    except Exception:
        pass

    waf_detected = False
    waf_provider = ""
    waf_badge = "waf"
    dns_ips = dns_info.get('ips', [])
    if resolved_ip and resolved_ip not in dns_ips:
        dns_ips.append(resolved_ip)

    if dns_ips:
        ip_intel_res = classify_ips(dns_ips)
        if ip_intel_res.get('is_cdn'):
            waf_detected = True
            waf_provider = ip_intel_res.get('waf_provider', '')
            waf_badge = ip_intel_res.get('badge_type', 'waf')

    if dns_info.get('alive'):
        resolver_str = dns_info.get('resolver', 'Public DNS')
        ip_hint = f" [{dns_ips[0]}]" if dns_ips else ""
        error_msg = f"Port 80/443 closed (DNS Live via {resolver_str}{ip_hint})"
        dns_status = 'resolved'
        dns_resolver = resolver_str
    else:
        error_msg = "Dead (DNS Unresolved across all public resolvers)" if not specific_resolver or specific_resolver == 'all' else f"Dead / Unresolved via {specific_resolver.title()}"
        dns_status = 'unresolved'
        dns_resolver = dns_info.get('resolver') or 'None (Dead across all resolvers)'

    return {
        'host': host,
        'subdomain': host,
        'alive': False,
        'status_code': 0,
        'title': '—',
        'server': waf_provider if waf_detected else '—',
        'waf_detected': waf_detected,
        'waf_provider': waf_provider,
        'waf_badge': waf_badge,
        'ip': dns_ips[0] if dns_ips else resolved_ip,
        'url': f'http://{host}',
        'protocol': 'none',
        'error': error_msg,
        'dns_status': dns_status,
        'dns_resolver': dns_resolver,
        'dns_ips': dns_ips
    }


def probe_hosts(
    hosts: list,
    max_workers: int = 15,
    timeout: float = 3.0,
    specific_resolver: str = None,
    host_ips: dict = None,
    rate_limit: Optional[float] = None,
    jitter: bool = True,
    **kwargs
) -> list:
    unique_hosts = sorted(set(h.strip().lower() for h in hosts if h.strip()))
    if not unique_hosts:
        return []

    rate_limiter = None
    if rate_limit is not None and float(rate_limit) > 0:
        rate_limiter = _HttpRateLimiter(rate=float(rate_limit), jitter=jitter)

    effective_workers = max(1, min(int(max_workers) if max_workers else 15, 20, len(unique_hosts)))
    if rate_limiter is not None and effective_workers > int(rate_limiter._rate):
        effective_workers = max(1, min(effective_workers, int(rate_limiter._rate)))

    results = []
    host_ips_map = host_ips or {}
    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        futures = [
            pool.submit(_probe_single_host, h, timeout, specific_resolver, host_ips_map.get(h, ""), rate_limiter)
            for h in unique_hosts
        ]
        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)

    # Sort results: live 200s first, then other live codes, then offline
    def sort_key(item):
        code = item.get('status_code', 0)
        if code == 200:
            return 0
        if code > 0:
            return 1
        return 2

    return sorted(results, key=sort_key)
