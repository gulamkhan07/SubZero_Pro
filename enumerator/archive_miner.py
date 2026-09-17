"""
Historical Archive & Wayback Machine URL Miner.
Queries Internet Archive (Wayback CDX API) and AlienVault OTX to extract historical subdomains,
sensitive exposed files (.env, .git, .zip, .sql, configs), parameter endpoints, and API routes.
Developed by: Gulam
"""
__author__ = "Gulam"

import re
import time
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from enumerator.request_utils import retry_request, random_user_agent
    HAS_RETRY = True
except ImportError:
    HAS_RETRY = False

# Sensitive file extension and path patterns
SENSITIVE_PATTERNS = [
    re.compile(r"\.(env|git|sql|bak|backup|tar|gz|tgz|zip|7z|rar|conf|config|ini|ya?ml|log|sqlite|sqlite3|db|swp|orig|old|key|pem|crt|pfx|p12|sh|bash)$", re.I),
    re.compile(r"(\.git/|\.svn/|\.env|\.htaccess|wp-config\.php|phpinfo\.php|server-status|phpmyadmin|actuator|swagger\.json|api-docs)", re.I)
]

# Sensitive query parameter names of interest for bug bounty / security analysis
SENSITIVE_PARAMS = {
    "redirect", "redirect_url", "redirect_to", "url", "next", "dest", "destination",
    "return", "return_to", "returnurl", "target", "goto",
    "token", "access_token", "auth_token", "api_key", "apikey", "key", "secret", "auth",
    "user", "username", "email", "id", "account", "user_id", "admin", "debug", "test",
    "cmd", "exec", "command", "file", "path", "folder", "download", "load"
}

API_PATTERNS = [
    re.compile(r"/(api|v1|v2|v3|graphql|rest|v4|v5)/", re.I)
]


def _clean_host(hostname: str) -> str:
    """Cleans hostname and strips port if present."""
    if not hostname:
        return ""
    host = hostname.split(':')[0].strip().lower().rstrip('.')
    return host


def fetch_wayback_urls(domain: str, limit: int = 2500, timeout: int = 10) -> List[str]:
    """Queries Wayback Machine CDX API for historical URLs with retry."""
    if not HAS_REQUESTS:
        return []
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit={limit}"
    headers = {"User-Agent": "SubdomainFinderPro-ArchiveMiner/2.2"}
    try:
        if HAS_RETRY:
            resp = retry_request(
                url, provider='wayback',
                headers=headers, timeout=timeout,
                max_retries=2, base_delay=2.0, min_interval=0.5,
            )
        else:
            resp = requests.get(url, timeout=timeout, headers=headers)
        if resp and resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                # First element is the header row ['original']
                return [row[0] for row in data[1:] if row and isinstance(row, list) and row[0]]
    except Exception:
        pass
    return []


def fetch_alienvault_urls(domain: str, limit: int = 500, timeout: int = 8) -> List[str]:
    """Queries AlienVault OTX URL API for historical URLs with retry."""
    if not HAS_REQUESTS:
        return []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit={limit}"
    headers = {"User-Agent": "SubdomainFinderPro-ArchiveMiner/2.2"}
    try:
        if HAS_RETRY:
            resp = retry_request(
                url, provider='alienvault',
                headers=headers, timeout=timeout,
                max_retries=2, base_delay=1.5, min_interval=0.5,
            )
        else:
            resp = requests.get(url, timeout=timeout, headers=headers)
        if resp and resp.status_code == 200:
            data = resp.json()
            url_list = data.get("url_list", [])
            return [item.get("url") for item in url_list if item.get("url")]
    except Exception:
        pass
    return []


def mine_archive_urls(domain: str, limit: int = 3000, timeout: int = 10) -> Dict[str, Any]:
    """
    Mines historical URLs from Wayback Machine and AlienVault OTX,
    extracts historical subdomains, sensitive file leaks, parameter targets, and API endpoints.
    """
    t0 = time.time()
    clean_domain = domain.strip().lower().rstrip('.')
    all_raw_urls: Set[str] = set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        f_wayback = executor.submit(fetch_wayback_urls, clean_domain, limit, timeout)
        f_otx = executor.submit(fetch_alienvault_urls, clean_domain, min(limit, 500), timeout)
        
        for f in as_completed([f_wayback, f_otx]):
            try:
                urls = f.result()
                if urls:
                    all_raw_urls.update(urls)
            except Exception:
                pass

    historical_subdomains: Set[str] = set()
    sensitive_files: List[Dict[str, str]] = []
    parameter_urls: List[Dict[str, Any]] = []
    api_endpoints: List[str] = []
    clean_all_urls: List[str] = []

    seen_sensitive = set()
    seen_params = set()
    seen_apis = set()

    for raw_url in all_raw_urls:
        if not raw_url or not isinstance(raw_url, str):
            continue
        raw_url = raw_url.strip()
        if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
            raw_url = "http://" + raw_url

        try:
            parsed = urlparse(raw_url)
        except Exception:
            continue

        host = _clean_host(parsed.hostname)
        if not host:
            continue

        # Extract subdomain if it belongs to target domain
        if host == clean_domain or host.endswith("." + clean_domain):
            historical_subdomains.add(host)

        url_str = raw_url
        clean_all_urls.append(url_str)
        path = parsed.path or ""
        query = parsed.query or ""

        # 1. Check for Sensitive Files & Paths
        for pat in SENSITIVE_PATTERNS:
            if pat.search(path) or pat.search(url_str):
                if url_str not in seen_sensitive:
                    seen_sensitive.add(url_str)
                    sensitive_files.append({
                        "url": url_str,
                        "host": host,
                        "path": path,
                        "category": "Sensitive File/Directory"
                    })
                break

        # 2. Check for Interesting Query Parameters
        if query:
            try:
                q_params = parse_qs(query, keep_blank_values=True)
                matched_params = [p for p in q_params.keys() if p.lower() in SENSITIVE_PARAMS]
                if matched_params:
                    if url_str not in seen_params:
                        seen_params.add(url_str)
                        parameter_urls.append({
                            "url": url_str,
                            "host": host,
                            "params": matched_params,
                            "count": len(matched_params)
                        })
            except Exception:
                pass

        # 3. Check for API Endpoints
        for api_pat in API_PATTERNS:
            if api_pat.search(path):
                if url_str not in seen_apis:
                    seen_apis.add(url_str)
                    api_endpoints.append(url_str)
                break

    sorted_subs = sorted(historical_subdomains)

    return {
        "developed_by": "Gulam",
        "domain": clean_domain,
        "total_urls": len(clean_all_urls),
        "total_subdomains": len(sorted_subs),
        "historical_subdomains": sorted_subs,
        "sensitive_files_count": len(sensitive_files),
        "sensitive_files": sensitive_files[:300],
        "parameter_urls_count": len(parameter_urls),
        "parameter_urls": parameter_urls[:300],
        "api_endpoints_count": len(api_endpoints),
        "api_endpoints": api_endpoints[:300],
        "sample_urls": clean_all_urls[:200],
        "duration": round(time.time() - t0, 2)
    }
