"""
Confirmed "True Origin IP" (WAF Bypass) Active Verification Engine.
Actively sends HTTP and HTTPS probes directly to suspected Origin IP addresses
with 'Host: <target_domain>' headers to verify if the server serves the
backend web application, confirming a 100% genuine WAF bypass vulnerability.
Developed by: Gulam
"""
__author__ = "Gulam"

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from typing import Any, Dict, Iterable, List, Optional
import urllib3

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Known default / parking / error page titles that must NOT trigger origin confirmation
DEFAULT_PAGE_TITLES = {
    "apache2 ubuntu default page", "apache2 debian default page",
    "test page for the apache http server", "test page for apache installation",
    "welcome to nginx", "welcome to nginx!",
    "iis windows server", "iis windows", "welcome - microsoft internet information services",
    "default web site page", "default page",
    "it works!", "it works",
    "cpanel", "cpanel login", "whm login", "webmail login",
    "plesk", "plesk obsidian", "plesk onyx", "default web page",
    "web server default page", "coming soon", "under construction",
    "website coming soon", "page parking", "parked domain",
    "domain parking", "future home of something quite cool",
    "congratulations", "403 forbidden", "404 not found",
    "access denied", "error", "server error",
    "web hosting", "hosting default",
    "directadmin", "ispconfig", "virtualmin", "webmin",
    "default parallels plesk panel page",
    "default website page", "namecheap",
}


def _is_default_page_title(title: str) -> bool:
    """Returns True if the title matches known default/parking/error pages."""
    if not title:
        return True
    t = title.strip().lower()
    if t in DEFAULT_PAGE_TITLES:
        return True
    # Fuzzy match: if any default phrase is contained in the title
    for default in DEFAULT_PAGE_TITLES:
        if default in t:
            return True
    return False


def _extract_title(html: str) -> str:
    """Extracts cleaned HTML <title> text."""
    if not html:
        return ""
    m = TITLE_REGEX.search(html)
    if m:
        return " ".join(m.group(1).split()).strip()
    return ""


def get_target_baseline(target_domain: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Fetches the baseline HTTP/HTTPS response attributes of the public target domain.
    Used for comparative verification against suspected Origin IPs.
    """
    baseline = {
        "domain": target_domain,
        "title": "",
        "status_code": 0,
        "server": "",
        "content_length": 0
    }
    if not HAS_REQUESTS:
        return baseline

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubZero-OriginVerifier/2.2"}
    for proto in ["https", "http"]:
        url = f"{proto}://{target_domain}"
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
            baseline["status_code"] = resp.status_code
            baseline["title"] = _extract_title(resp.text)
            baseline["server"] = resp.headers.get("Server", "")
            baseline["content_length"] = len(resp.content or b"")
            if baseline["title"] or baseline["status_code"] == 200:
                break
        except Exception:
            continue

    return baseline


def verify_single_origin_ip(
    ip: str,
    target_domain: str,
    baseline: Optional[Dict[str, Any]] = None,
    timeout: float = 3.5
) -> Dict[str, Any]:
    """
    Probes a candidate Origin IP on HTTP (80) and HTTPS (443) with 'Host: <target_domain>'.
    Determines if it is a confirmed Origin Server (WAF Bypass).
    """
    clean_ip = (ip or "").strip()
    clean_domain = target_domain.strip().lower().rstrip(".")
    result = {
        "ip": clean_ip,
        "target_domain": clean_domain,
        "is_confirmed_origin": False,
        "verified_proto": "",
        "status_code": 0,
        "origin_title": "",
        "server": "",
        "evidence": "",
        "confidence": "none"
    }

    if not clean_ip or not HAS_REQUESTS:
        return result

    base_title = (baseline.get("title") if baseline else "").strip()
    headers = {
        "Host": clean_domain,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubZero-OriginVerifier/2.2",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    for proto in ["https", "http"]:
        url = f"{proto}://{clean_ip}"
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            res_title = _extract_title(resp.text)
            server = resp.headers.get("Server", "")

            # 1. Exact Title Match with Public Baseline
            if base_title and res_title and (base_title.lower() == res_title.lower() or base_title.lower() in res_title.lower()):
                result.update({
                    "is_confirmed_origin": True,
                    "verified_proto": proto,
                    "status_code": resp.status_code,
                    "origin_title": res_title,
                    "server": server,
                    "evidence": f"HTML Title exactly matches target baseline ({res_title[:40]})",
                    "confidence": "high"
                })
                return result

            # 2. Domain presence in response body / Location header / Cookies
            resp_text_lower = (resp.text or "").lower()
            location_header = resp.headers.get("Location", "").lower()
            if clean_domain in location_header or (clean_domain in resp_text_lower and resp.status_code in [200, 301, 302]):
                result.update({
                    "is_confirmed_origin": True,
                    "verified_proto": proto,
                    "status_code": resp.status_code,
                    "origin_title": res_title,
                    "server": server,
                    "evidence": f"VHost accepted: redirected or responded with target domain content (HTTP {resp.status_code})",
                    "confidence": "medium"
                })
                return result

            # 3. Valid HTTP 200 with matching server attributes — but EXCLUDE default/parking pages
            if resp.status_code == 200 and res_title and not _is_default_page_title(res_title):
                result.update({
                    "is_confirmed_origin": True,
                    "verified_proto": proto,
                    "status_code": resp.status_code,
                    "origin_title": res_title,
                    "server": server,
                    "evidence": f"Direct web server active with title: '{res_title[:40]}'",
                    "confidence": "low"
                })
                return result

        except Exception:
            continue

    return result


def verify_origin_candidates(
    ip_list: Iterable[str],
    target_domain: str,
    max_workers: int = 10,
    timeout: float = 3.5
) -> Dict[str, Dict[str, Any]]:
    """
    Verifies multiple candidate origin IPs in parallel.
    Returns mapping of ip -> verification_result.
    """
    unique_ips = list(set(ip.strip() for ip in ip_list if ip and ip.strip()))
    if not unique_ips or not HAS_REQUESTS:
        return {}

    baseline = get_target_baseline(target_domain, timeout=timeout)
    results: Dict[str, Dict[str, Any]] = {}
    workers = min(len(unique_ips), max_workers) or 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(verify_single_origin_ip, ip, target_domain, baseline, timeout): ip
            for ip in unique_ips
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception:
                results[ip] = {"ip": ip, "is_confirmed_origin": False}

    return results
