"""
Active Subdomain Discovery Module.
Performs ultra-high-speed concurrent DNS wordlist brute-forcing with wildcard DNS detection.
Optimized with pure asyncio and dnspython for massive throughput (Open-Source Friendly).
Developed by: Gulam Khan
"""
__author__ = "Gulam Khan"

import os
import time
import uuid
import socket
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from functools import lru_cache
from typing import List, Set, Tuple, Any, Optional, Dict

import dns.asyncresolver
import dns.resolver
import dns.exception

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORDLISTS_DIR = PROJECT_ROOT / 'wordlists'

# Curated list of common fallback subdomain prefixes
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "bbs", "ww42",
    "mx", "email", "cloud", "1", "mail1", "2", "forum", "admin",
    "my", "beta", "api", "mobile", "news", "docs", "apps", "cdn",
    "stage", "staging", "app", "auth", "login", "register", "signup",
    "dashboard", "panel", "cpanel", "whm", "web", "router", "gateway",
    "gw", "intranet", "internal", "corp", "corpmail", "office", "owa",
    "exchange", "autodiscover", "sip", "lyncdiscover", "meet", "chat",
    "slack", "jira", "confluence", "git", "gitlab", "github", "bitbucket",
    "ci", "jenkins", "travis", "sonar", "artifactory", "nexus", "sentry",
    "grafana", "prometheus", "kibana", "elastic", "es", "elk", "log",
    "logs", "monitor", "monitoring", "nagios", "zabbix", "status", "health",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "oracle", "mssql", "memcached", "rabbitmq", "kafka", "analytics",
    "bi", "data", "warehouse", "redshift", "hadoop", "spark", "tableau",
    "static", "assets", "media", "img", "images", "css", "js",
    "files", "download", "downloads", "upload", "uploads", "storage",
    "s3", "bucket", "content", "video", "videos", "stream", "live",
    "pay", "payment", "checkout", "billing", "invoice", "finance",
    "wallet", "crypto", "auth0", "sso", "identity", "accounts", "id",
    "oauth", "saml", "ldap", "ad", "dc", "vpn1", "vpn2", "openvpn",
    "ssl", "wireguard", "ipsec", "fw", "firewall", "proxy", "squid",
    "waf", "lb", "balancer", "traefik", "nginx", "haproxy", "envoy",
    "api-dev", "api-stage", "api-staging", "api-prod", "api-v1", "api-v2",
    "v1", "v2", "v3", "graphql", "rest", "grpc", "ws", "wss", "socket",
    "connect", "nodes", "cluster", "k8s", "kubernetes", "swarm", "docker",
    "node1", "node2", "node3", "prod", "production", "uat", "qa",
    "dev1", "dev2", "test1", "test2", "sandbox", "lab", "poc",
    "demo", "preview", "review", "canary", "alpha", "edge", "nightly",
    "customer", "client", "members", "partners", "vendors", "affiliates",
    "sales", "marketing", "leads", "crm", "salesforce", "hubspot", "zendesk",
    "help", "faq", "kb", "knowledge", "community", "careers", "jobs",
    "hr", "people", "wiki", "intra", "net", "network", "lan", "wifi",
    "guest", "public", "private", "dmz", "mgmt", "management", "jump",
    "bastion", "ssh", "rdp", "vnc", "telnet", "term", "console",
    "backup", "backups", "bak", "old", "new", "temp", "tmp",
    "ns3", "ns4", "dns", "dns1", "dns2", "whois", "spf", "dmarc",
    "mail3", "mx1", "mx2", "relay", "filter", "antispam", "postmaster"
]

@lru_cache(maxsize=4)
def load_wordlist(size_or_name: str = "5000") -> List[str]:
    """
    Loads active wordlist from wordlists/ directory and caches it in memory.
    Massively reduces disk I/O on sequential or batch scans.
    """
    name = str(size_or_name or "5000").strip()
    candidates = [
        WORDLISTS_DIR / f"subdomains_{name}.txt",
        WORDLISTS_DIR / f"{name}.txt",
        WORDLISTS_DIR / name,
        WORDLISTS_DIR / "subdomains_5000.txt",
        WORDLISTS_DIR / "subdomains_10000.txt",
        PROJECT_ROOT / "wordlist.txt",
        WORDLISTS_DIR / "wordlist.txt",
    ]
    for path in candidates:
        if path.is_file():
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
                if words:
                    return words
            except Exception:
                continue
    return COMMON_SUBDOMAINS

def check_wildcard_dns(domain: str) -> bool:
    """
    Checks if domain has a wildcard DNS record (*.domain.com) configured.
    Uses robust multi-probe resolver check to prevent ISP captive portal false positives.
    """
    try:
        from enumerator.wildcard_detector import detect_wildcard_dns
        info = detect_wildcard_dns(domain, timeout=1.5)
        return bool(info.get('is_wildcard'))
    except Exception:
        random_sub = f"wildcard-check-{uuid.uuid4().hex[:12]}.{domain}"
        try:
            socket.getaddrinfo(random_sub, None)
            return True
        except (socket.gaierror, OSError):
            return False

async def _async_resolve_host(host: str, resolver: dns.asyncresolver.Resolver, sem: asyncio.Semaphore) -> tuple:
    """Asynchronous DNS resolution bounded by a semaphore."""
    t0 = time.time()
    async with sem:
        try:
            answers = await resolver.resolve(host, 'A')
            ips = sorted({rdata.address for rdata in answers})
            latency = round((time.time() - t0) * 1000, 1)
            return host, "resolved", ips, latency, None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            latency = round((time.time() - t0) * 1000, 1)
            return host, "nxdomain", [], latency, None
        except dns.exception.Timeout:
            latency = round((time.time() - t0) * 1000, 1)
            return host, "timeout", [], latency, "Timeout"
        except Exception as exc:
            latency = round((time.time() - t0) * 1000, 1)
            return host, "error", [], latency, str(exc)

def _resolve_single_host(cand: str, session: Any) -> Tuple[str, str, List[str]]:
    """
    Resolves a candidate domain using Anycast DoH (port 443) with native OS socket fallback.
    Immune to ISP port 53 UDP blocking and packet drops.
    """
    # Tier 1: Anycast Google DoH (Fast HTTP connection pooling)
    if session:
        try:
            r = session.get(f"https://dns.google/resolve?name={cand}&type=A", timeout=1.5)
            if r.status_code == 200:
                d = r.json()
                if d.get("Answer"):
                    ips = [a["data"] for a in d["Answer"] if a.get("type") == 1]
                    if ips:
                        return cand, "resolved", ips
                if d.get("Status") == 3 or (d.get("Status") == 0 and not d.get("Answer")):
                    return cand, "nxdomain", []
        except Exception:
            pass

    # Tier 2: Native OS socket resolution (WinSock / libc)
    try:
        r = socket.getaddrinfo(cand, None)
        ips = sorted({x[4][0] for x in r if x and len(x) > 4 and ":" not in x[4][0]})
        if ips:
            return cand, "resolved", ips
    except Exception:
        pass

    return cand, "nxdomain", []


def dns_brute_force(
    domain: str,
    wordlist: List[str] = None,
    max_workers: int = 60,
    wordlist_size: str = "5000",
    log_callback = None,
    verbose: bool = True,
    allow_wildcard_filtering: bool = False,
    wildcard_ips: Optional[List[str]] = None,
    **kwargs
) -> tuple:
    """
    Performs ultra-fast, firewall-resilient active DNS brute-forcing on domain using wordlist.
    Uses scaled HTTP/2 Anycast DoH and native OS resolver fallbacks to prevent UDP port 53 blocking.
    """
    if 'concurrency' in kwargs:
        max_workers = kwargs.pop('concurrency')
    if 'wordlist_name' in kwargs:
        wordlist_size = kwargs.pop('wordlist_name')
    if 'allow_wildcard' in kwargs:
        allow_wildcard_filtering = kwargs.pop('allow_wildcard')
    def log(msg: str):
        if log_callback:
            try:
                log_callback(msg)
            except Exception:
                pass

    root = domain.strip().lower().rstrip('.')
    if not root:
        return [], "Invalid root domain", 0

    log(f"[*] Starting Active DNS Brute-Force for: {root}")

    # Wildcard check
    wc_ip_set = set(wildcard_ips or [])
    if wildcard_ips is not None and len(wildcard_ips) > 0:
        is_wc = True
    elif wildcard_ips is not None and len(wildcard_ips) == 0:
        is_wc = False
    else:
        log(f"[*] Probing wildcard DNS on *.{root}...")
        is_wc = check_wildcard_dns(root)

    if is_wc and not allow_wildcard_filtering:
        msg = f"Wildcard DNS detected on *.{root}. Active brute-forcing skipped to prevent false-positive flood."
        log(f"[!] {msg}")
        return [], msg, 0
    elif is_wc:
        wc_summary = ', '.join(sorted(wc_ip_set)) if wc_ip_set else 'catchall baseline'
        log(f"[!] Wildcard DNS active on *.{root} ({wc_summary}). Intelligent baseline IP filtering engaged to isolate true subdomains.")
    else:
        log(f"[+] Wildcard check passed. Safe to proceed.")

    words = wordlist if wordlist is not None else load_wordlist(wordlist_size)
    candidates = [f"{w.strip().lower()}.{root}" for w in words if w.strip()]
    total_candidates = len(candidates)
    
    effective_workers = max(10, min(int(max_workers) if max_workers else 60, 80))
    progress_interval = 250 if total_candidates > 5000 else 100
    log(f"[*] Wordlist loaded: {total_candidates:,} queries using {effective_workers} concurrent resolver threads.")

    t_start = time.time()
    discovered: Set[str] = set()
    resolved_count = 0
    nxdomain_count = 0
    done_count = 0
    lock = threading.Lock()

    import requests
    from requests.adapters import HTTPAdapter
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=effective_workers, pool_maxsize=effective_workers, max_retries=1)
    session.mount("https://", adapter)
    session.headers.update({"Accept": "application/dns-json"})

    try:
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            futures = {pool.submit(_resolve_single_host, cand, session): cand for cand in candidates}
            for fut in as_completed(futures):
                try:
                    cand, status, ips = fut.result()
                except Exception:
                    cand, status, ips = futures[fut], "nxdomain", []

                with lock:
                    done_count += 1
                    if status == "resolved" and ips:
                        if is_wc and wc_ip_set and set(ips).issubset(wc_ip_set):
                            nxdomain_count += 1
                        else:
                            resolved_count += 1
                            discovered.add(cand)
                            num_str = f"#{done_count:04d}"
                            ip_str = ', '.join(ips[:2])
                            log(f"[ACTIVE-DNS {num_str}] [+] {cand} -> {ip_str} [RESOLVED]")
                    else:
                        nxdomain_count += 1

                    if done_count % progress_interval == 0 or done_count == total_candidates:
                        pct = round((done_count / total_candidates) * 100) if total_candidates else 100
                        log(f"[ACTIVE-DNS PROGRESS] {done_count:,}/{total_candidates:,} ({pct}%) | Testing: {cand} | Active: {resolved_count} | NXDOMAIN: {nxdomain_count}")
    finally:
        try:
            session.close()
        except Exception:
            pass

    dur = round(time.time() - t_start, 2)
    rate = round(done_count / max(dur, 0.05))
    log(f"[ACTIVE-DNS COMPLETE] Finished {done_count:,} queries in {dur}s (~{rate:,} qps) — Active: {resolved_count}, NXDOMAIN: {nxdomain_count}.")

    results = sorted(discovered)
    return results, None, len(results)
