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
from pathlib import Path
from functools import lru_cache
from typing import List, Set

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
    Returns True if random non-existent subdomain resolves.
    """
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

async def _async_dns_brute_force(candidates: List[str], max_workers: int, log_callback) -> tuple:
    """Core async engine for DNS brute-forcing."""
    resolver = dns.asyncresolver.Resolver()
    # Use reliable public DNS servers for speed and to avoid ISP blocking
    resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    sem = asyncio.Semaphore(max_workers)
    tasks = []
    
    discovered = set()
    resolved_count = 0
    nxdomain_count = 0
    timeout_count = 0
    done_count = 0
    total_candidates = len(candidates)
    
    for cand in candidates:
        tasks.append(asyncio.create_task(_async_resolve_host(cand, resolver, sem)))
        
    for coro in asyncio.as_completed(tasks):
        host, status, ips, latency, err = await coro
        done_count += 1
        num_str = f"#{done_count:04d}"
        
        if status == "resolved":
            discovered.add(host)
            resolved_count += 1
            ip_str = ', '.join(ips[:2]) if ips else 'unknown'
            log_callback(f"[ACTIVE-DNS {num_str}] [+] {host} -> {ip_str} ({latency}ms) [RESOLVED]")
        elif status == "timeout":
            timeout_count += 1
            log_callback(f"[ACTIVE-DNS {num_str}] [!] {host} -> DROPPED/TIMEOUT ({err}) after {latency}ms [TIMEOUT]")
        elif status == "nxdomain":
            nxdomain_count += 1
            log_callback(f"[ACTIVE-DNS {num_str}] [-] {host} -> NXDOMAIN ({latency}ms)")
            
        if done_count % 500 == 0 or done_count == total_candidates:
            pct = round((done_count / total_candidates) * 100)
            log_callback(f"[ACTIVE-DNS PROGRESS] {done_count:,}/{total_candidates:,} ({pct}%) | Active: {resolved_count} | NXDOMAIN: {nxdomain_count} | Dropped: {timeout_count}")
            
    return discovered, resolved_count, nxdomain_count, timeout_count, done_count

def dns_brute_force(
    domain: str,
    wordlist: List[str] = None,
    max_workers: int = 500,  # Open-source safe concurrency limit for async
    wordlist_size: str = "5000",
    log_callback = None,
    verbose: bool = True
) -> tuple:
    """
    Performs ultra-fast active DNS brute-forcing on domain using wordlist.
    Acts as a synchronous wrapper over the asyncio core engine.
    """
    def log(msg: str):
        if log_callback:
            try:
                log_callback(msg)
            except Exception:
                pass

    root = domain.strip().lower().rstrip('.')
    if not root:
        return [], "Invalid root domain", 0

    log(f"[*] Starting Async Active DNS Brute-Force for: {root}")

    # Wildcard check
    log(f"[*] Probing wildcard DNS on *.{root}...")
    if check_wildcard_dns(root):
        msg = f"Wildcard DNS detected on *.{root}. Active brute-forcing skipped to prevent false-positive flood."
        log(f"[!] {msg}")
        return [], msg, 0

    log(f"[+] Wildcard check passed. Safe to proceed.")

    words = wordlist if wordlist is not None else load_wordlist(wordlist_size)
    candidates = [f"{w.strip().lower()}.{root}" for w in words if w.strip()]
    total_candidates = len(candidates)
    
    # Bound max_workers to an open-source friendly safe limit (e.g. 50-1000)
    effective_workers = max(10, min(int(max_workers) if max_workers else 500, 1500))
    
    log(f"[*] Wordlist loaded: {total_candidates:,} queries using {effective_workers} async tasks.")

    t_start = time.time()
    
    # Launch async event loop
    try:
        discovered, resolved_count, nxdomain_count, timeout_count, done_count = asyncio.run(
            _async_dns_brute_force(candidates, effective_workers, log)
        )
    except Exception as e:
        log(f"[!] Async execution failed: {str(e)}")
        return [], f"Async error: {str(e)}", 0

    dur = round(time.time() - t_start, 2)
    rate = round(done_count / max(dur, 0.05))
    log(f"[ACTIVE-DNS COMPLETE] Finished {done_count:,} queries in {dur}s (~{rate:,} qps) — Active: {resolved_count}, NXDOMAIN: {nxdomain_count}, Dropped: {timeout_count}.")

    results = sorted(discovered)
    return results, None, len(results)
