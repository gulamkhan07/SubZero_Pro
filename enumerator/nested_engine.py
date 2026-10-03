"""
Nested & Recursive Subdomain Discovery Engine for SubZero
Specialized in multi-tenant, cloud-native, and multi-level (depth 2-5)
subdomain reconnaissance without requiring paid API subscriptions.
"""
__author__ = "SubZero Community"

import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from enumerator.dns_resolver import check_domain_multi_resolver
from enumerator.request_utils import retry_request, random_user_agent

# Standard cloud, environment and service vocabularies
KNOWN_ENV_KEYWORDS = {
    "devsecops", "sqa", "preprod", "prod", "production", "staging", "stage",
    "sandbox", "sbx", "sbx1", "sbx2", "uat", "val", "trn", "test", "testing",
    "qa", "dev", "devel", "development", "corp", "internal", "int", "dmz",
    "private", "priv", "lab", "demo", "preview", "review", "poc", "k8s",
    "cluster", "node", "core", "infra", "cloud", "aws", "azure", "gcp"
}

STANDARD_SERVICES = {
    "api", "app", "applications", "applicationsapi", "apps", "artwork", "auth",
    "billing", "bots", "botsapi", "cdn", "chatbotapi", "chatbotcommonapi",
    "chatbotdsapi", "chatbotui", "common", "content", "contentpartner",
    "contentpartnerapi", "cosmetics-sa", "cosmetics-sv", "cppdf", "dashboard",
    "data", "dataagent", "datahub", "devices", "dlpapi", "docs", "docsmanager",
    "dossier", "dossierbuilder", "dossierbuilderapi", "eventmanager", "events",
    "fia-a2a", "fia-sv", "files", "food-sa", "freya", "gateway", "grafana",
    "graphexplorer", "gri", "grr", "gw", "haapi", "help", "hub", "idmp",
    "impact-assessment", "insights", "insightsapi", "internal", "inventory",
    "kmdm", "kmdmapp", "knowledgenavigation", "label", "labeling", "lcm",
    "login", "mail", "management", "media", "metrics", "mia-sa", "monitor",
    "mr", "mrapi", "newsapi", "nl", "nlapi", "nlmsapi", "notifications",
    "pac", "pactbroker", "pat", "pdf", "pia-sa", "platform", "portal",
    "proxy", "registrations", "reports", "sccm", "sccmapi", "secure",
    "services", "sso", "static", "status", "submissionsectd", "support",
    "tools", "ui", "uimanager", "vpn", "waf", "web", "workflow", "xevmpd"
}


def extract_subzones(hosts: Iterable[str], root_domain: str) -> List[Tuple[str, int]]:
    """
    Analyzes discovered hosts and extracts parent sub-zones (e.g. devsecops.example.com, sqa.example.com).
    Returns list of (subzone, count) sorted by frequency of occurrence.
    """
    clean_root = root_domain.strip().lower().rstrip('.')
    if not clean_root:
        return []

    subzone_counts: Counter = Counter()

    for h in hosts:
        if not h or not isinstance(h, str):
            continue
        clean_host = h.strip().lower().rstrip('.')
        if not (clean_host.endswith('.' + clean_root)):
            continue
        
        prefix = clean_host[:-len('.' + clean_root)]
        parts = prefix.split('.')
        
        # If prefix is "api.gilead.devsecops", subzones are:
        # - devsecops.root
        # - gilead.devsecops.root
        if len(parts) >= 2:
            for i in range(1, len(parts)):
                subzone_name = '.'.join(parts[i:]) + '.' + clean_root
                subzone_counts[subzone_name] += 1
        elif len(parts) == 1:
            # Single prefix might itself be an environment subzone (e.g. devsecops.root)
            token = parts[0]
            if any(env in token for env in KNOWN_ENV_KEYWORDS):
                subzone_counts[clean_host] += 1

    return subzone_counts.most_common()


def mine_nested_patterns(
    hosts: Iterable[str],
    root_domain: str,
    max_candidates: int = 1500
) -> List[str]:
    """
    Learns naming conventions, client/tenant identifiers, environments, and services
    from discovered subdomains, synthesizing multi-level candidate hostnames.
    """
    clean_root = root_domain.strip().lower().rstrip('.')
    known_hosts = set()
    service_tokens = set(STANDARD_SERVICES)
    tenant_tokens = set()
    env_tokens = set(KNOWN_ENV_KEYWORDS)
    subzones = set()

    for h in hosts:
        if not h or not isinstance(h, str):
            continue
        clean_host = h.strip().lower().rstrip('.')
        known_hosts.add(clean_host)
        if not clean_host.endswith('.' + clean_root):
            continue
        
        prefix = clean_host[:-len('.' + clean_root)]
        parts = prefix.split('.')

        if len(parts) >= 3:
            # e.g. service.tenant.env.root
            service_tokens.add(parts[0])
            tenant_tokens.add(parts[1])
            env_tokens.add(parts[2])
            subzones.add(parts[-1] + '.' + clean_root)
            subzones.add('.'.join(parts[1:]) + '.' + clean_root)
        elif len(parts) == 2:
            # e.g. service.env.root OR service.tenant.root
            service_tokens.add(parts[0])
            mid = parts[1]
            if any(e in mid for e in KNOWN_ENV_KEYWORDS):
                env_tokens.add(mid)
            else:
                tenant_tokens.add(mid)
            subzones.add(parts[1] + '.' + clean_root)
        elif len(parts) == 1:
            token = parts[0]
            if any(e in token for e in KNOWN_ENV_KEYWORDS):
                env_tokens.add(token)
                subzones.add(token + '.' + clean_root)
            else:
                service_tokens.add(token)

    # Sanitize tokens (alphanumeric with hyphen)
    clean_services = sorted(s for s in service_tokens if re.match(r'^[a-z0-9][a-z0-9\-]{0,25}$', s))
    clean_tenants = sorted(t for t in tenant_tokens if re.match(r'^[a-z0-9][a-z0-9\-]{0,25}$', t))
    clean_subzones = sorted(z for z in subzones if z.endswith('.' + clean_root))

    candidates: Set[str] = set()

    # Rule 1: Service + Subzone (e.g. api.devsecops.example.com, portal.sqa.example.com)
    for zone in clean_subzones[:12]:
        for s in clean_services:
            c = f"{s}.{zone}"
            if c not in known_hosts:
                candidates.add(c)
                if len(candidates) >= max_candidates:
                    return sorted(candidates)

    # Rule 2: Service + Tenant + Subzone (e.g. api.gilead.devsecops.example.com)
    for zone in clean_subzones[:8]:
        for t in clean_tenants[:12]:
            for s in clean_services[:25]:
                c = f"{s}.{t}.{zone}"
                if c not in known_hosts:
                    candidates.add(c)
                    if len(candidates) >= max_candidates:
                        return sorted(candidates)

    # Rule 3: Service + Tenant + Sandbox Variations (e.g. api.gsksandbox.example.com, app.bntsandbox.example.com)
    for t in clean_tenants[:10]:
        for suffix in ("sandbox", "sbx", "sbx2", "test", "dev", "qual"):
            compound_zone = f"{t}{suffix}.{clean_root}"
            for s in clean_services[:20]:
                c = f"{s}.{compound_zone}"
                if c not in known_hosts:
                    candidates.add(c)
                    if len(candidates) >= max_candidates:
                        return sorted(candidates)

    # Rule 4: Tenant direct subdomains (e.g. gilead.devsecops.example.com, otsuka.devsecops.example.com)
    for zone in clean_subzones[:8]:
        for t in clean_tenants[:15]:
            c = f"{t}.{zone}"
            if c not in known_hosts:
                candidates.add(c)
                if len(candidates) >= max_candidates:
                    return sorted(candidates)

    return sorted(candidates)


def _check_single_anycast(cand: str, session: Any) -> bool:
    """
    Fast-Path Anycast DNS pre-filter for multi-level subdomain candidates.
    Queries Tier-1 Anycast DoH (Google + Cloudflare fallback).
    Returns True ONLY if an Answer record is present.
    Returns False on confirmed NXDOMAIN (Status 3) or NODATA (Status 0 without Answer).
    """
    try:
        # Tier-1 Anycast Endpoint 1: Google Public DNS
        r = session.get(f"https://dns.google/resolve?name={cand}&type=A", timeout=1.5)
        if r.status_code == 200:
            d = r.json()
            st = d.get("Status")
            answers = d.get("Answer", [])
            if answers:
                return True
            if st == 3 or (st == 0 and not answers):  # Confirmed NXDOMAIN or NODATA
                return False
    except Exception:
        pass

    try:
        # Tier-1 Anycast Endpoint 2: Cloudflare 1.1.1.1 DoH Fallback
        r = session.get(f"https://cloudflare-dns.com/dns-query?name={cand}&type=A", timeout=1.5)
        if r.status_code == 200:
            d = r.json()
            st = d.get("Status")
            answers = d.get("Answer", [])
            if answers:
                return True
            if st == 3 or (st == 0 and not answers):
                return False
    except Exception:
        pass

    return False


def discover_nested_subdomains(
    root_domain: str,
    discovered_hosts: Iterable[str],
    max_candidates: int = 300,
    max_workers: int = 60,
    dns_resolver: str = "all",
    log_cb: Optional[Callable[[str], None]] = None,
    wildcard_info: Optional[Dict[str, Any]] = None
) -> Set[str]:
    """
    Executes automated recursive discovery:
    1. Extracts high-density sub-zones.
    2. Synthesizes multi-level tenant & service candidate permutations.
    3. Fast-Path: Pre-filters candidates via fast Anycast DNS to weed out confirmed NXDOMAINs.
    4. Concurrently resolves surviving candidates across the full multi-resolver suite.
    5. Returns verified live nested subdomains.
    """
    clean_root = root_domain.strip().lower().rstrip('.')
    if not clean_root:
        return set()

    subzones = extract_subzones(discovered_hosts, clean_root)
    if not subzones:
        if log_cb:
            log_cb("[NESTED] No multi-level subzones identified in initial seed set.")
        return set()

    top_subzones = [sz for sz, count in subzones[:10]]
    if log_cb:
        log_cb(f"[NESTED] Identified {len(subzones)} candidate sub-zone(s): {', '.join(top_subzones[:5])}")

    # Generate multi-level candidates based on learned naming patterns
    candidates = mine_nested_patterns(discovered_hosts, clean_root, max_candidates=max_candidates)
    if not candidates:
        return set()

    if log_cb:
        log_cb(f"[NESTED] Synthesized {len(candidates)} candidate permutations. Applying Fast-Path Anycast pre-filter...")

    # Fast-Path Anycast pre-filter with scaled HTTP connection pooling
    surviving_candidates: List[str] = []
    try:
        import requests
        from requests.adapters import HTTPAdapter
        with requests.Session() as s:
            adapter = HTTPAdapter(pool_connections=60, pool_maxsize=60, max_retries=1)
            s.mount("https://", adapter)
            s.mount("http://", adapter)
            s.headers.update({"Accept": "application/dns-json", "User-Agent": random_user_agent()})
            with ThreadPoolExecutor(max_workers=min(max_workers, 60)) as pre_pool:
                fut_map = {pre_pool.submit(_check_single_anycast, c, s): c for c in candidates}
                for f in as_completed(fut_map):
                    c = fut_map[f]
                    try:
                        if f.result():
                            surviving_candidates.append(c)
                    except Exception:
                        pass
    except Exception:
        surviving_candidates = []

    if not surviving_candidates:
        if log_cb:
            log_cb("[NESTED] Fast-Path Anycast pre-filter complete: 0 active permutations detected.")
        return set()

    if log_cb:
        log_cb(f"[NESTED-FASTPATH] {len(surviving_candidates)} high-signal candidate(s) advancing to multi-resolver verification...")

    live_nested: Set[str] = set()

    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(surviving_candidates)))) as pool:
        futures = {pool.submit(check_domain_multi_resolver, c, dns_resolver): c for c in surviving_candidates}
        for future in as_completed(futures):
            cand = futures[future]
            try:
                res = future.result()
                if res.get("status") == "resolved" and (res.get("ips") or res.get("cname")):
                    if wildcard_info and wildcard_info.get("is_wildcard"):
                        from enumerator.wildcard_detector import is_wildcard_false_positive
                        if is_wildcard_false_positive(res.get("ips", []), res.get("cname", ""), wildcard_info):
                            continue
                    live_nested.add(cand)
                    if log_cb:
                        resolver = res.get("resolver", "DNS")
                        ip_lead = res["ips"][0] if res.get("ips") else (f"CNAME: {res.get('cname')}" if res.get('cname') else "")
                        log_cb(f"[NESTED-FOUND] 🎯 {cand} -> Live on {ip_lead} (via {resolver})")
            except Exception:
                continue

    if log_cb:
        log_cb(f"[NESTED] Recursive scan finished. Discovered {len(live_nested)} new verified live nested subdomain(s)!")

    return live_nested

