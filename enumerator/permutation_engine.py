"""
Subdomain Permutation & Mutation Engine.
Generates intelligent candidate mutations and permutations based on discovered seed subdomains
and resolves them using multi-resolver DNS to uncover hidden development, staging, and internal assets.
Developed by: Gulam
"""
__author__ = "Gulam"

import re
import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Any, Tuple, Optional
from enumerator.dns_resolver import check_domain_multi_resolver

# Common environment and service prefixes/suffixes used for mutations
ENVIRONMENT_WORDS = [
    "dev", "devel", "development", "stage", "staging", "test", "testing",
    "uat", "qa", "prod", "production", "internal", "corp", "admin", "priv",
    "private", "sandbox", "demo", "preview", "review", "lab", "poc", "beta", "alpha"
]

SERVICE_WORDS = [
    "api", "v1", "v2", "v3", "auth", "login", "sso", "portal", "gateway",
    "gw", "vpn", "proxy", "waf", "cdn", "static", "assets", "media", "img",
    "files", "docs", "app", "apps", "web", "mail", "secure", "status", "monitor"
]

NUMERIC_SUFFIXES = ["1", "2", "3", "01", "02"]
DELIMITERS = ["-", ""]


def generate_permutations(
    root_domain: str,
    seeds: List[str],
    custom_words: Optional[List[str]] = None,
    max_candidates: int = 500,
    **kwargs
) -> List[Dict[str, str]]:
    """
    Generates intelligent mutation candidate subdomains based on seed hosts.
    Returns a list of dicts: {'candidate': hostname, 'rule': mutation_rule, 'source_seed': seed}
    """
    if 'max_results' in kwargs:
        max_candidates = kwargs.pop('max_results')
    root = root_domain.strip().lower().rstrip('.')
    if not root:
        return []

    word_pool = set(ENVIRONMENT_WORDS + SERVICE_WORDS)
    if custom_words:
        word_pool.update(w.strip().lower() for w in custom_words if w.strip())

    candidates: Dict[str, Tuple[str, str]] = {}  # candidate -> (rule, seed)

    # Clean seeds and extract sub-prefixes
    clean_prefixes = set()
    for s in seeds:
        s = s.strip().lower().rstrip('.')
        if not s:
            continue
        if s == root:
            continue
        if s.endswith("." + root):
            prefix = s[:-len("." + root)]
        else:
            prefix = s
        
        # Split multipart prefix e.g. api-dev, api.staging
        parts = re.split(r'[\.\-_]', prefix)
        for p in parts:
            if p and len(p) >= 2 and p.isalnum():
                clean_prefixes.add(p)
        if prefix and len(prefix) >= 2:
            clean_prefixes.add(prefix)

    # If no valid seed prefixes provided, seed with common base services
    if not clean_prefixes:
        clean_prefixes = {"api", "dev", "app", "admin", "vpn", "mail", "portal", "test", "stage"}

    sorted_prefixes = sorted(clean_prefixes)
    sorted_words = sorted(word_pool)

    # Rule 1: Prefix / Suffix insertions with delimiters (Interleaved for fair representation)
    for delim in DELIMITERS:
        for word in sorted_words:
            for prefix in sorted_prefixes:
                if prefix == word:
                    continue

                # Prefix + Delimiter + Word e.g. api-dev.target.com
                c1 = f"{prefix}{delim}{word}.{root}"
                if c1 not in candidates:
                    candidates[c1] = (f"prefix-delim-word ({prefix}+{delim}+{word})", prefix)
                if len(candidates) >= max_candidates:
                    break

                # Word + Delimiter + Prefix e.g. dev-api.target.com
                c2 = f"{word}{delim}{prefix}.{root}"
                if c2 not in candidates:
                    candidates[c2] = (f"word-delim-prefix ({word}+{delim}+{prefix})", prefix)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    # Rule 2: Numeric permutations e.g. api1, api-01, dev2
    if len(candidates) < max_candidates:
        for num in NUMERIC_SUFFIXES:
            for delim in ["", "-"]:
                for prefix in sorted_prefixes:
                    c = f"{prefix}{delim}{num}.{root}"
                    if c not in candidates:
                        candidates[c] = (f"numeric-suffix ({prefix}+{delim}+{num})", prefix)
                    if len(candidates) >= max_candidates:
                        break
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break

    # Rule 3: Subdomain level depth mutation e.g. dev.api.target.com
    if len(candidates) < max_candidates:
        for env in ["dev", "stage", "test", "uat", "admin", "internal"]:
            for prefix in sorted_prefixes:
                if prefix == env:
                    continue
                c = f"{env}.{prefix}.{root}"
                if c not in candidates:
                    candidates[c] = (f"depth-level ({env}.{prefix})", prefix)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break

    result = []
    for cand, (rule, seed) in list(candidates.items())[:max_candidates]:
        result.append({
            "candidate": cand,
            "rule": rule,
            "seed": seed
        })
    return result


def check_wildcard_for_root(domain: str) -> bool:
    """Detects if root domain has a wildcard DNS record (*.domain.com).
    Uses the robust multi-probe wildcard detector which avoids false positives
    from ISP captive portals and search redirect DNS.
    """
    try:
        from enumerator.wildcard_detector import detect_wildcard_dns
        result = detect_wildcard_dns(domain, num_probes=2, timeout=1.5)
        return result.get("is_wildcard", False)
    except Exception:
        # Fallback to simple socket probe if wildcard_detector is unavailable
        probe = f"wildcard-perm-{uuid.uuid4().hex[:12]}.{domain}"
        try:
            socket.getaddrinfo(probe, None)
            return True
        except socket.gaierror:
            return False
        except Exception:
            return False


def scan_permutations(
    root_domain: str,
    seeds: List[str],
    custom_words: Optional[List[str]] = None,
    max_candidates: int = 300,
    max_workers: int = 30,
    specific_resolver: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates and actively scans permutations with concurrent multi-resolver verification.
    """
    t0 = time.time()
    domain = root_domain.strip().lower().rstrip('.')
    is_wildcard = check_wildcard_for_root(domain)

    candidates = generate_permutations(domain, seeds, custom_words=custom_words, max_candidates=max_candidates)
    total_candidates = len(candidates)

    if not candidates:
        return {
            "developed_by": "Gulam",
            "domain": domain,
            "is_wildcard": is_wildcard,
            "total_candidates": 0,
            "total_live": 0,
            "duration": 0,
            "results": []
        }

    results = []
    live_count = 0

    def _resolve_candidate(item):
        host = item["candidate"]
        res = check_domain_multi_resolver(host, specific_resolver=specific_resolver, timeout=1.5)
        return {
            "host": host,
            "rule": item["rule"],
            "seed": item["seed"],
            "alive": res.get("alive", False),
            "status": res.get("status", "unresolved"),
            "resolver": res.get("resolver", "None"),
            "ips": res.get("ips", []),
            "summary": res.get("summary", "")
        }

    with ThreadPoolExecutor(max_workers=min(max_workers, total_candidates)) as executor:
        futures = [executor.submit(_resolve_candidate, item) for item in candidates]
        for f in as_completed(futures):
            try:
                r = f.result()
                if r["alive"]:
                    live_count += 1
                results.append(r)
            except Exception:
                continue

    # Sort results: live ones first, then alphabetical
    results.sort(key=lambda x: (not x["alive"], x["host"]))

    return {
        "developed_by": "Gulam",
        "domain": domain,
        "is_wildcard": is_wildcard,
        "total_candidates": total_candidates,
        "total_live": live_count,
        "duration": round(time.time() - t0, 2),
        "results": results
    }
