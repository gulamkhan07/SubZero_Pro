"""
DNS Zone Transfer (AXFR) Pre-Flight Auditor for SubZero
Audits authoritative nameservers for DNS Zone Transfer misconfigurations (RFC 5936).
If a zone transfer is allowed, 100% of internal and external DNS records are extracted instantly.
Developed by: Gulam
"""
__author__ = "Gulam"

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.query
import dns.resolver
import dns.zone
from enumerator.normalizer import normalize_subdomains, valid_domain


def _test_nameserver_axfr(
    domain: str,
    ns_host: str,
    ns_ip: str,
    timeout: float = 2.5
) -> Tuple[str, str, bool, List[str], Optional[str]]:
    """Attempts a DNS zone transfer against a specific nameserver IP."""
    try:
        xfr = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout)
        z = dns.zone.from_xfr(xfr)
        raw_names: List[str] = []
        for node in z.nodes.keys():
            n_str = str(node).strip()
            if n_str in ('@', ''):
                raw_names.append(domain)
            else:
                raw_names.append(f"{n_str}.{domain}")

        clean_subs = sorted(normalize_subdomains(raw_names, domain))
        if clean_subs:
            return ns_host, ns_ip, True, clean_subs, None
        return ns_host, ns_ip, False, [], "Empty zone payload"
    except Exception as exc:
        return ns_host, ns_ip, False, [], type(exc).__name__


def check_zone_transfer(
    domain: str,
    timeout: float = 2.5,
    max_workers: int = 6
) -> Dict[str, Any]:
    """
    Performs rapid, non-intrusive DNS Zone Transfer (AXFR) audit against
    all authoritative Name Servers configured for the target root domain.

    Returns:
        Dict containing vulnerability status, vulnerable nameservers,
        and all extracted subdomains if open.
    """
    t0 = time.time()
    root = domain.strip().lower().rstrip('.')
    if not valid_domain(root):
        return {
            'developed_by': 'Gulam',
            'domain': root,
            'is_vulnerable': False,
            'vulnerable': False,
            'vulnerable_nameservers': [],
            'tested_nameservers': [],
            'subdomains': [],
            'total_subdomains': 0,
            'evidence': 'Invalid root domain',
            'duration': 0.0
        }

    # Resolve authoritative NS records for root domain
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        ns_ans = resolver.resolve(root, 'NS')
        ns_hosts = sorted({str(r.target).rstrip('.').lower() for r in ns_ans})
    except Exception as exc:
        return {
            'developed_by': 'Gulam',
            'domain': root,
            'is_vulnerable': False,
            'vulnerable': False,
            'vulnerable_nameservers': [],
            'tested_nameservers': [],
            'subdomains': [],
            'total_subdomains': 0,
            'evidence': f"Authoritative NS resolution failed: {exc}",
            'duration': round(time.time() - t0, 2)
        }

    # Resolve IP addresses for all authoritative nameservers
    targets_to_probe: List[Tuple[str, str]] = []
    tested_nameservers: List[Dict[str, str]] = []

    for ns in ns_hosts:
        try:
            ip_ans = resolver.resolve(ns, 'A')
            for rr in ip_ans:
                ip_str = str(rr.address)
                targets_to_probe.append((ns, ip_str))
                tested_nameservers.append({'nameserver': ns, 'ip': ip_str})
        except Exception:
            continue

    if not targets_to_probe:
        return {
            'developed_by': 'Gulam',
            'domain': root,
            'is_vulnerable': False,
            'vulnerable': False,
            'vulnerable_nameservers': [],
            'tested_nameservers': tested_nameservers,
            'subdomains': [],
            'total_subdomains': 0,
            'evidence': 'No reachable nameserver IPs identified',
            'duration': round(time.time() - t0, 2)
        }

    vulnerable_ns: List[Dict[str, Any]] = []
    discovered_subdomains: Set[str] = set()

    workers = min(len(targets_to_probe), max_workers) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_test_nameserver_axfr, root, ns, ip, timeout): (ns, ip)
            for ns, ip in targets_to_probe
        }
        for future in as_completed(futures):
            ns_host, ns_ip, success, subs, err = future.result()
            if success and subs:
                vulnerable_ns.append({
                    'nameserver': ns_host,
                    'ip': ns_ip,
                    'records_count': len(subs)
                })
                discovered_subdomains.update(subs)

    is_vulnerable = len(vulnerable_ns) > 0
    evidence = (
        f"Open zone transfer confirmed on {len(vulnerable_ns)} authoritative nameserver(s)!"
        if is_vulnerable
        else f"Zone transfer rejected across {len(tested_nameservers)} nameserver IP(s) (Standard/Secure)."
    )

    all_subs = sorted(discovered_subdomains)
    return {
        'developed_by': 'Gulam',
        'domain': root,
        'is_vulnerable': is_vulnerable,
        'vulnerable': is_vulnerable,
        'vulnerable_nameservers': vulnerable_ns,
        'tested_nameservers': tested_nameservers,
        'subdomains': all_subs,
        'total_subdomains': len(all_subs),
        'evidence': evidence,
        'duration': round(time.time() - t0, 2)
    }
