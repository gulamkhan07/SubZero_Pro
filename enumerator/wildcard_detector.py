"""
DNS Wildcard Detection & False-Positive Filter.
Detects if a domain utilizes wildcard DNS records (*.domain.com) and filters out
bogus subdomains that only resolve to catch-all wildcard IP addresses.
"""
__author__ = "SubZero Community"

import random
import socket
import string
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def _generate_random_subdomain(domain: str, length: int = 16) -> str:
    """Generates a random non-existent subdomain name."""
    chars = string.ascii_lowercase + string.digits
    rand_prefix = "sz-wc-" + "".join(random.choice(chars) for _ in range(length))
    return f"{rand_prefix}.{domain.strip().lower().rstrip('.')}"


def _resolve_candidate(host: str, resolver_ip: Optional[str] = "1.1.1.1", timeout: float = 1.5) -> Tuple[List[str], str]:
    """Resolves host and returns (list_of_ips, cname)."""
    ips: List[str] = []
    cname: str = ""
    dnspython_definitive = False  # True if dnspython gave a definitive answer (NXDOMAIN/resolved)

    if HAS_DNSPYTHON and resolver_ip:
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [resolver_ip]
            r.timeout = timeout
            r.lifetime = timeout

            try:
                ans = r.resolve(host, "A")
                if getattr(ans, 'canonical_name', None):
                    cname = str(getattr(ans.canonical_name, 'to_text', lambda: ans.canonical_name)()).rstrip(".")
                for rr in ans:
                    ips.append(rr.address)
                dnspython_definitive = True
                return sorted(set(ips)), cname
            except dns.resolver.NXDOMAIN:
                # Domain definitively does not exist — do NOT fall through to socket
                dnspython_definitive = True
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass

            # Try CNAME directly if no A record (and not NXDOMAIN)
            if not dnspython_definitive:
                try:
                    ans_cname = r.resolve(host, "CNAME")
                    if ans_cname:
                        cname = ans_cname[0].target.to_text().rstrip(".")
                        dnspython_definitive = True
                except dns.resolver.NXDOMAIN:
                    dnspython_definitive = True
                except Exception:
                    pass
        except Exception:
            pass

    # Socket fallback — ONLY if dnspython did not give a definitive answer
    # This prevents ISP captive portals / search redirect DNS from causing false wildcards
    if not dnspython_definitive:
        try:
            _, _, ip_list = socket.gethostbyname_ex(host)
            if ip_list:
                ips.extend(ip_list)
        except Exception:
            pass

    return sorted(set(ips)), cname


def detect_wildcard_dns(
    domain: str,
    resolver_ip: str = "1.1.1.1",
    num_probes: int = 3,
    timeout: float = 1.5
) -> Dict[str, Any]:
    """
    Tests if domain has an active wildcard DNS record by probing multiple
    randomly generated non-existent subdomains.
    Returns detailed wildcard profile dictionary.
    """
    clean_domain = domain.strip().lower().rstrip(".")
    probe_results = []
    all_resolved_ips: Set[str] = set()
    detected_cnames: Set[str] = set()

    for _ in range(num_probes):
        rand_host = _generate_random_subdomain(clean_domain)
        ips, cname = _resolve_candidate(rand_host, resolver_ip=resolver_ip, timeout=timeout)
        probe_results.append({
            "host": rand_host,
            "ips": ips,
            "cname": cname,
            "resolved": bool(ips or cname)
        })
        if ips:
            all_resolved_ips.update(ips)
        if cname:
            detected_cnames.add(cname)

    # If all probes resolved, wildcard DNS is definitively active
    resolved_count = sum(1 for p in probe_results if p["resolved"])
    is_wildcard = (resolved_count == num_probes and (bool(all_resolved_ips) or bool(detected_cnames)))

    return {
        "domain": clean_domain,
        "is_wildcard": is_wildcard,
        "wildcard_ips": sorted(all_resolved_ips),
        "wildcard_cnames": sorted(detected_cnames),
        "probes_tested": num_probes,
        "probes_resolved": resolved_count,
        "checked_resolver": resolver_ip
    }


def is_wildcard_false_positive(
    resolved_ips: List[str],
    cname: str,
    wildcard_info: Optional[Dict[str, Any]]
) -> bool:
    """
    Determines if a discovered subdomain resolution is merely a wildcard false-positive
    pointing to the same catch-all wildcard infrastructure.
    """
    if not wildcard_info or not wildcard_info.get("is_wildcard"):
        return False

    wc_ips = set(wildcard_info.get("wildcard_ips", []))
    wc_cnames = set(wildcard_info.get("wildcard_cnames", []))

    sub_ips = set(ip.strip() for ip in (resolved_ips or []) if ip and ip.strip())
    sub_cname = (cname or "").strip().lower().rstrip(".")

    # If subdomain has no unique IPs outside the wildcard IP set
    if sub_ips and wc_ips and sub_ips.issubset(wc_ips):
        return True

    # If subdomain has CNAME matching wildcard CNAME
    if sub_cname and wc_cnames and sub_cname in wc_cnames:
        return True

    return False
