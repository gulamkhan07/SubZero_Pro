"""
Reverse DNS (PTR) Subnet Sweeping Engine.
Takes discovered Origin IP addresses, groups them into /24 network subnets,
and performs concurrent reverse DNS lookups to uncover internal, unlisted,
and staging subdomains sharing the same infrastructure.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    import dns.reversename
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def lookup_ptr_single(ip: str, resolver_ip: Optional[str] = "1.1.1.1", timeout: float = 1.5) -> str:
    """Performs a single PTR lookup for an IP address."""
    clean_ip = (ip or "").strip()
    if not clean_ip:
        return ""

    if HAS_DNSPYTHON and resolver_ip:
        try:
            rev_name = dns.reversename.from_address(clean_ip)
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [resolver_ip]
            r.timeout = timeout
            r.lifetime = timeout
            ans = r.resolve(rev_name, "PTR")
            if ans:
                return str(ans[0].target).rstrip(".").strip().lower()
        except Exception:
            pass

    # Socket fallback
    try:
        host, _, _ = socket.gethostbyaddr(clean_ip)
        if host:
            return host.rstrip(".").strip().lower()
    except Exception:
        pass

    return ""


def get_surrounding_ips(ip_str: str, window: int = 15) -> List[str]:
    """Generates surrounding IPs in the same /24 subnet."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.version != 4:
            return [str(ip_obj)]
        net = ipaddress.ip_network(f"{ip_str.strip()}/24", strict=False)
        base_int = int(ip_obj)
        surrounding = []
        for offset in range(-window, window + 1):
            cand_int = base_int + offset
            cand_ip = ipaddress.ip_address(cand_int)
            if cand_ip in net and cand_ip != net.network_address and cand_ip != net.broadcast_address:
                surrounding.append(str(cand_ip))
        return surrounding
    except Exception:
        return [ip_str.strip()]


def sweep_ips_for_ptrs(
    ip_list: Iterable[str],
    target_domain: str,
    sweep_surrounding: bool = True,
    window: int = 10,
    resolver_ip: str = "1.1.1.1",
    max_workers: int = 25,
    timeout: float = 1.5
) -> Dict[str, Any]:
    """
    Performs multi-threaded reverse DNS sweep on provided IPs and optionally their
    surrounding /24 subnet neighborhood.
    Filters discovered hostnames matching target_domain.
    """
    clean_domain = target_domain.strip().lower().rstrip(".")
    initial_ips = list(set(ip.strip() for ip in ip_list if ip and ip.strip()))

    probe_set: Set[str] = set()
    for ip in initial_ips:
        if sweep_surrounding:
            for s_ip in get_surrounding_ips(ip, window=window):
                probe_set.add(s_ip)
        else:
            probe_set.add(ip)

    ptr_records: Dict[str, str] = {}
    discovered_subdomains: Set[str] = set()

    workers = min(len(probe_set), max_workers) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(lookup_ptr_single, ip, resolver_ip, timeout): ip
            for ip in probe_set
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                hostname = future.result()
                if hostname:
                    ptr_records[ip] = hostname
                    if hostname == clean_domain or hostname.endswith("." + clean_domain):
                        if hostname != clean_domain:
                            discovered_subdomains.add(hostname)
            except Exception:
                pass

    return {
        "target_domain": clean_domain,
        "ips_checked": len(probe_set),
        "ptr_records_found": len(ptr_records),
        "discovered_subdomains": sorted(discovered_subdomains),
        "ptr_map": ptr_records
    }
