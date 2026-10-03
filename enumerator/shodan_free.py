"""
Shodan Free InternetDB Subdomain Harvester for SubZero
Extracts exclusively subdomains from Shodan's free, public
InternetDB API (https://internetdb.shodan.io/) without any paid keys,
ignoring open ports, vulnerabilities, and irrelevant metadata.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Set
import requests

from enumerator.request_utils import random_user_agent

SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
TIMEOUT = 4.0


def query_shodan_ip(ip: str, timeout: float = TIMEOUT) -> Optional[List[str]]:
    """
    Queries Shodan InternetDB for a single IP address and returns its raw hostnames list.
    Ignores ports, CVEs, and other metadata.
    """
    clean_ip = ip.strip()
    if not clean_ip:
        return None
    url = SHODAN_INTERNETDB_URL.format(ip=clean_ip)
    headers = {
        "User-Agent": random_user_agent(),
        "Accept": "application/json"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                return data.get('hostnames') or []
    except Exception:
        pass
    return None


def harvest_shodan_internetdb(
    ips: Iterable[str],
    target_domain: str,
    max_workers: int = 15,
    timeout: float = TIMEOUT
) -> Dict[str, Any]:
    """
    Concurrently queries Shodan InternetDB across provided IPs.
    Extracts strictly target subdomains, discarding open ports and CVEs.

    Returns:
        {
            'subdomains': sorted list of discovered subdomains,
            'total_discovered': int,
            'total_queried': int
        }
    """
    clean_domain = target_domain.strip().lower().rstrip('.')
    unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if ip and ip.strip()))

    discovered_subs: Set[str] = set()

    if not unique_ips or not clean_domain:
        return {
            'subdomains': [],
            'total_discovered': 0,
            'total_queried': 0
        }

    with ThreadPoolExecutor(max_workers=min(max_workers, len(unique_ips))) as executor:
        futures = {executor.submit(query_shodan_ip, ip, timeout): ip for ip in unique_ips}
        for future in as_completed(futures):
            try:
                hostnames = future.result()
                if not hostnames or not isinstance(hostnames, list):
                    continue

                for h in hostnames:
                    if not isinstance(h, str):
                        continue
                    clean_host = h.strip().lower().rstrip('.')
                    if clean_host == clean_domain or clean_host.endswith('.' + clean_domain):
                        discovered_subs.add(clean_host)
            except Exception:
                continue

    return {
        'subdomains': sorted(discovered_subs),
        'total_discovered': len(discovered_subs),
        'total_queried': len(unique_ips)
    }
