"""
SubZero Result Filtering and Live/Dead Classification Service.
"""
__author__ = "SubZero Community"

from typing import Any, Dict, List


def _is_result_live(r: Dict[str, Any]) -> bool:
    """Returns True if the subdomain record resolved to live DNS/IP."""
    if r.get('is_wildcard_catchall') or r.get('dns') == 'wildcard-catchall' or r.get('is_dead') is True:
        return False
    if r.get('is_live') is True:
        return True
    if r.get('dns') in ('unresolved', 'nxdomain'):
        return False
    return bool(r.get('dns_ips') or r.get('primary_ip') or r.get('dns') == 'resolved')


def _is_result_dead(r: Dict[str, Any]) -> bool:
    """Returns True if the subdomain record failed DNS resolution or is unresolvable."""
    return not _is_result_live(r)


def _filter_results(
    results: List[Dict[str, Any]],
    status_filter: str = 'all',
    query: str = ''
) -> List[Dict[str, Any]]:
    """Filters results by status (all, live, dead) and optional search query."""
    status = (status_filter or 'all').strip().lower()
    if status == 'live':
        filtered = [r for r in results if _is_result_live(r)]
    elif status == 'dead':
        filtered = [r for r in results if _is_result_dead(r)]
    else:
        filtered = list(results)

    if query:
        q = query.strip().lower()
        filtered = [
            r for r in filtered
            if q in r.get('subdomain', '').lower()
            or q in (r.get('primary_ip') or '').lower()
            or q in (r.get('waf_provider') or '').lower()
        ]

    return filtered
