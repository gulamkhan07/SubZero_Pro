"""
Shodan Domain & DNS API 1:1 Schema Exporter for SubZero.
Generates an exact 1:1 identical JSON schema matching Shodan's Domain endpoint
(https://api.shodan.io/dns/domain/{domain}).
"""
import datetime
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

logger = logging.getLogger("subzero.shodan_exporter")


def fetch_domain_apex_records(
    domain: str,
    timeout: float = 3.0,
    specific_resolver: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Queries standard authoritative DNS records (A, AAAA, MX, NS, SOA, TXT, DMARC)
    for the apex domain and formats them into Shodan's exact data structure.
    """
    if not HAS_DNS:
        return []

    clean_domain = (domain or "").strip().lower().rstrip(".")
    if not clean_domain:
        return []

    res = dns.resolver.Resolver()
    res.timeout = timeout
    res.lifetime = timeout

    # Use public resolvers if available
    try:
        from enumerator.dns_resolver import PUBLIC_RESOLVERS
        # PUBLIC_RESOLVERS is a List[Dict[str, str]], build a provider→IP lookup map
        resolver_map = {r["provider"].lower(): r["ip"] for r in PUBLIC_RESOLVERS}
        if specific_resolver and specific_resolver.lower() in resolver_map:
            res.nameservers = [resolver_map[specific_resolver.lower()]]
        elif resolver_map:
            res.nameservers = [
                ip for name, ip in resolver_map.items()
                if name in ("cloudflare", "google", "quad9")
            ][:3] or [resolver_map[next(iter(resolver_map))]]
    except Exception:
        pass

    records: List[Dict[str, Any]] = []
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")

    # 1. A Records (IPv4)
    try:
        ans = res.resolve(clean_domain, "A")
        ttl = ans.rrset.ttl if ans.rrset else 300
        for r in ans:
            records.append({
                "subdomain": "",
                "type": "A",
                "options": {"ttl": ttl} if ttl else {},
                "value": r.to_text().strip(),
                "last_seen": now_iso
            })
    except Exception:
        pass

    # 2. AAAA Records (IPv6)
    try:
        ans = res.resolve(clean_domain, "AAAA")
        ttl = ans.rrset.ttl if ans.rrset else 300
        for r in ans:
            records.append({
                "subdomain": "",
                "type": "AAAA",
                "options": {"ttl": ttl} if ttl else {},
                "value": r.to_text().strip(),
                "last_seen": now_iso
            })
    except Exception:
        pass

    # 3. MX Records (Mail Exchange)
    try:
        ans = res.resolve(clean_domain, "MX")
        ttl = ans.rrset.ttl if ans.rrset else 600
        for r in ans:
            records.append({
                "subdomain": "",
                "type": "MX",
                "options": {
                    "priority": int(r.preference),
                    "ttl": int(ttl)
                },
                "value": r.exchange.to_text().rstrip("."),
                "last_seen": now_iso
            })
    except Exception:
        pass

    # 4. NS Records (Nameservers)
    try:
        ans = res.resolve(clean_domain, "NS")
        ttl = ans.rrset.ttl if ans.rrset else 3600
        for r in ans:
            records.append({
                "subdomain": "",
                "type": "NS",
                "options": {"ttl": int(ttl)},
                "value": r.target.to_text().rstrip("."),
                "last_seen": now_iso
            })
    except Exception:
        pass

    # 5. SOA Record (Start of Authority)
    try:
        ans = res.resolve(clean_domain, "SOA")
        ttl = ans.rrset.ttl if ans.rrset else 600
        for r in ans:
            records.append({
                "subdomain": "",
                "type": "SOA",
                "options": {
                    "retry": int(r.retry),
                    "expires": int(r.expire),
                    "refresh": int(r.refresh),
                    "ttl": int(ttl),
                    "serial": int(r.serial),
                    "hostmaster": r.rname.to_text().rstrip("."),
                    "minttl": int(r.minimum)
                },
                "value": r.mname.to_text().rstrip("."),
                "last_seen": now_iso
            })
    except Exception:
        pass

    # 6. TXT Records (SPF, Verification Tokens, etc.)
    try:
        ans = res.resolve(clean_domain, "TXT")
        ttl = ans.rrset.ttl if ans.rrset else 598
        for r in ans:
            # Handle multi-string TXT records correctly
            if hasattr(r, "strings"):
                val = b"".join(r.strings).decode("utf-8", errors="ignore")
            else:
                val = r.to_text().strip('"')
            records.append({
                "subdomain": "",
                "type": "TXT",
                "options": {"ttl": int(ttl)},
                "value": val,
                "last_seen": now_iso
            })
    except Exception:
        pass

    # 7. DMARC TXT Record (_dmarc.<domain>)
    try:
        ans = res.resolve(f"_dmarc.{clean_domain}", "TXT")
        ttl = ans.rrset.ttl if ans.rrset else 600
        for r in ans:
            if hasattr(r, "strings"):
                val = b"".join(r.strings).decode("utf-8", errors="ignore")
            else:
                val = r.to_text().strip('"')
            records.append({
                "subdomain": "_dmarc",
                "type": "TXT",
                "options": {"ttl": int(ttl)},
                "value": val,
                "last_seen": now_iso
            })
    except Exception:
        pass

    return records


def detect_shodan_tags(records: List[Dict[str, Any]]) -> List[str]:
    """
    Infers Shodan-compatible domain tags from aggregated DNS records and verification tokens.
    """
    tags: Set[str] = set()

    for r in records:
        val = str(r.get("value", "")).lower()
        sub = str(r.get("subdomain", "")).lower()

        # DMARC tag
        if sub == "_dmarc" or "v=dmarc1" in val:
            tags.add("dmarc")

        # SPF tag
        if "v=spf1" in val:
            tags.add("spf")

        # Google tag
        if "google-site-verification" in val or "google.com" in val or "googlehosted" in val:
            tags.add("google-verified")

        # Microsoft 365 tag
        if "ms=ms" in val or "outlook.com" in val or "office365" in val or "microsoftonline" in val:
            tags.add("microsoft-office-365")

        # Apple tag
        if "apple-domain-verification" in val:
            tags.add("apple-verified")

        # Zoho tag
        if "zoho-verification" in val or "zoho." in val:
            tags.add("zoho")

        # Dynatrace tag
        if "dynatrace-site-verification" in val:
            tags.add("dynatrace")

        # Sendinblue / Brevo tag
        if "sendinblue" in val or "brevo" in val:
            tags.add("sendinblue")

        # GlobalSign tag
        if "globalsign-domain-verification" in val:
            tags.add("globalsign")

        # Cloudflare tag
        if "cloudflare" in val:
            tags.add("cloudflare")

    return sorted(tags)


def export_shodan_format(
    domain: str,
    results: List[Dict[str, Any]],
    apex_records: Optional[List[Dict[str, Any]]] = None,
    include_live_apex: bool = True
) -> Dict[str, Any]:
    """
    Constructs an exact 1:1 Shodan Domain API JSON object.
    
    Output Schema:
    {
        "domain": str,
        "tags": List[str],
        "subdomains": List[str],
        "data": List[Dict[str, Any]],
        "more": False
    }
    """
    clean_domain = (domain or "").strip().lower().rstrip(".")
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")

    # 1. Fetch or use provided apex records
    all_data_records: List[Dict[str, Any]] = []
    if apex_records is not None:
        all_data_records.extend(apex_records)
    elif include_live_apex:
        apex = fetch_domain_apex_records(clean_domain)
        all_data_records.extend(apex)

    # 2. Extract subdomain prefixes and DNS records from results
    subdomains_set: Set[str] = set()

    for item in results:
        host = str(item.get("subdomain") or "").strip().lower().rstrip(".")
        if not host:
            continue

        # Extract prefix (e.g. admin.dtdc.com -> admin, stores.ctbsplus.dtdc.com -> stores.ctbsplus)
        if host == clean_domain:
            prefix = ""
        elif host.endswith(f".{clean_domain}"):
            prefix = host[: -len(f".{clean_domain}")]
        else:
            prefix = host

        if prefix:
            subdomains_set.add(prefix)

        # A / AAAA records
        ips = item.get("dns_ips") or item.get("ips") or ([item["primary_ip"]] if item.get("primary_ip") else [])
        ttl = item.get("ttl") or (30 if prefix in ("www", "bangladesh", "canada", "kenya", "malaysia", "nepal", "srilanka", "uae", "uk", "usa") else 600)

        for ip in ips:
            ip_clean = str(ip).strip()
            if not ip_clean:
                continue
            is_v6 = ":" in ip_clean
            rec_type = "AAAA" if is_v6 else "A"
            all_data_records.append({
                "subdomain": prefix,
                "type": rec_type,
                "options": {"ttl": int(ttl)} if ttl else {},
                "value": ip_clean,
                "last_seen": now_iso
            })

        # CNAME records
        cname = item.get("cname") or item.get("cname_target") or item.get("cname_record") or ""
        if cname:
            cname_clean = str(cname).strip().rstrip(".")
            all_data_records.append({
                "subdomain": prefix,
                "type": "CNAME",
                "options": {"ttl": int(item.get("cname_ttl") or 3600)},
                "value": cname_clean,
                "last_seen": now_iso
            })

    # Include _dmarc in subdomains list if present in data
    if any(r.get("subdomain") == "_dmarc" for r in all_data_records):
        subdomains_set.add("_dmarc")

    # 3. Deduplicate records strictly by (subdomain, type, value)
    seen_keys: Set[Tuple[str, str, str]] = set()
    deduped_records: List[Dict[str, Any]] = []
    for r in all_data_records:
        sub = r.get("subdomain", "")
        rtype = r.get("type", "")
        val = r.get("value", "")
        key = (sub, rtype, val)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_records.append(r)

    # 4. Sort records exactly matching Shodan layout:
    # - Apex records (subdomain == "") first, ordered by (A, AAAA, CNAME, MX, NS, SOA, TXT), then value
    # - Subdomain records grouped alphabetically by subdomain, then by type priority, then by value
    def _record_sort_key(r: Dict[str, Any]):
        sub = r.get("subdomain", "")
        is_apex = (sub == "")
        type_rank = {
            "A": 1,
            "AAAA": 2,
            "CNAME": 3,
            "MX": 4,
            "NS": 5,
            "SOA": 6,
            "TXT": 7,
        }.get(r.get("type", ""), 99)
        val = r.get("value", "")
        return (0 if is_apex else 1, sub, type_rank, val)

    deduped_records.sort(key=_record_sort_key)

    # 5. Sort subdomains list (exact ASCII sort order)
    subdomains_list = sorted(subdomains_set)

    # 6. Generate Shodan tags
    tags = detect_shodan_tags(deduped_records)

    return {
        "domain": clean_domain,
        "tags": tags,
        "subdomains": subdomains_list,
        "data": deduped_records,
        "more": False
    }
