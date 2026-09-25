"""
DNS Asset Integrity & Dangling CNAME Auditor.
Performs defensive auditing of DNS CNAME pointers against known cloud asset signatures
(AWS S3, GitHub Pages, Heroku, Azure, Shopify, Zendesk, Fastly, etc.) to detect misconfigurations.
Developed by: Gulam
"""
__author__ = "Gulam"

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket
import urllib3

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known Cloud Service Signatures for Defensive Asset Auditing
SERVICE_SIGNATURES = [
    {
        "service": "AWS S3",
        "cname_patterns": [r"s3[\.\-]website[\.\-].*\.amazonaws\.com", r".*\.s3\.amazonaws\.com"],
        "fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
        "remediation": "Remove the dangling CNAME from DNS or claim the S3 bucket in your AWS account."
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": [r".*\.github\.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "404 - Not Found"],
        "remediation": "Remove the CNAME pointing to github.io or configure custom domain in your GitHub repository."
    },
    {
        "service": "Heroku",
        "cname_patterns": [r".*\.herokudns\.com", r".*\.herokuapp\.com"],
        "fingerprints": ["No such app", "Heroku | No such app"],
        "remediation": "Delete DNS CNAME pointing to heroku or attach the domain to an active Heroku app."
    },
    {
        "service": "Microsoft Azure",
        "cname_patterns": [r".*\.azurewebsites\.net", r".*\.cloudapp\.net"],
        "fingerprints": ["404 Web Site not found", "Web App - Unavailable"],
        "remediation": "Remove unlinked Azure CNAME from your DNS zone."
    },
    {
        "service": "Shopify",
        "cname_patterns": [r".*\.myshopify\.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "remediation": "Remove Shopify CNAME or reconnect your domain in Shopify admin."
    },
    {
        "service": "Zendesk",
        "cname_patterns": [r".*\.zendesk\.com"],
        "fingerprints": ["Help Center Closed"],
        "remediation": "Update Zendesk host mapping or delete the obsolete CNAME."
    },
    {
        "service": "Fastly",
        "cname_patterns": [r".*\.fastly\.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "remediation": "Add domain to active Fastly service or remove CNAME."
    },
    {
        "service": "Pantheon",
        "cname_patterns": [r".*\.pantheonsite\.io"],
        "fingerprints": ["404 error unknown site"],
        "remediation": "Remove decommissioned Pantheon CNAME."
    },
    {
        "service": "Surge.sh",
        "cname_patterns": [r".*\.surge\.sh"],
        "fingerprints": ["project not found"],
        "remediation": "Remove surge.sh CNAME or deploy your project."
    },
    {
        "service": "Bitbucket",
        "cname_patterns": [r".*\.bitbucket\.io"],
        "fingerprints": ["Repository not found"],
        "remediation": "Configure repository or delete dangling Bitbucket pointer."
    }
]


def resolve_cname(host: str) -> str:
    """
    Resolves the canonical name (CNAME) for a given hostname.
    Uses dnspython if available, with socket fallback.
    """
    host = host.strip().lower()
    if HAS_DNSPYTHON:
        for ns in [None, ['1.1.1.1'], ['8.8.8.8']]:
            try:
                resolver = dns.resolver.Resolver(configure=(ns is None))
                if ns:
                    resolver.nameservers = ns
                resolver.timeout = 2.0
                resolver.lifetime = 2.0
                answers = resolver.resolve(host, 'CNAME')
                for rdata in answers:
                    return rdata.target.to_text().rstrip('.')
            except Exception:
                continue

    # Socket fallback
    try:
        cname, _, _ = socket.gethostbyname_ex(host)
        if cname and cname.lower() != host:
            return cname.lower().rstrip('.')
    except Exception:
        pass

    return ""


def _audit_single_host(host: str) -> dict:
    host = host.strip().lower()
    if not host:
        return {}

    cname = resolve_cname(host)
    if not cname:
        return {
            "host": host,
            "cname": "None (Direct A/AAAA)",
            "service": "Internal / Direct",
            "status": "safe",
            "status_label": "Direct Record",
            "evidence": "No external CNAME alias detected.",
            "remediation": "None required."
        }

    # Match CNAME against cloud service patterns
    matched_rule = None
    for rule in SERVICE_SIGNATURES:
        for pattern in rule["cname_patterns"]:
            if re.search(pattern, cname, re.IGNORECASE):
                matched_rule = rule
                break
        if matched_rule:
            break

    if not matched_rule:
        return {
            "host": host,
            "cname": cname,
            "service": "Third-Party CNAME",
            "status": "info",
            "status_label": "Active CNAME",
            "evidence": f"Points to {cname} (No known unclaimed signature match).",
            "remediation": "Monitor CNAME target lifecycle."
        }

    service_name = matched_rule["service"]
    fingerprints = matched_rule["fingerprints"]
    remediation = matched_rule["remediation"]

    # Verify if CNAME is dangling or returning unclaimed asset signature
    evidence = ""
    is_dangling = False
    connection_failed = False

    if HAS_REQUESTS:
        endpoints = [f"https://{host}", f"http://{host}"]
        for url in endpoints:
            resp = None
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubdomainFinderPro/2.2"},
                    timeout=2.5,
                    verify=False,
                    allow_redirects=True,
                    stream=True
                )
                body = ""
                try:
                    chunk = next(resp.iter_content(32768), b"")
                    body = chunk.decode('utf-8', errors='ignore')
                except Exception:
                    body = getattr(resp, 'text', '') or ''

                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        is_dangling = True
                        evidence = f"Matched '{fp}' fingerprint in {resp.status_code} response."
                        break
                if is_dangling:
                    break
            except Exception:
                connection_failed = True
                continue
            finally:
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass

    # If HTTP connection failed, verify whether CNAME target itself resolves
    if not is_dangling and connection_failed:
        target_resolves = False
        try:
            if HAS_DNSPYTHON:
                r = dns.resolver.Resolver(configure=False)
                r.nameservers = ['1.1.1.1', '8.8.8.8']
                r.timeout = 1.5
                r.lifetime = 1.5
                ans = r.resolve(cname, 'A')
                if ans and len(ans) > 0:
                    target_resolves = True
        except Exception:
            pass

        if not target_resolves:
            try:
                socket.gethostbyname(cname)
                target_resolves = True
            except Exception:
                target_resolves = False

        if not target_resolves:
            is_dangling = True
            evidence = f"CNAME target '{cname}' does not resolve (NXDOMAIN / orphaned asset)."

    if is_dangling:
        return {
            "host": host,
            "cname": cname,
            "service": service_name,
            "status": "dangling",
            "status_label": "Dangling Pointer (Risk)",
            "evidence": evidence or f"Points to unclaimed {service_name} asset.",
            "remediation": remediation
        }

    return {
        "host": host,
        "cname": cname,
        "service": service_name,
        "status": "safe",
        "status_label": "Claimed / Active",
        "evidence": f"CNAME points to active {service_name} infrastructure.",
        "remediation": "None required (service is active)."
    }


def audit_hosts(hosts: list, max_workers: int = 15) -> list:
    """
    Audits a list of hostnames concurrently for dangling CNAME pointers.
    Optimized for low-spec standard computers.
    """
    unique_hosts = sorted(set(h.strip().lower() for h in hosts if h.strip()))
    if not unique_hosts:
        return []

    effective_workers = max(1, min(int(max_workers) if max_workers else 15, 20, len(unique_hosts)))
    results = []
    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        futures = [pool.submit(_audit_single_host, h) for h in unique_hosts]
        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)

    # Sort: dangling risks first, then third-party, then safe direct records
    def sort_order(item):
        st = item.get("status")
        if st == "dangling":
            return 0
        if st == "info":
            return 1
        return 2

    return sorted(results, key=sort_order)
