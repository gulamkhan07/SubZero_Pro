"""
IP Intelligence & Cloud WAF vs. Direct Origin IP Detector.
Performs high-speed local CIDR network matching to distinguish between
CDN/WAF-protected subdomains and direct Origin server IPs (WAF bypass targets).
Developed by: Gulam
"""
__author__ = "Gulam"

import ipaddress
from typing import Dict, List, Optional, Tuple

# Pre-compiled CIDR networks for Tier-1 CDNs & WAFs
# Sources: Official published IP ranges from Cloudflare, Fastly, AWS, Akamai, etc.
CDN_WAF_RANGES: List[Tuple[str, List[ipaddress.IPv4Network]]] = [
    (
        "Cloudflare WAF",
        [
            ipaddress.ip_network("173.245.48.0/20"),
            ipaddress.ip_network("103.21.244.0/22"),
            ipaddress.ip_network("103.22.200.0/22"),
            ipaddress.ip_network("103.31.4.0/22"),
            ipaddress.ip_network("141.101.64.0/18"),
            ipaddress.ip_network("108.162.192.0/18"),
            ipaddress.ip_network("190.93.240.0/20"),
            ipaddress.ip_network("188.114.96.0/20"),
            ipaddress.ip_network("197.234.240.0/22"),
            ipaddress.ip_network("198.41.128.0/17"),
            ipaddress.ip_network("162.158.0.0/15"),
            ipaddress.ip_network("104.16.0.0/13"),
            ipaddress.ip_network("104.24.0.0/14"),
            ipaddress.ip_network("172.64.0.0/13"),
            ipaddress.ip_network("131.0.72.0/22"),
        ]
    ),
    (
        "AWS CloudFront",
        [
            ipaddress.ip_network("13.32.0.0/15"),
            ipaddress.ip_network("13.35.0.0/16"),
            ipaddress.ip_network("13.224.0.0/14"),
            ipaddress.ip_network("13.249.0.0/16"),
            ipaddress.ip_network("18.64.0.0/14"),
            ipaddress.ip_network("18.154.0.0/15"),
            ipaddress.ip_network("18.160.0.0/15"),
            ipaddress.ip_network("52.84.0.0/15"),
            ipaddress.ip_network("54.182.0.0/16"),
            ipaddress.ip_network("54.192.0.0/16"),
            ipaddress.ip_network("54.230.0.0/16"),
            ipaddress.ip_network("54.239.128.0/18"),
            ipaddress.ip_network("99.84.0.0/16"),
            ipaddress.ip_network("99.86.0.0/16"),
            ipaddress.ip_network("143.204.0.0/16"),
            ipaddress.ip_network("205.251.192.0/19"),
            ipaddress.ip_network("216.137.32.0/19"),
        ]
    ),
    (
        "Fastly CDN",
        [
            ipaddress.ip_network("151.101.0.0/16"),
            ipaddress.ip_network("199.232.0.0/16"),
            ipaddress.ip_network("146.75.0.0/16"),
            ipaddress.ip_network("157.240.0.0/16"),
        ]
    ),
    (
        "Akamai Edge",
        [
            ipaddress.ip_network("23.0.0.0/12"),
            ipaddress.ip_network("104.64.0.0/10"),
            ipaddress.ip_network("184.24.0.0/13"),
            ipaddress.ip_network("2.16.0.0/13"),
            ipaddress.ip_network("96.16.0.0/15"),
        ]
    ),
    (
        "Imperva / Incapsula",
        [
            ipaddress.ip_network("199.83.128.0/21"),
            ipaddress.ip_network("198.143.32.0/19"),
            ipaddress.ip_network("149.126.72.0/21"),
            ipaddress.ip_network("103.28.248.0/22"),
            ipaddress.ip_network("45.64.64.0/22"),
            ipaddress.ip_network("185.11.124.0/22"),
            ipaddress.ip_network("192.230.64.0/18"),
        ]
    ),
    (
        "Sucuri WAF",
        [
            ipaddress.ip_network("192.88.134.0/23"),
            ipaddress.ip_network("185.93.228.0/22"),
            ipaddress.ip_network("66.248.200.0/22"),
            ipaddress.ip_network("208.109.0.0/22"),
        ]
    )
]

# Major Cloud Hosting Ranges (Direct Hosting / Origin Candidates)
CLOUD_ORIGIN_RANGES: List[Tuple[str, List[ipaddress.IPv4Network]]] = [
    (
        "AWS EC2 / Compute",
        [
            ipaddress.ip_network("3.0.0.0/9"),
            ipaddress.ip_network("3.128.0.0/10"),
            ipaddress.ip_network("15.177.0.0/16"),
            ipaddress.ip_network("34.192.0.0/12"),
            ipaddress.ip_network("35.153.0.0/16"),
            ipaddress.ip_network("44.192.0.0/11"),
            ipaddress.ip_network("52.0.0.0/11"),
            ipaddress.ip_network("54.0.0.0/10"),
        ]
    ),
    (
        "Microsoft Azure",
        [
            ipaddress.ip_network("13.64.0.0/11"),
            ipaddress.ip_network("20.0.0.0/10"),
            ipaddress.ip_network("40.64.0.0/10"),
            ipaddress.ip_network("51.140.0.0/14"),
            ipaddress.ip_network("52.136.0.0/13"),
            ipaddress.ip_network("104.40.0.0/13"),
        ]
    ),
    (
        "Google Cloud (GCP)",
        [
            ipaddress.ip_network("34.64.0.0/11"),
            ipaddress.ip_network("34.96.0.0/12"),
            ipaddress.ip_network("35.184.0.0/13"),
            ipaddress.ip_network("35.208.0.0/12"),
            ipaddress.ip_network("35.224.0.0/12"),
            ipaddress.ip_network("35.240.0.0/13"),
        ]
    ),
    (
        "DigitalOcean",
        [
            ipaddress.ip_network("104.131.0.0/16"),
            ipaddress.ip_network("104.248.0.0/16"),
            ipaddress.ip_network("138.68.0.0/16"),
            ipaddress.ip_network("142.93.0.0/16"),
            ipaddress.ip_network("159.203.0.0/16"),
            ipaddress.ip_network("165.22.0.0/16"),
            ipaddress.ip_network("167.99.0.0/16"),
            ipaddress.ip_network("178.62.0.0/16"),
            ipaddress.ip_network("206.189.0.0/16"),
        ]
    ),
    (
        "Hetzner",
        [
            ipaddress.ip_network("88.198.0.0/16"),
            ipaddress.ip_network("136.243.0.0/16"),
            ipaddress.ip_network("144.76.0.0/16"),
            ipaddress.ip_network("168.119.0.0/16"),
            ipaddress.ip_network("178.63.0.0/16"),
        ]
    ),
]


def classify_ip(ip_str: str) -> Dict[str, any]:
    """
    Analyzes an IPv4 or IPv6 string and determines whether it belongs to a
    CDN/WAF service (e.g. Cloudflare, CloudFront, Fastly) or is a Direct Origin IP.
    Returns:
      {
        'ip': ip_str,
        'is_cdn': bool,
        'waf_provider': str,
        'is_origin': bool,
        'badge_type': str,  # 'cloudflare', 'cloudfront', 'fastly', 'akamai', 'origin'
        'label': str
      }
    """
    ip_clean = (ip_str or "").strip()
    if not ip_clean:
        return {
            "ip": "",
            "is_cdn": False,
            "waf_provider": "Unknown",
            "is_origin": False,
            "badge_type": "unknown",
            "label": "Unresolved"
        }

    try:
        ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return {
            "ip": ip_clean,
            "is_cdn": False,
            "waf_provider": "Invalid IP",
            "is_origin": False,
            "badge_type": "unknown",
            "label": "Invalid IP"
        }

    # Only process IPv4 for CIDR range matching
    if isinstance(ip_obj, ipaddress.IPv4Address):
        # 1. Check CDN / WAF Ranges first
        for name, networks in CDN_WAF_RANGES:
            for net in networks:
                if ip_obj in net:
                    badge = "cloudflare" if "Cloudflare" in name else ("cloudfront" if "CloudFront" in name else ("fastly" if "Fastly" in name else "akamai"))
                    return {
                        "ip": ip_clean,
                        "is_cdn": True,
                        "waf_provider": name,
                        "is_origin": False,
                        "badge_type": badge,
                        "label": name
                    }

        # 2. Check Major Cloud Hosting Providers (Direct Origin Candidates)
        for name, networks in CLOUD_ORIGIN_RANGES:
            for net in networks:
                if ip_obj in net:
                    return {
                        "ip": ip_clean,
                        "is_cdn": False,
                        "waf_provider": name,
                        "is_origin": True,
                        "badge_type": "origin",
                        "label": f"{name} (Direct Origin 🔥)"
                    }

    # 3. If not in any CDN range, it's a Direct Dedicated Origin IP (WAF Bypass!)
    return {
        "ip": ip_clean,
        "is_cdn": False,
        "waf_provider": "Direct Server",
        "is_origin": True,
        "badge_type": "origin",
        "label": "Direct Origin IP 🔥"
    }


def classify_ips(ip_list: List[str]) -> Dict[str, any]:
    """
    Classifies a list of IPs for a subdomain and returns summary intel for the primary IP.
    """
    valid_ips = [ip.strip() for ip in ip_list if ip and ip.strip()]
    if not valid_ips:
        return {
            "primary_ip": "",
            "all_ips": [],
            "is_cdn": False,
            "waf_provider": "None",
            "is_origin": False,
            "badge_type": "none",
            "label": "No IP"
        }

    primary = valid_ips[0]
    intel = classify_ip(primary)
    intel["primary_ip"] = primary
    intel["all_ips"] = valid_ips
    return intel
