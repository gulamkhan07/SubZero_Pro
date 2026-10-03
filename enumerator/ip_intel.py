"""
IP Intelligence & Cloud WAF vs. Direct Origin IP Detector.
Performs high-speed local CIDR network matching (IPv4 and IPv6), CNAME
fingerprinting, and HTTP header analysis to distinguish between CDN/WAF-protected
subdomains and direct Origin server IPs (WAF bypass targets).
Developed by: Gulam
"""
__author__ = "Gulam"

import ipaddress
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple, Union

from enumerator.intelligence.database import GLOBAL_DATABASE
from enumerator.intelligence.correlation import GLOBAL_CORRELATION_ENGINE
from enumerator.intelligence.registry import PROVIDER_REGISTRY

NetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Pre-compiled CIDR networks for Tier-1 Enterprise CDNs & WAFs (IPv4 + IPv6)
# Sources: Official published IP ranges from Cloudflare, AWS, Azure, Google, Akamai, F5, Imperva, Fortinet, Radware, etc.
CDN_WAF_RANGES: List[Tuple[str, List[NetworkType]]] = [
    (
        "Cloudflare WAF",
        [
            # IPv4
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
            # IPv6
            ipaddress.ip_network("2606:4700::/32"),
            ipaddress.ip_network("2400:cb00::/32"),
            ipaddress.ip_network("2405:8100::/32"),
            ipaddress.ip_network("2405:b500::/32"),
            ipaddress.ip_network("2803:f800::/32"),
            ipaddress.ip_network("2a06:98c0::/29"),
            ipaddress.ip_network("2c0f:f248::/32"),
        ]
    ),
    (
        "AWS WAF",
        [
            # IPv4 (CloudFront & Global Accelerator Anycast)
            ipaddress.ip_network("13.32.0.0/15"),
            ipaddress.ip_network("13.35.0.0/16"),
            ipaddress.ip_network("13.224.0.0/14"),
            ipaddress.ip_network("13.249.0.0/16"),
            ipaddress.ip_network("15.158.0.0/16"),
            ipaddress.ip_network("18.64.0.0/14"),
            ipaddress.ip_network("18.154.0.0/15"),
            ipaddress.ip_network("18.160.0.0/15"),
            ipaddress.ip_network("52.84.0.0/15"),
            ipaddress.ip_network("54.182.0.0/16"),
            ipaddress.ip_network("54.192.0.0/16"),
            ipaddress.ip_network("54.230.0.0/16"),
            ipaddress.ip_network("54.239.128.0/18"),
            ipaddress.ip_network("54.240.128.0/18"),
            ipaddress.ip_network("65.8.0.0/16"),
            ipaddress.ip_network("65.9.0.0/16"),
            ipaddress.ip_network("99.84.0.0/16"),
            ipaddress.ip_network("99.86.0.0/16"),
            ipaddress.ip_network("108.138.0.0/15"),
            ipaddress.ip_network("108.156.0.0/14"),
            ipaddress.ip_network("143.204.0.0/16"),
            ipaddress.ip_network("205.251.192.0/19"),
            ipaddress.ip_network("216.137.32.0/19"),
            # IPv6
            ipaddress.ip_network("2600:9000::/28"),
            ipaddress.ip_network("2a05:d07a:a000::/40"),
            ipaddress.ip_network("2a05:d074:4000::/40"),
            ipaddress.ip_network("2600:1f00::/24", strict=False),
        ]
    ),
    (
        "Microsoft Azure WAF",
        [
            # IPv4 (Azure Front Door & Edge WAF Anycast)
            ipaddress.ip_network("13.107.246.0/24"),
            ipaddress.ip_network("13.107.213.0/24"),
            ipaddress.ip_network("13.107.246.0/23"),
            ipaddress.ip_network("13.107.238.0/23"),
            ipaddress.ip_network("204.79.197.0/24"),
            ipaddress.ip_network("13.107.4.0/24"),
            ipaddress.ip_network("13.107.6.0/24"),
            ipaddress.ip_network("13.77.161.0/24"),
            ipaddress.ip_network("52.230.152.0/24"),
            ipaddress.ip_network("52.239.152.0/24"),
            ipaddress.ip_network("150.171.0.0/16"),
            ipaddress.ip_network("13.107.128.0/22"),
            ipaddress.ip_network("13.107.64.0/18"),
            ipaddress.ip_network("20.150.0.0/16"),
            ipaddress.ip_network("20.190.128.0/18"),
            # IPv6
            ipaddress.ip_network("2620:1ec:4::/48"),
            ipaddress.ip_network("2620:1ec:a92::/48"),
            ipaddress.ip_network("2603:1061::/32"),
            ipaddress.ip_network("2a01:111:2003::/48"),
        ]
    ),
    (
        "Google Cloud Armor",
        [
            # IPv4 (Google External Global HTTP(S) Load Balancers / Cloud Armor Anycast)
            ipaddress.ip_network("34.96.0.0/16"),
            ipaddress.ip_network("34.98.0.0/16"),
            ipaddress.ip_network("34.102.0.0/16"),
            ipaddress.ip_network("34.107.0.0/16"),
            ipaddress.ip_network("34.110.0.0/16"),
            ipaddress.ip_network("34.111.0.0/16"),
            ipaddress.ip_network("34.117.0.0/16"),
            ipaddress.ip_network("34.120.0.0/16"),
            ipaddress.ip_network("34.149.0.0/16"),
            ipaddress.ip_network("34.160.0.0/16"),
            ipaddress.ip_network("35.186.192.0/18"),
            ipaddress.ip_network("35.190.0.0/17"),
            ipaddress.ip_network("35.227.192.0/18"),
            ipaddress.ip_network("35.244.128.0/17"),
            # IPv6
            ipaddress.ip_network("2600:1901::/32"),
            ipaddress.ip_network("2600:1900::/28"),
        ]
    ),
    (
        "Akamai App & API Protector",
        [
            # IPv4 - Comprehensive Akamai Edge Anycast networks
            # Covers 23.192.0.0/10 which includes 23.215.55.173 (nayaraenergy.com)
            ipaddress.ip_network("23.192.0.0/10"),
            ipaddress.ip_network("23.32.0.0/11"),
            ipaddress.ip_network("23.64.0.0/14"),
            ipaddress.ip_network("23.0.0.0/12"),
            ipaddress.ip_network("104.64.0.0/10"),
            ipaddress.ip_network("184.24.0.0/13"),
            ipaddress.ip_network("184.84.0.0/14"),
            ipaddress.ip_network("184.50.0.0/15"),
            ipaddress.ip_network("184.51.0.0/16"),
            ipaddress.ip_network("2.16.0.0/13"),
            ipaddress.ip_network("2.20.0.0/14"),
            ipaddress.ip_network("96.16.0.0/15"),
            ipaddress.ip_network("96.6.0.0/15"),
            ipaddress.ip_network("72.246.0.0/15"),
            ipaddress.ip_network("173.222.0.0/15"),
            ipaddress.ip_network("173.223.0.0/16"),
            ipaddress.ip_network("63.208.0.0/13"),
            ipaddress.ip_network("88.221.0.0/16"),
            ipaddress.ip_network("92.122.0.0/15"),
            ipaddress.ip_network("95.100.0.0/15"),
            ipaddress.ip_network("118.214.0.0/16"),
            ipaddress.ip_network("125.56.0.0/14"),
            ipaddress.ip_network("217.163.0.0/16"),
            # IPv6
            ipaddress.ip_network("2600:1400::/24", strict=False),
            ipaddress.ip_network("2600:1480::/32", strict=False),
            ipaddress.ip_network("2a02:26f0::/32", strict=False),
        ]
    ),
    (
        "F5 Distributed Cloud WAF",
        [
            # IPv4 - F5 / Volterra / Shape Anycast CIDRs
            ipaddress.ip_network("84.17.65.0/24"),
            ipaddress.ip_network("185.151.204.0/22"),
            ipaddress.ip_network("141.193.32.0/20"),
            ipaddress.ip_network("159.60.0.0/16"),
            ipaddress.ip_network("107.162.128.0/17"),
            ipaddress.ip_network("198.61.128.0/18"),
            ipaddress.ip_network("208.85.208.0/20"),
            ipaddress.ip_network("65.61.128.0/17"),
            # IPv6
            ipaddress.ip_network("2602:fd13::/36", strict=False),
            ipaddress.ip_network("2a0b:3e00::/29", strict=False),
        ]
    ),
    (
        "Imperva WAF",
        [
            # IPv4 - Imperva / Incapsula Anycast
            ipaddress.ip_network("199.83.128.0/21"),
            ipaddress.ip_network("198.143.32.0/19"),
            ipaddress.ip_network("149.126.72.0/21"),
            ipaddress.ip_network("103.28.248.0/22"),
            ipaddress.ip_network("45.64.64.0/22"),
            ipaddress.ip_network("185.11.124.0/22"),
            ipaddress.ip_network("192.230.64.0/18"),
            ipaddress.ip_network("107.154.0.0/16"),
            ipaddress.ip_network("45.223.0.0/16"),
            ipaddress.ip_network("131.153.0.0/16"),
            # IPv6
            ipaddress.ip_network("2a02:e980::/29", strict=False),
        ]
    ),
    (
        "Fortinet FortiWeb",
        [
            # IPv4 - FortiWeb Cloud & FortiGuard Anycast
            ipaddress.ip_network("154.52.0.0/16"),
            ipaddress.ip_network("208.91.112.0/21"),
            ipaddress.ip_network("173.243.128.0/20"),
            ipaddress.ip_network("66.171.120.0/24"),
            ipaddress.ip_network("204.101.4.0/24"),
            ipaddress.ip_network("12.34.240.0/20"),
            ipaddress.ip_network("96.45.32.0/20"),
        ]
    ),
    (
        "Radware Cloud WAF",
        [
            # IPv4 - Radware Cloud WAF & ShieldSquare CIDRs
            ipaddress.ip_network("192.230.128.0/18"),
            ipaddress.ip_network("194.90.0.0/16"),
            ipaddress.ip_network("207.189.96.0/19"),
            ipaddress.ip_network("147.161.0.0/16"),
            ipaddress.ip_network("185.76.64.0/22"),
            ipaddress.ip_network("64.211.0.0/18"),
            ipaddress.ip_network("209.68.0.0/18"),
        ]
    ),
    (
        "Fastly CDN",
        [
            # IPv4
            ipaddress.ip_network("151.101.0.0/16"),
            ipaddress.ip_network("199.232.0.0/16"),
            ipaddress.ip_network("146.75.0.0/16"),
            ipaddress.ip_network("157.240.0.0/16"),
            # IPv6
            ipaddress.ip_network("2a04:4e40::/32"),
            ipaddress.ip_network("2a04:4e42::/32"),
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
    ),
    (
        "Vercel Edge",
        [
            ipaddress.ip_network("76.76.21.0/24"),
            ipaddress.ip_network("76.223.126.0/24"),
        ]
    ),
    (
        "Netlify Edge",
        [
            ipaddress.ip_network("75.2.60.0/24"),
            ipaddress.ip_network("99.83.190.0/24"),
            ipaddress.ip_network("165.227.0.0/16"),
        ]
    ),
    (
        "BunnyCDN",
        [
            ipaddress.ip_network("185.244.25.0/24"),
            ipaddress.ip_network("169.150.247.0/24"),
            ipaddress.ip_network("185.180.12.0/24"),
        ]
    )
]

# Major Cloud Hosting Ranges (Direct Hosting / Origin Candidates)
CLOUD_ORIGIN_RANGES: List[Tuple[str, List[NetworkType]]] = [
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
    (
        "Oracle Cloud (OCI)",
        [
            ipaddress.ip_network("130.35.0.0/16"),
            ipaddress.ip_network("138.1.0.0/16"),
            ipaddress.ip_network("140.238.0.0/16"),
            ipaddress.ip_network("150.136.0.0/16"),
        ]
    ),
    (
        "Alibaba Cloud",
        [
            # Alibaba Cloud ECS — specific documented subnets instead of entire /8
            ipaddress.ip_network("47.52.0.0/14"),     # Hong Kong / AP
            ipaddress.ip_network("47.56.0.0/15"),     # Hong Kong
            ipaddress.ip_network("47.74.0.0/15"),     # Singapore / AP
            ipaddress.ip_network("47.88.0.0/14"),     # US West
            ipaddress.ip_network("47.92.0.0/14"),     # China East
            ipaddress.ip_network("47.96.0.0/11"),     # China regions
            ipaddress.ip_network("47.240.0.0/14"),    # International
            ipaddress.ip_network("47.244.0.0/15"),    # Hong Kong
            ipaddress.ip_network("47.246.0.0/15"),    # International
            ipaddress.ip_network("47.248.0.0/14"),    # International
            ipaddress.ip_network("47.254.0.0/15"),    # US / EU regions
            ipaddress.ip_network("8.208.0.0/12"),     # International compute
            ipaddress.ip_network("39.96.0.0/13"),     # China compute
            ipaddress.ip_network("39.104.0.0/14"),    # China compute
            ipaddress.ip_network("101.132.0.0/14"),   # China compute
            ipaddress.ip_network("106.14.0.0/15"),    # China Shanghai
            ipaddress.ip_network("120.24.0.0/14"),    # China Shenzhen
            ipaddress.ip_network("120.76.0.0/14"),    # China Hangzhou
            ipaddress.ip_network("121.40.0.0/13"),    # China Hangzhou
            ipaddress.ip_network("149.129.0.0/16"),   # AP / Indonesia
            ipaddress.ip_network("161.117.0.0/16"),   # AP Singapore
        ]
    ),
    (
        "Linode / Akamai Cloud",
        [
            ipaddress.ip_network("172.104.0.0/15"),
            ipaddress.ip_network("139.162.0.0/16"),
            ipaddress.ip_network("45.33.0.0/16"),
        ]
    ),
    (
        "OVHcloud",
        [
            ipaddress.ip_network("51.254.0.0/15"),
            ipaddress.ip_network("54.36.0.0/15"),
            ipaddress.ip_network("147.135.0.0/16"),
        ]
    ),
    (
        "Vultr",
        [
            ipaddress.ip_network("45.76.0.0/16"),
            ipaddress.ip_network("45.77.0.0/16"),
            ipaddress.ip_network("66.42.0.0/16"),
            ipaddress.ip_network("108.61.0.0/16"),
            ipaddress.ip_network("149.28.0.0/16"),
            ipaddress.ip_network("139.180.128.0/17"),
            ipaddress.ip_network("207.246.64.0/18"),
            ipaddress.ip_network("216.238.64.0/18"),
        ]
    ),
    (
        "Scaleway",
        [
            ipaddress.ip_network("51.15.0.0/16"),
            ipaddress.ip_network("51.158.0.0/15"),
            ipaddress.ip_network("62.210.0.0/16"),
            ipaddress.ip_network("163.172.0.0/16"),
            ipaddress.ip_network("212.47.224.0/19"),
        ]
    ),
    (
        "Tencent Cloud",
        [
            ipaddress.ip_network("43.128.0.0/11"),
            ipaddress.ip_network("49.51.0.0/16"),
            ipaddress.ip_network("119.28.0.0/15"),
            ipaddress.ip_network("129.226.0.0/16"),
            ipaddress.ip_network("150.109.0.0/16"),
        ]
    ),
    (
        "Huawei Cloud",
        [
            ipaddress.ip_network("117.78.0.0/17"),
            ipaddress.ip_network("119.3.0.0/16"),
            ipaddress.ip_network("121.36.0.0/15"),
            ipaddress.ip_network("159.138.0.0/16"),
        ]
    ),
    (
        "Contabo",
        [
            ipaddress.ip_network("161.97.64.0/18"),
            ipaddress.ip_network("194.163.128.0/17"),
            ipaddress.ip_network("173.249.0.0/17"),
            ipaddress.ip_network("144.91.64.0/18"),
            ipaddress.ip_network("207.180.192.0/18"),
        ]
    ),
    (
        "Moro Hub Cloud (Dubai Govt / DEWA)",
        [
            ipaddress.ip_network("66.220.48.0/22"),
            ipaddress.ip_network("185.66.144.0/22"),
            ipaddress.ip_network("185.238.180.0/23"),
        ]
    ),
    (
        "e& Enterprise Cloud (Etisalat UAE)",
        [
            ipaddress.ip_network("195.229.0.0/16"),
            ipaddress.ip_network("213.42.0.0/16"),
            ipaddress.ip_network("5.32.0.0/14"),
            ipaddress.ip_network("5.195.0.0/17"),
            ipaddress.ip_network("83.111.0.0/17"),
            ipaddress.ip_network("94.56.0.0/17"),
        ]
    ),
    (
        "du Enterprise Cloud (EITC UAE)",
        [
            ipaddress.ip_network("80.227.96.0/19"),
            ipaddress.ip_network("94.202.96.0/19"),
            ipaddress.ip_network("5.30.0.0/21"),
        ]
    ),
    (
        "Core42 / G42 Cloud (UAE Sovereign Cloud)",
        [
            ipaddress.ip_network("185.201.24.0/22"),
        ]
    ),
]

# Canonical Name (CNAME) Signatures for CDN & WAF providers (All 9 Enterprise WAFs)
CNAME_WAF_SIGNATURES: List[Tuple[str, str, str]] = [
    # 1. Cloudflare WAF
    ("Cloudflare WAF", "cloudflare", "cloudflare.net"),
    ("Cloudflare WAF", "cloudflare", "cloudflare.com"),
    ("Cloudflare WAF", "cloudflare", "cloudflare-custom.com"),

    # 2. AWS WAF / CloudFront
    ("AWS WAF", "aws", "cloudfront.net"),
    ("AWS WAF", "aws", "awsglobalaccelerator.com"),
    ("AWS WAF", "aws", "elb.amazonaws.com"),
    ("AWS WAF", "aws", "elasticloadbalancing.amazonaws.com"),

    # 3. Microsoft Azure WAF
    ("Microsoft Azure WAF", "azure", "azureedge.net"),
    ("Microsoft Azure WAF", "azure", "azurefd.net"),
    ("Microsoft Azure WAF", "azure", "trafficmanager.net"),
    ("Microsoft Azure WAF", "azure", "azurefd.us"),
    ("Microsoft Azure WAF", "azure", "azurewebsites.net"),

    # 4. Google Cloud Armor
    ("Google Cloud Armor", "google", "googlehosted.com"),
    ("Google Cloud Armor", "google", "ghs.googlehosted.com"),
    ("Google Cloud Armor", "google", "1e100.net"),

    # 5. Akamai App & API Protector
    ("Akamai App & API Protector", "akamai", "akamaiedge.net"),
    ("Akamai App & API Protector", "akamai", "akamai.net"),
    ("Akamai App & API Protector", "akamai", "edgekey.net"),
    ("Akamai App & API Protector", "akamai", "edgesuite.net"),
    ("Akamai App & API Protector", "akamai", "akamaitechnologies.com"),
    ("Akamai App & API Protector", "akamai", "akamai-staging.net"),

    # 6. F5 Distributed Cloud WAF
    ("F5 Distributed Cloud WAF", "f5", "f5.com"),
    ("F5 Distributed Cloud WAF", "f5", "f5edge.net"),
    ("F5 Distributed Cloud WAF", "f5", "f5cloud.net"),
    ("F5 Distributed Cloud WAF", "f5", "volterra.io"),
    ("F5 Distributed Cloud WAF", "f5", "shapehost.com"),
    ("F5 Distributed Cloud WAF", "f5", "f5distributedcloud.com"),

    # 7. Imperva WAF
    ("Imperva WAF", "imperva", "incapdns.net"),
    ("Imperva WAF", "imperva", "impervadns.net"),
    ("Imperva WAF", "imperva", "imperva.com"),

    # 8. Fortinet FortiWeb
    ("Fortinet FortiWeb", "fortinet", "fortiweb-cloud.com"),
    ("Fortinet FortiWeb", "fortinet", "fortiweb.com"),
    ("Fortinet FortiWeb", "fortinet", "fortiguard.net"),
    ("Fortinet FortiWeb", "fortinet", "fortigate.com"),

    # 9. Radware Cloud WAF
    ("Radware Cloud WAF", "radware", "cwaf.radware.com"),
    ("Radware Cloud WAF", "radware", "radwarecloud.net"),
    ("Radware Cloud WAF", "radware", "radware.com"),
    ("Radware Cloud WAF", "radware", "shieldsquare.net"),

    # Additional Providers
    ("Fastly CDN", "fastly", "fastly.net"),
    ("Fastly CDN", "fastly", "fastlylb.net"),
    ("Sucuri WAF", "sucuri", "sucuri.net"),
    ("Vercel Edge", "vercel", "vercel-dns.com"),
    ("Vercel Edge", "vercel", "vercel.app"),
    ("Netlify Edge", "netlify", "netlify.app"),
    ("Netlify Edge", "netlify", "netlify.com"),
    ("BunnyCDN", "bunny", "b-cdn.net"),

    # Alibaba Cloud CDN & WAF
    ("Alibaba Cloud CDN", "alibaba", "kunluncan.com"),
    ("Alibaba Cloud CDN", "alibaba", "kunlungr.com"),
    ("Alibaba Cloud CDN", "alibaba", "alikunlun.com"),
    ("Alibaba Cloud CDN", "alibaba", "alicdn.com"),
    ("Alibaba Cloud WAF", "alibaba", "aliyunwaf.com"),

    # Tencent Cloud CDN & WAF
    ("Tencent Cloud CDN", "tencent", "qcloudcdn.com"),
    ("Tencent Cloud CDN", "tencent", "myqcloud.com"),
    ("Tencent Cloud CDN", "tencent", "dnsv1.com"),
    ("Tencent Cloud CDN", "tencent", "tcdnlive.com"),

    # Huawei Cloud CDN & WAF
    ("Huawei Cloud CDN", "huawei", "cdnhwc1.com"),
    ("Huawei Cloud CDN", "huawei", "cdnhwc2.com"),
    ("Huawei Cloud CDN", "huawei", "hwclouds.com"),
    ("Huawei Cloud CDN", "huawei", "huaweicloud.com"),

    # Barracuda CloudGen WAF
    ("Barracuda WAF", "barracuda", "barracudanetworks.com"),
    ("Barracuda WAF", "barracuda", "barracuda.com"),
    ("Barracuda WAF", "barracuda", "barracudawaf.com"),

    # Citrix NetScaler ADC / AppFirewall
    ("Citrix NetScaler AppFirewall", "citrix", "netscaler.com"),
    ("Citrix NetScaler AppFirewall", "citrix", "citrix.com"),

    # ArvanCloud CDN / WAF
    ("ArvanCloud CDN", "arvancloud", "arvancloud.ir"),
    ("ArvanCloud CDN", "arvancloud", "arvancloud.com"),

    # Check Point CloudGuard AppSec / WAF (Dubai / UAE Banking & Govt)
    ("Check Point CloudGuard WAF", "checkpoint", "checkpoint.com"),
    ("Check Point CloudGuard WAF", "checkpoint", "cloudguard.app"),
    ("Check Point CloudGuard WAF", "checkpoint", "chkp.com"),

    # Palo Alto Networks Prisma Cloud / WAF (UAE Enterprise)
    ("Palo Alto Prisma WAF", "paloalto", "prismacloud.io"),
    ("Palo Alto Prisma WAF", "paloalto", "paloaltonetworks.com"),

    # AppTrana / Indusface Cloud WAF (UAE / Middle East Popular)
    ("AppTrana WAF (Indusface)", "apptrana", "indusface.net"),
    ("AppTrana WAF (Indusface)", "apptrana", "apptrana.com"),
    ("AppTrana WAF (Indusface)", "apptrana", "indusface.com"),

    # Wallarm API & Cloud WAF (Dubai DIFC / Fintech)
    ("Wallarm WAF", "wallarm", "wallarm.com"),
    ("Wallarm WAF", "wallarm", "wallarm.io"),

    # Moro Hub Sovereign Cloud (Dubai Govt / DEWA)
    ("Moro Hub Cloud (Dubai)", "morohub", "morohub.com"),
    ("Moro Hub Cloud (Dubai)", "morohub", "moro.cloud"),

    # Help AG / e& Managed WAF (UAE Enterprise)
    ("Help AG / e& Managed WAF (UAE)", "helpag", "helpag.com"),
    ("Help AG / e& Managed WAF (UAE)", "helpag", "etisalat.ae"),
    ("Help AG / e& Managed WAF (UAE)", "helpag", "eand.com"),

    # du Enterprise Cloud (UAE)
    ("du Enterprise Cloud (UAE)", "ducloud", "du.ae"),
    ("du Enterprise Cloud (UAE)", "ducloud", "ducloud.ae"),

    # Core42 / G42 Cloud (UAE Sovereign Cloud)
    ("Core42 Cloud (UAE)", "g42", "core42.ai"),
    ("Core42 Cloud (UAE)", "g42", "g42cloud.com"),
]


# Ordered keyword → badge type mapping (replaces 60-line if/elif chain)
_BADGE_KEYWORDS: List[Tuple[str, str]] = [
    ("cloudflare", "cloudflare"), ("aws", "aws"), ("cloudfront", "aws"),
    ("azure", "azure"), ("google", "google"), ("cloud armor", "google"),
    ("akamai", "akamai"), ("f5", "f5"), ("shape", "f5"), ("volterra", "f5"),
    ("imperva", "imperva"), ("incapsula", "imperva"),
    ("fortinet", "fortinet"), ("fortiweb", "fortinet"),
    ("radware", "radware"), ("fastly", "fastly"), ("sucuri", "sucuri"),
    ("vercel", "vercel"), ("netlify", "netlify"), ("bunny", "bunny"),
    ("alibaba", "alibaba"), ("aliyun", "alibaba"),
    ("tencent", "tencent"), ("qcloud", "tencent"),
    ("huawei", "huawei"), ("barracuda", "barracuda"),
    ("citrix", "citrix"), ("netscaler", "citrix"),
    ("arvancloud", "arvancloud"),
    ("checkpoint", "checkpoint"), ("cloudguard", "checkpoint"),
    ("paloalto", "paloalto"), ("prisma", "paloalto"),
    ("apptrana", "apptrana"), ("indusface", "apptrana"),
    ("wallarm", "wallarm"),
    ("morohub", "morohub"), ("moro", "morohub"),
    ("helpag", "helpag"), ("etisalat", "helpag"), ("e&", "helpag"),
    ("ducloud", "ducloud"), ("du ", "ducloud"),
    ("g42", "g42"), ("core42", "g42"),
]


def _badge_type_for_provider(name: str) -> str:
    """Maps provider name to its badge type using keyword matching."""
    n = name.lower()
    for keyword, badge in _BADGE_KEYWORDS:
        if keyword in n:
            return badge
    return "waf"


def detect_waf_from_http(headers: Optional[Dict[str, str]] = None, body: str = "", status_code: int = 0) -> Optional[Dict[str, Any]]:
    """
    Detects WAF / Cloud Security platforms from HTTP response headers, status codes, and HTML body fingerprints.
    Supports all 9 enterprise platforms: Cloudflare, AWS WAF, Azure WAF, Google Cloud Armor, Akamai,
    F5, Imperva, Fortinet, and Radware.
    """
    h = {k.lower(): str(v) for k, v in (headers or {}).items()}
    server = h.get('server', '').lower()
    body_lower = (body or '').lower()
    is_blocked = (status_code in (403, 406, 429, 503))

    # 1. Akamai App & API Protector
    if 'akamai-grn' in h or 'x-akamai-request-id' in h or 'x-akamai-session-info' in h or 'akamai' in server:
        evidence = 'Akamai-GRN header' if 'akamai-grn' in h else f'Server: {h.get("server", "Akamai")}'
        return {
            'waf_provider': 'Akamai App & API Protector',
            'badge_type': 'akamai',
            'evidence': evidence,
            'is_blocked': is_blocked or 'unauthorized request blocked' in body_lower or 'access denied' in body_lower
        }
    # NOTE: Akamai body-only fallback is handled in the unified body fingerprint section below

    # 2. Cloudflare WAF
    if 'cf-ray' in h or 'cloudflare' in server or 'cf-cache-status' in h:
        return {
            'waf_provider': 'Cloudflare WAF',
            'badge_type': 'cloudflare',
            'evidence': 'cf-ray / Server: cloudflare',
            'is_blocked': is_blocked or 'attention required! | cloudflare' in body_lower or 'cloudflare ray id' in body_lower
        }

    # 3. AWS WAF
    if 'x-amz-cf-id' in h or 'x-amz-cf-pop' in h or 'awselb' in server or any(k.startswith('x-amz-waf-') for k in h):
        return {
            'waf_provider': 'AWS WAF',
            'badge_type': 'aws',
            'evidence': 'x-amz-cf-id / AWS WAF header',
            'is_blocked': is_blocked or 'request blocked by aws waf' in body_lower
        }

    # 4. Microsoft Azure WAF
    if 'x-azure-ref' in h or 'x-ms-ref' in h or 'azure' in server or 'application-gateway' in server:
        return {
            'waf_provider': 'Microsoft Azure WAF',
            'badge_type': 'azure',
            'evidence': 'x-azure-ref / Azure WAF header',
            'is_blocked': is_blocked or 'azure front door' in body_lower
        }

    # 5. Google Cloud Armor
    if 'via' in h and 'google' in h['via'].lower() and ('gse' in server or 'google frontend' in server or is_blocked):
        return {
            'waf_provider': 'Google Cloud Armor',
            'badge_type': 'google',
            'evidence': 'Via: 1.1 google / GSE',
            'is_blocked': is_blocked or 'cloud armor' in body_lower
        }
    if 'server' in h and ('gse' in server or 'google frontend' in server) and is_blocked:
        return {
            'waf_provider': 'Google Cloud Armor',
            'badge_type': 'google',
            'evidence': 'Google Frontend 403 Security Policy',
            'is_blocked': True
        }

    # 6. F5 Distributed Cloud WAF
    if any(k.startswith('x-f5-') or k.startswith('x-shape-') for k in h) or 'bigip' in server or 'f5' in server or any('bigip' in v.lower() for v in h.values()):
        return {
            'waf_provider': 'F5 Distributed Cloud WAF',
            'badge_type': 'f5',
            'evidence': 'F5 / BigIP header',
            'is_blocked': is_blocked or 'the requested url was rejected' in body_lower
        }

    # 7. Imperva WAF
    if 'x-iinfo' in h or ('x-cdn' in h and 'incapsula' in h['x-cdn'].lower()):
        return {
            'waf_provider': 'Imperva WAF',
            'badge_type': 'imperva',
            'evidence': 'X-Iinfo / Incapsula header',
            'is_blocked': is_blocked or 'incapsula incident id' in body_lower
        }

    # 8. Fortinet FortiWeb
    if 'fortiweb' in server or any('fortiwaf' in k or 'fortiwaf' in v.lower() for k, v in h.items()):
        return {
            'waf_provider': 'Fortinet FortiWeb',
            'badge_type': 'fortinet',
            'evidence': 'FortiWeb server / cookie header',
            'is_blocked': is_blocked or 'fortiweb' in body_lower
        }

    # 9. Radware Cloud WAF
    if any(k.startswith('x-rdwr-') or 'rdwr' in k for k in h) or 'radware' in server:
        return {
            'waf_provider': 'Radware Cloud WAF',
            'badge_type': 'radware',
            'evidence': 'X-RDWR header',
            'is_blocked': is_blocked or 'unauthorized access - radware' in body_lower
        }

    # 10. Barracuda CloudGen WAF
    if 'barra_counter_session' in h or 'bni__barracuda_lb_cookie' in h or 'bni_persistence' in h or 'barracuda' in server:
        return {
            'waf_provider': 'Barracuda WAF',
            'badge_type': 'barracuda',
            'evidence': 'Barracuda server / cookie header',
            'is_blocked': is_blocked
        }

    # 11. Citrix NetScaler AppFirewall
    if 'citrix_ns_id' in h or any(k.startswith('ns_af') for k in h) or any('nsc_' in k for k in h) or 'netscaler' in server:
        return {
            'waf_provider': 'Citrix NetScaler AppFirewall',
            'badge_type': 'citrix',
            'evidence': 'NetScaler cookie / server header',
            'is_blocked': is_blocked
        }

    # 12. Alibaba Cloud WAF / CDN
    if 'eagleeye-traceid' in h or 'ali-swift-global-savetime' in h or 's-w-a-f' in h or 'x-alicdn-da-status' in h or 'alicdn' in server or 'aliyun' in server:
        return {
            'waf_provider': 'Alibaba Cloud WAF',
            'badge_type': 'alibaba',
            'evidence': 'Alibaba Cloud / EagleEye / Aliyun header',
            'is_blocked': is_blocked
        }

    # 13. Tencent Cloud CDN / WAF
    if 'x-dau-tcdn' in h or 'x-tc-sec-status' in h or 'tencent' in server or 'tcdn' in server:
        return {
            'waf_provider': 'Tencent Cloud CDN',
            'badge_type': 'tencent',
            'evidence': 'Tencent Cloud TCDN header / Server',
            'is_blocked': is_blocked
        }

    # 14. Huawei Cloud WAF / CDN
    if 'hws-trace-id' in h or 'x-hws-trace-id' in h or 'huaweicloud' in server:
        return {
            'waf_provider': 'Huawei Cloud WAF',
            'badge_type': 'huawei',
            'evidence': 'Huawei Cloud HWS trace header',
            'is_blocked': is_blocked
        }

    # 15. ArvanCloud CDN / WAF
    if 'ar-poweredby' in h or 'ar-request-id' in h or 'arvancloud' in server or ('via' in h and 'arvan' in h['via'].lower()):
        return {
            'waf_provider': 'ArvanCloud CDN',
            'badge_type': 'arvancloud',
            'evidence': 'ArvanCloud header',
            'is_blocked': is_blocked
        }

    # 16. Check Point CloudGuard AppSec / WAF (Dubai / UAE Banking & Govt)
    if 'x-cp-appsec' in h or any(k.startswith('x-chkp') for k in h) or 'checkpoint' in server or 'chkp' in server:
        return {
            'waf_provider': 'Check Point CloudGuard WAF',
            'badge_type': 'checkpoint',
            'evidence': 'Check Point / CloudGuard header or Server',
            'is_blocked': is_blocked
        }

    # 17. Palo Alto Networks Prisma Cloud / WAF
    if any(k.startswith('x-pan-') for k in h) or any(k.startswith('x-prisma-') for k in h) or 'paloalto' in server:
        return {
            'waf_provider': 'Palo Alto Prisma WAF',
            'badge_type': 'paloalto',
            'evidence': 'Palo Alto / Prisma header',
            'is_blocked': is_blocked
        }

    # 18. AppTrana / Indusface WAF (UAE / Middle East Popular)
    if any(k.startswith('x-indusface') for k in h) or any(k.startswith('x-apptrana') for k in h) or 'indusface' in server or 'apptrana' in server:
        return {
            'waf_provider': 'AppTrana WAF (Indusface)',
            'badge_type': 'apptrana',
            'evidence': 'AppTrana / Indusface header or Server',
            'is_blocked': is_blocked
        }

    # 19. Wallarm API & Cloud WAF (Dubai DIFC / Fintech)
    if any(k.startswith('x-wallarm') for k in h) or 'wallarm' in server:
        return {
            'waf_provider': 'Wallarm WAF',
            'badge_type': 'wallarm',
            'evidence': 'Wallarm header or Server',
            'is_blocked': is_blocked
        }

    # 20. Help AG / e& Managed WAF (UAE)
    if 'helpag' in server or any('helpag' in k for k in h) or 'eand' in server:
        return {
            'waf_provider': 'Help AG / e& Managed WAF (UAE)',
            'badge_type': 'helpag',
            'evidence': 'Help AG / e& Enterprise header',
            'is_blocked': is_blocked
        }

    # Body fingerprint fallbacks for blocked statuses
    if is_blocked:
        if 'unauthorized request blocked' in body_lower:
            return {
                'waf_provider': 'Akamai App & API Protector',
                'badge_type': 'akamai',
                'evidence': 'Title: Unauthorized Request Blocked (Akamai signature)',
                'is_blocked': True
            }
        if 'attention required! | cloudflare' in body_lower or 'cf-browser-verification' in body_lower:
            return {
                'waf_provider': 'Cloudflare WAF',
                'badge_type': 'cloudflare',
                'evidence': 'Cloudflare challenge page body',
                'is_blocked': True
            }
        if 'request blocked by aws waf' in body_lower:
            return {
                'waf_provider': 'AWS WAF',
                'badge_type': 'aws',
                'evidence': 'AWS WAF block message body',
                'is_blocked': True
            }
        if 'incapsula incident id' in body_lower:
            return {
                'waf_provider': 'Imperva WAF',
                'badge_type': 'imperva',
                'evidence': 'Imperva block page body',
                'is_blocked': True
            }

    return None


def classify_cname(cname_str: str) -> Optional[Dict[str, Any]]:
    """
    Checks if a canonical name (CNAME) points to a known CDN/WAF provider.
    Returns intelligence dict if matched, None otherwise.
    """
    cname_clean = (cname_str or "").strip().lower().rstrip('.')
    if not cname_clean:
        return None

    for provider_name, badge_type, pattern in CNAME_WAF_SIGNATURES:
        if cname_clean.endswith(f".{pattern}") or cname_clean == pattern or f".{pattern}" in cname_clean:
            return {
                "is_cdn": True,
                "waf_provider": provider_name,
                "is_origin": False,
                "badge_type": badge_type,
                "label": provider_name,
                "detected_via": "cname",
                "cname": cname_clean,
            }
    return None


# Lightweight Heuristic GeoIP Mapping (Major Cloud & Regional Subnets)
GEOIP_RANGES: List[Tuple[str, str, str, List[NetworkType]]] = [
    # United Arab Emirates / Dubai (AS8966, AS15802, AS204832, DEWA, etc.)
    ("United Arab Emirates", "AE", "🇦🇪", [
        ipaddress.ip_network("5.32.0.0/14"),
        ipaddress.ip_network("66.220.48.0/22"),
        ipaddress.ip_network("185.66.144.0/22"),
        ipaddress.ip_network("185.238.180.0/23"),
        ipaddress.ip_network("195.229.0.0/16"),
        ipaddress.ip_network("213.42.0.0/16"),
        ipaddress.ip_network("5.192.0.0/14"),
        ipaddress.ip_network("83.110.0.0/15"),
        ipaddress.ip_network("94.56.0.0/14"),
        ipaddress.ip_network("94.200.0.0/14"),
        ipaddress.ip_network("80.227.0.0/16"),
        ipaddress.ip_network("185.201.24.0/22"),
    ]),
    # Germany (Hetzner, Contabo)
    ("Germany", "DE", "🇩🇪", [
        ipaddress.ip_network("88.198.0.0/16"),
        ipaddress.ip_network("136.243.0.0/16"),
        ipaddress.ip_network("138.201.0.0/16"),
        ipaddress.ip_network("144.76.0.0/16"),
        ipaddress.ip_network("168.119.0.0/16"),
        ipaddress.ip_network("178.63.0.0/16"),
        ipaddress.ip_network("194.163.128.0/17"),
        ipaddress.ip_network("161.97.64.0/18"),
        ipaddress.ip_network("173.249.0.0/17"),
    ]),
    # France (OVH, Scaleway)
    ("France", "FR", "🇫🇷", [
        ipaddress.ip_network("51.15.0.0/16"),
        ipaddress.ip_network("51.158.0.0/15"),
        ipaddress.ip_network("62.210.0.0/16"),
        ipaddress.ip_network("163.172.0.0/16"),
        ipaddress.ip_network("212.47.224.0/19"),
        ipaddress.ip_network("51.254.0.0/15"),
        ipaddress.ip_network("54.36.0.0/15"),
        ipaddress.ip_network("147.135.0.0/16"),
    ]),
    # China (Alibaba, Tencent, Huawei) — specific subnets matching CLOUD_ORIGIN_RANGES
    ("China", "CN", "🇨🇳", [
        ipaddress.ip_network("47.92.0.0/14"),      # Alibaba China
        ipaddress.ip_network("47.96.0.0/11"),      # Alibaba China
        ipaddress.ip_network("39.96.0.0/13"),      # Alibaba China
        ipaddress.ip_network("39.104.0.0/14"),     # Alibaba China
        ipaddress.ip_network("101.132.0.0/14"),    # Alibaba China
        ipaddress.ip_network("106.14.0.0/15"),     # Alibaba Shanghai
        ipaddress.ip_network("120.24.0.0/14"),     # Alibaba Shenzhen
        ipaddress.ip_network("120.76.0.0/14"),     # Alibaba Hangzhou
        ipaddress.ip_network("121.40.0.0/13"),     # Alibaba Hangzhou
        ipaddress.ip_network("8.208.0.0/12"),      # Alibaba International
        ipaddress.ip_network("43.128.0.0/11"),     # Tencent
        ipaddress.ip_network("49.51.0.0/16"),      # Tencent
        ipaddress.ip_network("119.28.0.0/15"),     # Tencent
        ipaddress.ip_network("129.226.0.0/16"),    # Tencent
        ipaddress.ip_network("150.109.0.0/16"),    # Tencent
        ipaddress.ip_network("117.78.0.0/17"),     # Huawei
        ipaddress.ip_network("119.3.0.0/16"),      # Huawei
        ipaddress.ip_network("121.36.0.0/15"),     # Huawei
        ipaddress.ip_network("159.138.0.0/16"),    # Huawei
    ]),
    # Singapore
    ("Singapore", "SG", "🇸🇬", [
        ipaddress.ip_network("103.21.244.0/22"),
        ipaddress.ip_network("103.28.248.0/22"),
    ]),
    # United States / Global Anycast
    ("United States", "US", "🇺🇸", [
        ipaddress.ip_network("104.16.0.0/13"),
        ipaddress.ip_network("172.64.0.0/13"),
        ipaddress.ip_network("198.41.128.0/17"),
        ipaddress.ip_network("162.158.0.0/15"),
        ipaddress.ip_network("13.32.0.0/15"),
        ipaddress.ip_network("54.192.0.0/16"),
        ipaddress.ip_network("54.230.0.0/16"),
        ipaddress.ip_network("3.0.0.0/9"),
        ipaddress.ip_network("34.192.0.0/12"),
        ipaddress.ip_network("34.64.0.0/11"),
        ipaddress.ip_network("13.64.0.0/11"),
        ipaddress.ip_network("20.0.0.0/10"),
        ipaddress.ip_network("45.76.0.0/16"),
        ipaddress.ip_network("108.61.0.0/16"),
        ipaddress.ip_network("172.104.0.0/15"),
        ipaddress.ip_network("45.33.0.0/16"),
        ipaddress.ip_network("104.131.0.0/16"),
        ipaddress.ip_network("159.203.0.0/16"),
    ]),
]


@lru_cache(maxsize=2048)
def _geo_lookup(ip_clean: str) -> Tuple[str, str, str]:
    """Cached internal geo lookup. Returns (country_name, country_code, country_flag)."""
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        for country, code, flag, networks in GEOIP_RANGES:
            for net in networks:
                if ip_obj.version == net.version and ip_obj in net:
                    return (country, code, flag)
    except Exception:
        pass
    return ("Global", "GL", "🌐")


def get_ip_geo(ip_str: str) -> Dict[str, str]:
    """Resolves IP to country name, ISO code, and emoji flag."""
    ip_clean = (ip_str or "").strip()
    if not ip_clean:
        return {"country_name": "Unknown", "country_code": "", "country_flag": "🌐"}
    name, code, flag = _geo_lookup(ip_clean)
    return {"country_name": name, "country_code": code, "country_flag": flag}


def invalidate_cache() -> None:
    """Invalidates all cached IP and Geo lookup entries across ip_intel and intelligence database."""
    _match_ip_range.cache_clear()
    _geo_lookup.cache_clear()
    GLOBAL_DATABASE.invalidate_cache()


@lru_cache(maxsize=4096)
def _match_ip_range(ip_clean: str) -> Tuple[str, bool, bool, str, str]:
    """Cached internal IP range matching. Returns (provider, is_cdn, is_origin, badge_type, label)."""
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return ("Invalid IP", False, False, "unknown", "Invalid IP")

    # 1. Check dynamic intelligence database first
    db_match = GLOBAL_DATABASE.lookup_ip(ip_clean)
    if db_match:
        name, is_cdn, is_origin, badge, label, _ = db_match
        return (name, is_cdn, is_origin, badge, label)

    # 2. Check CDN / WAF Ranges (static fallback)
    for name, networks in CDN_WAF_RANGES:
        for net in networks:
            if ip_obj.version == net.version and ip_obj in net:
                return (name, True, False, _badge_type_for_provider(name), name)

    # 3. Check Cloud Hosting (Origin Candidates)
    for name, networks in CLOUD_ORIGIN_RANGES:
        for net in networks:
            if ip_obj.version == net.version and ip_obj in net:
                return (name, False, True, "origin", f"{name} (Direct Origin)")

    # 4. Unknown / Unclassified (Phase 15: Unknown must not equal Direct Origin)
    return ("Unknown", False, False, "unknown", "Unknown / Unclassified")


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """
    Analyzes an IPv4 or IPv6 string and determines whether it belongs to a
    CDN/WAF service or is a Direct Origin IP, enriched with GeoIP location.
    Results are cached internally for repeated lookups of the same IP.
    """
    ip_clean = (ip_str or "").strip()
    if not ip_clean:
        return {
            "ip": "", "is_cdn": False, "waf_provider": "Unknown",
            "is_origin": False, "badge_type": "unknown", "label": "Unresolved",
            "country_name": "Unknown", "country_code": "", "country_flag": "🌐"
        }

    try:
        ipaddress.ip_address(ip_clean)
    except ValueError:
        return {
            "ip": ip_clean, "is_cdn": False, "waf_provider": "Invalid IP",
            "is_origin": False, "badge_type": "unknown", "label": "Invalid IP",
            "country_name": "Unknown", "country_code": "", "country_flag": "🌐"
        }

    single_res = GLOBAL_CORRELATION_ENGINE.classify_single_ip(ip_clean)
    geo_name, geo_code, geo_flag = _geo_lookup(ip_clean)

    return {
        "ip": ip_clean,
        "is_cdn": single_res.is_cdn,
        "waf_provider": single_res.waf_provider,
        "is_origin": single_res.is_origin,
        "badge_type": single_res.badge_type,
        "label": single_res.label,
        "country_name": geo_name,
        "country_code": geo_code,
        "country_flag": geo_flag,
        "network_provider": single_res.network_provider,
        "service_provider": single_res.service_provider,
        "waf_confirmed": single_res.waf_confirmed,
        "confidence": single_res.confidence,
        "evidence": single_res.evidence.to_dict(),
        "status": single_res.status,
        "asn": single_res.asn,
        "asn_org": single_res.asn_org,
    }


def classify_ips(ip_list: List[str], cname: str = "") -> Dict[str, Any]:
    """
    Classifies a list of IPs (and optional CNAME) for a subdomain and returns summary intel.
    Every resolved IP is independently classified (Phase 14).
    If a CNAME indicates a CDN/WAF provider, it takes precedence or augments the detection.
    """
    return GLOBAL_CORRELATION_ENGINE.classify_ips_multi(ip_list, cname_str=cname, get_geo_func=get_ip_geo)
