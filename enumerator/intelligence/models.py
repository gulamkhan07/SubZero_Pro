"""
Data models and type definitions for SubZero Dynamic Intelligence Engine.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ProviderCategory(str, Enum):
    WAF_CDN = "waf_cdn"
    CDN_EDGE = "cdn_edge"
    CLOUD_ORIGIN = "cloud_origin"
    VPS_HOSTING = "vps_hosting"
    REGIONAL_SOVEREIGN_CLOUD = "regional_sovereign_cloud"
    OTHER_INFRASTRUCTURE = "other_infrastructure"


class DynamicSourceType(str, Enum):
    OFFICIAL_JSON = "official_json"
    OFFICIAL_API = "official_api"
    SERVICE_TAG = "service_tag"
    ASN_BGP = "asn_bgp"
    VENDOR_SOURCE = "vendor_source"
    CNAME_HTTP_ONLY = "cname_http_only"
    STATIC_FALLBACK = "static_fallback"


class TrustLevel(str, Enum):
    AUTHORITATIVE = "authoritative"
    VERIFIED_VENDOR = "verified_vendor"
    ASN_INFERRED = "asn_inferred"
    HEURISTIC = "heuristic"


@dataclass
class RangeProvenance:
    cidr: str
    provider: str
    source: str
    source_url: str = ""
    retrieved_at: str = ""
    feed_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cidr": self.cidr,
            "provider": self.provider,
            "source": self.source,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "feed_version": self.feed_version,
        }


@dataclass
class ProviderMetadata:
    name: str
    category: ProviderCategory
    is_cdn: bool
    is_origin: bool
    badge_type: str
    strategy: DynamicSourceType
    source_url: str = ""
    asns: List[int] = field(default_factory=list)
    cname_signatures: List[str] = field(default_factory=list)
    http_headers: List[str] = field(default_factory=list)
    http_servers: List[str] = field(default_factory=list)
    http_body_signatures: List[str] = field(default_factory=list)
    refresh_interval_hours: int = 24
    trust_level: TrustLevel = TrustLevel.HEURISTIC
    fallback_strategy: str = "use_last_known_good"


@dataclass
class ProviderDataset:
    provider: str
    category: str
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    asns: List[int] = field(default_factory=list)
    source: str = "official"
    source_url: str = ""
    last_checked: str = ""
    last_changed: str = ""
    etag: Optional[str] = None
    version: Optional[str] = None
    status: str = "healthy"  # "healthy", "stale", "rejected"
    provenance: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "category": self.category,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "asns": self.asns,
            "source": self.source,
            "source_url": self.source_url,
            "last_checked": self.last_checked,
            "last_changed": self.last_changed,
            "etag": self.etag,
            "version": self.version,
            "status": self.status,
            "provenance": self.provenance,
        }


@dataclass
class EvidenceBundle:
    cidr_match: bool = False
    asn_match: bool = False
    rdap_match: bool = False
    cname_match: bool = False
    http_headers_match: bool = False
    http_body_match: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cidr": self.cidr_match,
            "asn": self.asn_match,
            "rdap": self.rdap_match,
            "cname": self.cname_match,
            "http_headers": self.http_headers_match,
            "http_body": self.http_body_match,
            "details": self.details,
        }


@dataclass
class SingleIPClassification:
    ip: str
    network_provider: str
    service_provider: str
    waf_provider: str
    waf_confirmed: bool
    is_cdn: bool
    is_origin: bool
    badge_type: str
    label: str
    confidence: str  # "high", "medium", "low", "none"
    evidence: EvidenceBundle
    country_name: str = "Global"
    country_code: str = ""
    country_flag: str = "🌐"
    asn: Optional[int] = None
    asn_org: str = ""
    rdap_org: str = ""
    status: str = "classified"  # "classified", "unknown", "conflicting"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "network_provider": self.network_provider,
            "service_provider": self.service_provider,
            "waf_provider": self.waf_provider,
            "waf_confirmed": self.waf_confirmed,
            "is_cdn": self.is_cdn,
            "is_origin": self.is_origin,
            "badge_type": self.badge_type,
            "label": self.label,
            "confidence": self.confidence,
            "evidence": self.evidence.to_dict(),
            "country_name": self.country_name,
            "country_code": self.country_code,
            "country_flag": self.country_flag,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "rdap_org": self.rdap_org,
            "status": self.status,
        }
