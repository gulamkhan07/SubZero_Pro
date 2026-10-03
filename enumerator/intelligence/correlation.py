"""
Evidence-Based Correlation Engine for SubZero.
Combines CIDR network matching, ASN ownership, CNAME signatures, and HTTP fingerprints.
Enforces evidence hierarchy: HTTP > CNAME > CIDR > ASN > RDAP.
Distinguishes Network Provider from WAF Confirmation, and Unknown from Direct Origin.
"""
from functools import lru_cache
import logging
from typing import Any, Dict, List, Optional, Tuple

from enumerator.intelligence.asn_rdap import GLOBAL_ASN_RDAP, AsnRdapService
from enumerator.intelligence.database import GLOBAL_DATABASE, IntelligenceDatabase
from enumerator.intelligence.models import (
    EvidenceBundle,
    ProviderCategory,
    SingleIPClassification,
)
from enumerator.intelligence.registry import PROVIDER_REGISTRY, get_provider

logger = logging.getLogger("subzero.intel.correlation")


class CorrelationEngine:
    """
    Correlates multiple signals to arrive at an evidence-backed classification.
    """

    def __init__(
        self,
        db: Optional[IntelligenceDatabase] = None,
        asn_service: Optional[AsnRdapService] = None
    ):
        self.db = db or GLOBAL_DATABASE
        self.asn_service = asn_service or GLOBAL_ASN_RDAP

    def classify_single_ip(
        self,
        ip_str: str,
        cname_str: str = "",
        http_waf_info: Optional[Dict[str, Any]] = None,
        asn_override: Optional[int] = None,
    ) -> SingleIPClassification:
        """
        Classifies an individual IP address with full evidence correlation.
        """
        clean_ip = (ip_str or "").strip()
        if not clean_ip:
            return SingleIPClassification(
                ip="",
                network_provider="Unknown",
                service_provider="Unknown",
                waf_provider="Unknown",
                waf_confirmed=False,
                is_cdn=False,
                is_origin=False,
                badge_type="none",
                label="No IP",
                confidence="none",
                evidence=EvidenceBundle(),
                status="unknown",
            )

        evidence = EvidenceBundle()

        # 1. CIDR Network Lookup
        cidr_match = self.db.lookup_ip(clean_ip)
        cidr_provider = None
        is_cdn_cidr = False
        is_origin_cidr = False
        badge_type = "unknown"
        label = "Unknown / Unclassified"

        if cidr_match:
            cidr_provider, is_cdn_cidr, is_origin_cidr, badge_type, label, prov_data = cidr_match
            evidence.cidr_match = True
            evidence.details["cidr_provider"] = cidr_provider
            evidence.details["provenance"] = prov_data

        # 2. ASN Enrichment
        asn_info = self.asn_service.lookup_ip_intel(clean_ip)
        effective_asn = asn_override or asn_info.get("asn")
        asn_providers = self.asn_service.get_providers_for_asn(effective_asn) if effective_asn else []
        if effective_asn:
            evidence.asn_match = bool(asn_providers)
            evidence.details["asn"] = effective_asn
            evidence.details["asn_providers"] = asn_providers

        # 3. CNAME Fingerprinting
        cname_match = self.classify_cname_strict(cname_str) if cname_str else None
        if cname_match:
            evidence.cname_match = True
            evidence.details["cname_provider"] = cname_match.get("waf_provider")

        # 4. HTTP Evidence
        if http_waf_info:
            evidence.http_headers_match = bool(http_waf_info.get("waf_provider"))
            evidence.http_body_match = bool(http_waf_info.get("is_blocked"))
            evidence.details["http_provider"] = http_waf_info.get("waf_provider")
            evidence.details["http_evidence"] = http_waf_info.get("evidence", "")

        # ---------------------------------------------------------------------
        # Correlation & Evidence Hierarchy Resolution
        # ---------------------------------------------------------------------
        network_provider = cidr_provider or (asn_providers[0] if asn_providers else "Unknown")
        service_provider = "Unknown"
        waf_provider = "None"
        waf_confirmed = False
        is_cdn = False
        is_origin = False
        confidence = "none"
        status = "classified"

        # Signal 1: HTTP-Level Evidence (Highest Authority for active protection)
        if http_waf_info and http_waf_info.get("waf_provider"):
            http_p = http_waf_info["waf_provider"]
            service_provider = http_p
            waf_provider = http_p
            waf_confirmed = True
            is_cdn = True
            is_origin = False
            badge_type = http_waf_info.get("badge_type") or "waf"
            label = http_p
            confidence = "high"

        # Signal 2: CNAME-Level Evidence
        elif cname_match:
            cname_p = cname_match["waf_provider"]
            service_provider = cname_p
            waf_provider = cname_p
            is_cdn = cname_match["is_cdn"]
            is_origin = cname_match["is_origin"]
            badge_type = cname_match["badge_type"]
            label = f"{cname_p} (CNAME)"

            # If CNAME and CIDR agree -> high confidence
            if cidr_provider and (cidr_provider.lower() in cname_p.lower() or cname_p.lower() in cidr_provider.lower()):
                waf_confirmed = is_cdn
                confidence = "high"
            else:
                waf_confirmed = is_cdn
                confidence = "medium"

        # Signal 3: CIDR Network Match
        elif cidr_match:
            service_provider = cidr_provider
            badge_type = cidr_match[3]
            label = cidr_match[4]
            is_cdn = is_cdn_cidr
            is_origin = is_origin_cidr

            if is_cdn:
                waf_provider = cidr_provider
                # CIDR match alone indicates provider network detected, NOT definitive active WAF rule enforcement
                waf_confirmed = False
                confidence = "medium"
            else:
                # Cloud Origin candidate (AWS EC2, Hetzner, etc.)
                waf_provider = cidr_provider
                waf_confirmed = False
                confidence = "high" if is_origin else "medium"

        # Signal 4: ASN-Only Evidence
        elif asn_providers:
            asn_p = asn_providers[0]
            network_provider = asn_p
            meta = get_provider(asn_p)
            if meta:
                is_cdn = meta.is_cdn
                is_origin = meta.is_origin
                badge_type = meta.badge_type
                label = f"{asn_p} (ASN)"
                waf_provider = asn_p
            confidence = "low"

        # Signal 5: Completely Unrecognized -> UNKNOWN MUST NOT EQUAL DIRECT ORIGIN (Phase 15)
        else:
            network_provider = "Unknown"
            service_provider = "Unknown"
            waf_provider = "Unknown"
            waf_confirmed = False
            is_cdn = False
            is_origin = False
            badge_type = "unknown"
            label = "Unknown / Unclassified"
            confidence = "none"
            status = "unknown"

        # Check for ASN vs CIDR discrepancy
        is_conflict, conflict_candidates = self.asn_service.detect_asn_cidr_conflict(cidr_provider, asn_providers)
        if is_conflict:
            status = "conflicting"
            evidence.details["conflict_candidates"] = conflict_candidates

        return SingleIPClassification(
            ip=clean_ip,
            network_provider=network_provider,
            service_provider=service_provider,
            waf_provider=waf_provider,
            waf_confirmed=waf_confirmed,
            is_cdn=is_cdn,
            is_origin=is_origin,
            badge_type=badge_type,
            label=label,
            confidence=confidence,
            evidence=evidence,
            status=status,
            asn=effective_asn,
            asn_org=asn_info.get("asn_org", ""),
            rdap_org=asn_info.get("rdap_org", ""),
        )

    def classify_cname_strict(self, cname_str: str) -> Optional[Dict[str, Any]]:
        """
        Strict DNS label & suffix CNAME matcher. Avoids broad substring false positives.
        """
        cname_clean = (cname_str or "").strip().lower().rstrip(".")
        if not cname_clean:
            return None

        for name, meta in PROVIDER_REGISTRY.items():
            for pattern in meta.cname_signatures:
                pat_clean = pattern.strip().lower().rstrip(".")
                if cname_clean == pat_clean or cname_clean.endswith(f".{pat_clean}"):
                    return {
                        "is_cdn": meta.is_cdn,
                        "waf_provider": meta.name,
                        "is_origin": meta.is_origin,
                        "badge_type": meta.badge_type,
                        "label": meta.name,
                        "detected_via": "cname",
                        "cname": cname_clean,
                    }
        return None

    def classify_ips_multi(
        self,
        ip_list: List[str],
        cname_str: str = "",
        http_waf_info: Optional[Dict[str, Any]] = None,
        get_geo_func=None,
    ) -> Dict[str, Any]:
        """
        Classifies every resolved IP independently, gathers per-IP evidence,
        and constructs an aggregate summary without discarding secondary IPs.
        """
        valid_ips = [ip.strip() for ip in (ip_list or []) if ip and ip.strip()]

        if not valid_ips:
            cname_res = self.classify_cname_strict(cname_str) if cname_str else None
            if cname_res:
                return {
                    "primary_ip": "",
                    "all_ips": [],
                    "all_ip_classifications": [],
                    "is_cdn": cname_res["is_cdn"],
                    "waf_provider": cname_res["waf_provider"],
                    "is_origin": cname_res["is_origin"],
                    "badge_type": cname_res["badge_type"],
                    "label": f"{cname_res['waf_provider']} (CNAME)",
                    "cname": cname_str.strip(),
                    "summary": {
                        "providers": [cname_res["waf_provider"]],
                        "has_cdn": cname_res["is_cdn"],
                        "has_origin_candidate": cname_res["is_origin"],
                    },
                }
            return {
                "primary_ip": "",
                "all_ips": [],
                "all_ip_classifications": [],
                "is_cdn": False,
                "waf_provider": "None",
                "is_origin": False,
                "badge_type": "none",
                "label": "No IP",
                "summary": {
                    "providers": [],
                    "has_cdn": False,
                    "has_origin_candidate": False,
                },
            }

        # Classify each IP independently
        classifications: List[SingleIPClassification] = []
        for ip in valid_ips:
            cls = self.classify_single_ip(ip, cname_str=cname_str, http_waf_info=http_waf_info)
            if get_geo_func:
                geo = get_geo_func(ip)
                cls.country_name = geo.get("country_name", "Global")
                cls.country_code = geo.get("country_code", "")
                cls.country_flag = geo.get("country_flag", "🌐")
            classifications.append(cls)

        primary_cls = classifications[0]

        # Aggregate summary across all IPs
        detected_providers = list(dict.fromkeys(c.waf_provider for c in classifications if c.waf_provider not in ("None", "Unknown")))
        has_cdn = any(c.is_cdn for c in classifications)
        has_origin = any(c.is_origin for c in classifications)

        # Legacy-compatible primary payload enriched with multi-IP data
        result: Dict[str, Any] = {
            "primary_ip": primary_cls.ip,
            "all_ips": valid_ips,
            "all_ip_classifications": [c.to_dict() for c in classifications],
            "is_cdn": has_cdn,
            "is_origin": primary_cls.is_origin,
            "waf_provider": primary_cls.waf_provider,
            "badge_type": primary_cls.badge_type,
            "label": primary_cls.label,
            "country_name": primary_cls.country_name,
            "country_code": primary_cls.country_code,
            "country_flag": primary_cls.country_flag,
            "confidence": primary_cls.confidence,
            "waf_confirmed": primary_cls.waf_confirmed,
            "summary": {
                "providers": detected_providers,
                "has_cdn": has_cdn,
                "has_origin_candidate": has_origin,
                "total_ips": len(valid_ips),
            },
        }

        # If primary IP is origin/unknown but CNAME definitively points to a CDN/WAF:
        cname_match = self.classify_cname_strict(cname_str) if cname_str else None
        if cname_match and not result["is_cdn"]:
            result["is_cdn"] = True
            result["waf_provider"] = cname_match["waf_provider"]
            result["is_origin"] = False
            result["badge_type"] = cname_match["badge_type"]
            result["label"] = f"{cname_match['waf_provider']} (CNAME)"
            result["cname"] = cname_str.strip()

        return result


GLOBAL_CORRELATION_ENGINE = CorrelationEngine()
