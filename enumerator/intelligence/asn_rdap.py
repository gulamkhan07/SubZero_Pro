"""
ASN and RDAP Intelligence & Enrichment Layer.
Provides network ownership signals without equating ASN ownership to WAF confirmation.
Caches lookups per-IP and handles conflicts and graceful failure.
"""
from functools import lru_cache
import logging
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from enumerator.intelligence.config import GLOBAL_CONFIG, IntelligenceConfig
from enumerator.intelligence.registry import PROVIDER_REGISTRY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("subzero.intel.asn")

# Build reverse ASN -> Provider Name lookup table from registry
ASN_TO_PROVIDERS: Dict[int, List[str]] = {}
for name, meta in PROVIDER_REGISTRY.items():
    for asn in meta.asns:
        ASN_TO_PROVIDERS.setdefault(asn, []).append(name)


class AsnRdapService:
    """
    Enriches IP addresses with Autonomous System (ASN) and RDAP metadata.
    Treats ASN as supporting network evidence, never definitive WAF proof.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None, session: Optional[requests.Session] = None):
        self.config = config or GLOBAL_CONFIG
        self.session = session or requests.Session()
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

    def get_providers_for_asn(self, asn: int) -> List[str]:
        """Returns verified providers associated with an Autonomous System Number."""
        return ASN_TO_PROVIDERS.get(asn, [])

    def lookup_ip_intel(self, ip_str: str) -> Dict[str, Any]:
        """
        Enriches an IP with ASN and RDAP data using in-memory cache and graceful fallback.
        Returns:
            {
                "asn": Optional[int],
                "asn_org": str,
                "rdap_org": str,
                "asn_providers": List[str],
                "status": "enriched" | "unavailable"
            }
        """
        clean_ip = (ip_str or "").strip()
        if not clean_ip:
            return {"asn": None, "asn_org": "", "rdap_org": "", "asn_providers": [], "status": "unavailable"}

        if clean_ip in self._memory_cache:
            return self._memory_cache[clean_ip]

        result = {
            "asn": None,
            "asn_org": "",
            "rdap_org": "",
            "asn_providers": [],
            "status": "unavailable",
        }

        # If ASN/RDAP is disabled via config, return empty enriched shell
        if not self.config.enable_asn_enrichment and not self.config.enable_rdap_enrichment:
            self._memory_cache[clean_ip] = result
            return result

        # Optional online RDAP / ASN lookup with fast timeout (only when live updates enabled)
        if self.config.enable_rdap_enrichment and self.config.enable_live_updates:
            try:
                # Fast ARIN/RDAP bootstrap query with strict timeout
                rdap_url = f"https://rdap.arin.net/registry/ip/{clean_ip}"
                resp = self.session.get(
                    rdap_url,
                    timeout=self.config.request_timeout,
                    headers={"Accept": "application/rdap+json, application/json"},
                    verify=False,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name", "")
                    handle = data.get("handle", "")
                    org = name or handle or ""
                    result["rdap_org"] = org
                    result["status"] = "enriched"
            except Exception:
                # Failure must never block reconnaissance
                pass

        self._memory_cache[clean_ip] = result
        return result

    def detect_asn_cidr_conflict(
        self,
        cidr_provider: Optional[str],
        asn_providers: List[str]
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Checks for discrepancies between CIDR matching and ASN ownership.
        Returns (is_conflict, candidates_list).
        """
        if not cidr_provider and not asn_providers:
            return False, []

        candidates = []
        if cidr_provider:
            candidates.append({
                "provider": cidr_provider,
                "cidr_match": True,
                "asn_match": cidr_provider in asn_providers,
            })

        for p in asn_providers:
            if p != cidr_provider:
                candidates.append({
                    "provider": p,
                    "cidr_match": False,
                    "asn_match": True,
                })

        is_conflict = len(candidates) > 1 and any(not c["asn_match"] or not c["cidr_match"] for c in candidates)
        return is_conflict, candidates


GLOBAL_ASN_RDAP = AsnRdapService()
