"""
Dynamic Intelligence Updater & Feed Adapters.
Refreshes provider network ranges using official machine-readable feeds.
Maintains ETag, Last-Modified, versioning, change detection, and Last-Known-Good fallback.
Developed by: Gulam Khan
"""
import datetime
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
import urllib3

from enumerator.intelligence.config import GLOBAL_CONFIG, IntelligenceConfig
from enumerator.intelligence.database import GLOBAL_DATABASE, IntelligenceDatabase
from enumerator.intelligence.models import (
    DynamicSourceType,
    ProviderDataset,
    RangeProvenance,
)
from enumerator.intelligence.registry import PROVIDER_REGISTRY, get_provider
from enumerator.intelligence.validation import (
    sanitize_and_deduplicate_cidrs,
    validate_dataset_change,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("subzero.intel.updater")


class IntelligenceUpdater:
    """
    Manages downloading, validating, and updating provider network intelligence.
    """

    def __init__(
        self,
        db: Optional[IntelligenceDatabase] = None,
        config: Optional[IntelligenceConfig] = None,
        session: Optional[requests.Session] = None,
    ):
        self.db = db or GLOBAL_DATABASE
        self.config = config or GLOBAL_CONFIG
        self.session = session or requests.Session()
        if self.config.proxy_url:
            self.session.proxies = {
                "http": self.config.proxy_url,
                "https": self.config.proxy_url,
            }

    def update_provider(self, provider_name: str, force: bool = False) -> Dict[str, Any]:
        """
        Refreshes a specific provider's ranges from its authoritative source.
        Returns a summary dictionary of the update result.
        """
        meta = get_provider(provider_name)
        if not meta:
            return {"status": "error", "message": f"Provider '{provider_name}' not found in registry."}

        existing_dataset = self.db.providers.get(provider_name)
        url = meta.source_url

        if not url or meta.strategy in (DynamicSourceType.CNAME_HTTP_ONLY, DynamicSourceType.STATIC_FALLBACK):
            return {
                "status": "skipped",
                "provider": provider_name,
                "message": f"Provider '{provider_name}' uses {meta.strategy.value}; no public range feed available.",
            }

        # Check freshness unless force=True
        if not force and existing_dataset and existing_dataset.last_checked:
            try:
                last_dt = datetime.datetime.fromisoformat(existing_dataset.last_checked)
                age_hours = (datetime.datetime.now(datetime.timezone.utc) - last_dt).total_seconds() / 3600.0
                if age_hours < meta.refresh_interval_hours:
                    logger.debug(f"[INTEL] {provider_name} feed is fresh ({round(age_hours, 1)}h old), skipping.")
                    return {
                        "status": "cached",
                        "provider": provider_name,
                        "age_hours": age_hours,
                        "message": "Feed is still fresh within configured interval.",
                    }
            except Exception:
                pass

        headers = {
            "User-Agent": "SubZero-IntelligenceUpdater/2.2",
            "Accept": "application/json, text/plain, */*",
        }
        if existing_dataset and existing_dataset.etag:
            headers["If-None-Match"] = existing_dataset.etag

        logger.info(f"[INTEL] {provider_name} feed checked: {url}")
        try:
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.config.request_timeout,
                verify=False,
            )
        except Exception as exc:
            msg = f"Network failure fetching {provider_name} ({exc}). Using last-known-good dataset."
            logger.warning(f"[INTEL] {msg}")
            if existing_dataset:
                existing_dataset.status = "stale"
            return {"status": "stale_fallback", "provider": provider_name, "error": str(exc), "message": msg}

        # HTTP 304 Not Modified
        if resp.status_code == 304:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if existing_dataset:
                existing_dataset.last_checked = now_iso
                existing_dataset.status = "healthy"
            logger.info(f"[INTEL] {provider_name} unchanged (HTTP 304).")
            return {"status": "unchanged", "provider": provider_name, "message": "Content not modified (ETag)."}

        if resp.status_code != 200:
            msg = f"HTTP {resp.status_code} received from {url}. Preserving last-known-good dataset."
            logger.warning(f"[INTEL] {msg}")
            if existing_dataset:
                existing_dataset.status = "stale"
            return {"status": "stale_fallback", "provider": provider_name, "error": f"HTTP {resp.status_code}", "message": msg}

        # Parse downloaded content
        raw_cidrs, new_version = self._parse_feed_response(provider_name, meta.strategy, resp)
        if not raw_cidrs:
            msg = f"Downloaded content for {provider_name} contained no CIDRs. Provider dataset rejected."
            logger.warning(f"[INTEL] {msg}")
            if existing_dataset:
                existing_dataset.status = "stale"
            return {"status": "rejected", "provider": provider_name, "error": "empty_or_invalid_feed", "message": msg}

        # Sanitize and deduplicate
        valid_cidrs, rejected = sanitize_and_deduplicate_cidrs(raw_cidrs)
        if rejected:
            logger.debug(f"[INTEL] {provider_name}: rejected {len(rejected)} invalid CIDRs: {rejected[:3]}")

        # Catastrophic change validation
        prev_all = (existing_dataset.ipv4 + existing_dataset.ipv6) if existing_dataset else []
        is_valid, reason = validate_dataset_change(provider_name, valid_cidrs, prev_all)

        if not is_valid:
            msg = f"Dataset change rejected for {provider_name}: {reason}"
            logger.warning(f"[INTEL] Provider dataset rejected. {msg}")
            if existing_dataset:
                existing_dataset.status = "stale"
            return {"status": "rejected", "provider": provider_name, "reason": reason, "message": msg}

        # Partition IPv4 and IPv6
        new_v4 = []
        new_v6 = []
        for c in valid_cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                if net.version == 4:
                    new_v4.append(c)
                else:
                    new_v6.append(c)
            except Exception:
                continue

        # Diff calculation
        prev_set = set(prev_all)
        new_set = set(valid_cidrs)
        added = sorted(new_set - prev_set)
        removed = sorted(prev_set - new_set)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        etag = resp.headers.get("ETag") or resp.headers.get("etag")

        provenance = [
            RangeProvenance(
                cidr=c,
                provider=provider_name,
                source=meta.strategy.value,
                source_url=url,
                retrieved_at=now_iso,
                feed_version=new_version or etag or "1.0",
            ).to_dict()
            for c in valid_cidrs
        ]

        updated_dataset = ProviderDataset(
            provider=provider_name,
            category=meta.category.value,
            ipv4=new_v4,
            ipv6=new_v6,
            asns=meta.asns,
            source="official",
            source_url=url,
            last_checked=now_iso,
            last_changed=now_iso if (added or removed or not existing_dataset) else (existing_dataset.last_changed if existing_dataset else now_iso),
            etag=etag,
            version=new_version or (existing_dataset.version if existing_dataset else "1.0"),
            status="healthy",
            provenance=provenance,
        )

        self.db.update_provider_dataset(updated_dataset)
        self.db.invalidate_cache()
        self.db.save_to_cache()

        if added or removed:
            logger.info(f"[INTEL] {provider_name} updated: +{len(added)} / -{len(removed)} CIDRs.")
        else:
            logger.info(f"[INTEL] {provider_name} unchanged.")

        return {
            "status": "updated",
            "provider": provider_name,
            "total_cidrs": len(valid_cidrs),
            "ipv4_count": len(new_v4),
            "ipv6_count": len(new_v6),
            "added_count": len(added),
            "removed_count": len(removed),
            "added": added[:5],
            "removed": removed[:5],
            "etag": etag,
        }

    def update_all(self, force: bool = False) -> Dict[str, Any]:
        """
        Updates all registered providers that have dynamic endpoints.
        """
        results = {}
        for name in PROVIDER_REGISTRY.keys():
            results[name] = self.update_provider(name, force=force)
        return results

    def _parse_feed_response(
        self, provider: str, strategy: DynamicSourceType, resp: requests.Response
    ) -> Tuple[List[str], Optional[str]]:
        """Parses feed response based on provider conventions."""
        try:
            data = resp.json()
        except Exception:
            # Fallback to plain text line-by-line
            lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]
            return lines, None

        cidrs: List[str] = []
        version: Optional[str] = None

        # 1. Cloudflare Official API
        if provider == "Cloudflare WAF":
            # {"result": {"ipv4_cidrs": [...], "ipv6_cidrs": [...]}}
            res_obj = data.get("result", {})
            cidrs.extend(res_obj.get("ipv4_cidrs", []))
            cidrs.extend(res_obj.get("ipv6_cidrs", []))

        # 2. AWS WAF / CloudFront & AWS EC2
        elif provider in ("AWS WAF", "AWS EC2 / Compute"):
            version = str(data.get("syncToken", ""))
            prefixes = data.get("prefixes", [])
            ipv6_prefixes = data.get("ipv6_prefixes", [])

            is_waf = (provider == "AWS WAF")
            target_services = {"CLOUDFRONT", "GLOBALACCELERATOR"} if is_waf else {"EC2", "AMAZON"}

            for p in prefixes:
                srv = p.get("service", "").upper()
                if is_waf:
                    if srv in target_services:
                        cidrs.append(p.get("ip_prefix", ""))
                else:
                    if srv == "EC2":
                        cidrs.append(p.get("ip_prefix", ""))

            for p in ipv6_prefixes:
                srv = p.get("service", "").upper()
                if is_waf:
                    if srv in target_services:
                        cidrs.append(p.get("ipv6_prefix", ""))
                else:
                    if srv == "EC2":
                        cidrs.append(p.get("ipv6_prefix", ""))

        # 3. Google Cloud Armor & GCP Compute
        elif provider in ("Google Cloud Armor", "Google Cloud (GCP)"):
            prefixes = data.get("prefixes", [])
            for p in prefixes:
                if "ipv4Prefix" in p:
                    cidrs.append(p["ipv4Prefix"])
                if "ipv6Prefix" in p:
                    cidrs.append(p["ipv6Prefix"])

        # 4. Fastly CDN
        elif provider == "Fastly CDN":
            cidrs.extend(data.get("addresses", []))
            cidrs.extend(data.get("ipv6_addresses", []))

        # 5. BunnyCDN
        elif provider == "BunnyCDN":
            if isinstance(data, list):
                cidrs.extend([str(item) for item in data if isinstance(item, str)])

        # 6. Oracle Cloud (OCI)
        elif provider == "Oracle Cloud (OCI)":
            regions = data.get("regions", [])
            for r in regions:
                for cidr_obj in r.get("cidrs", []):
                    c = cidr_obj.get("cidr")
                    if c:
                        cidrs.append(c)

        # 7. Generic JSON array or object
        else:
            if isinstance(data, list):
                cidrs.extend([str(x) for x in data if isinstance(x, str)])
            elif isinstance(data, dict):
                for val in data.values():
                    if isinstance(val, list):
                        cidrs.extend([str(x) for x in val if isinstance(x, str)])

        return cidrs, version


# Global updater instance
GLOBAL_UPDATER = IntelligenceUpdater()
