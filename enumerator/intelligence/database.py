"""
Intelligence Database & In-Memory CIDR Lookup Engine.
Loads Last-Known-Good (LKG) datasets and overlays dynamic cached feeds.
"""
import ipaddress
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from enumerator.intelligence.config import GLOBAL_CONFIG, IntelligenceConfig
from enumerator.intelligence.models import (
    DynamicSourceType,
    ProviderCategory,
    ProviderDataset,
    RangeProvenance,
)
from enumerator.intelligence.registry import PROVIDER_REGISTRY, get_provider

logger = logging.getLogger("subzero.intel.database")

NetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class IntelligenceDatabase:
    """
    Thread-safe intelligence database that indexes provider CIDRs, ASNs,
    and metadata for sub-millisecond local queries.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None):
        self.config = config or GLOBAL_CONFIG
        self._lock = threading.RLock()
        self.providers: Dict[str, ProviderDataset] = {}
        # Precompiled network lists for fast iteration
        self._ipv4_entries: List[Tuple[ipaddress.IPv4Network, str, bool, bool, str, str, Dict[str, Any]]] = []
        self._ipv6_entries: List[Tuple[ipaddress.IPv6Network, str, bool, bool, str, str, Dict[str, Any]]] = []
        # Cache for exact IP string lookups
        self._ip_cache: Dict[str, Optional[Tuple[str, bool, bool, str, str, Dict[str, Any]]]] = {}
        self.load()

    def invalidate_cache(self) -> None:
        """Flushes the local IP query cache."""
        with self._lock:
            self._ip_cache.clear()

    def _get_lkg_file_path(self) -> Path:
        """Returns the path to the bundled LKG baseline JSON."""
        return Path(__file__).resolve().parent / "data" / "lkg_intelligence.json"

    def _get_cache_file_path(self) -> Path:
        """Returns the path to the dynamic cache file."""
        return Path(self.config.cache_dir) / "dynamic_intelligence.json"

    def load(self) -> None:
        """Loads intelligence from bundled LKG baseline and overlays cached updates."""
        with self._lock:
            self.providers.clear()
            self._ipv4_entries.clear()
            self._ipv6_entries.clear()
            self._ip_cache.clear()

            # 1. Load bundled LKG baseline
            lkg_path = self._get_lkg_file_path()
            if lkg_path.exists():
                try:
                    with open(lkg_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    for name, pdata in data.get("providers", {}).items():
                        self.providers[name] = ProviderDataset(
                            provider=name,
                            category=pdata.get("category", "waf_cdn"),
                            ipv4=pdata.get("ipv4", []),
                            ipv6=pdata.get("ipv6", []),
                            asns=pdata.get("asns", []),
                            source=pdata.get("source", "baseline"),
                            source_url=pdata.get("source_url", ""),
                            last_checked=pdata.get("last_checked", ""),
                            last_changed=pdata.get("last_changed", ""),
                            etag=pdata.get("etag"),
                            version=pdata.get("version", "1.0.0"),
                            status=pdata.get("status", "healthy"),
                            provenance=pdata.get("provenance", []),
                        )
                    logger.debug(f"[INTEL] Loaded {len(self.providers)} providers from LKG baseline.")
                except Exception as e:
                    logger.error(f"[INTEL] Failed to load LKG baseline: {e}")

            # 2. Overlay dynamic cache if exists
            cache_path = self._get_cache_file_path()
            if cache_path.exists():
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        cached_data = json.load(f)
                    for name, pdata in cached_data.get("providers", {}).items():
                        # Update or insert
                        self.providers[name] = ProviderDataset(
                            provider=name,
                            category=pdata.get("category", "waf_cdn"),
                            ipv4=pdata.get("ipv4", []),
                            ipv6=pdata.get("ipv6", []),
                            asns=pdata.get("asns", []),
                            source=pdata.get("source", "dynamic_cache"),
                            source_url=pdata.get("source_url", ""),
                            last_checked=pdata.get("last_checked", ""),
                            last_changed=pdata.get("last_changed", ""),
                            etag=pdata.get("etag"),
                            version=pdata.get("version"),
                            status=pdata.get("status", "healthy"),
                            provenance=pdata.get("provenance", []),
                        )
                    logger.debug(f"[INTEL] Overlaid dynamic cache from {cache_path}")
                except Exception as e:
                    logger.warning(f"[INTEL] Failed to load dynamic cache, using LKG: {e}")

            # 3. Build indexed CIDR tables
            self._rebuild_indices()

    def _rebuild_indices(self) -> None:
        """Compiles string CIDRs into IPv4Network and IPv6Network objects."""
        new_v4 = []
        new_v6 = []

        for name, dataset in self.providers.items():
            meta = get_provider(name)
            is_cdn = meta.is_cdn if meta else ("waf" in dataset.category or "cdn" in dataset.category)
            is_origin = meta.is_origin if meta else ("origin" in dataset.category or "hosting" in dataset.category)
            badge_type = meta.badge_type if meta else ("waf" if is_cdn else "origin")
            label = f"{name} (Direct Origin)" if is_origin else name

            # Build provenance lookup map
            prov_map = {p.get("cidr"): p for p in dataset.provenance if isinstance(p, dict)}

            for cidr in dataset.ipv4:
                try:
                    net = ipaddress.ip_network(cidr.strip(), strict=False)
                    provenance = prov_map.get(cidr, {"cidr": cidr, "provider": name, "source": dataset.source})
                    new_v4.append((net, name, is_cdn, is_origin, badge_type, label, provenance))
                except Exception:
                    continue

            for cidr in dataset.ipv6:
                try:
                    net = ipaddress.ip_network(cidr.strip(), strict=False)
                    provenance = prov_map.get(cidr, {"cidr": cidr, "provider": name, "source": dataset.source})
                    new_v6.append((net, name, is_cdn, is_origin, badge_type, label, provenance))
                except Exception:
                    continue

        # Longest Prefix Match (LPM): specific subnets (/24) take precedence over broad supernets (/16)
        new_v4.sort(key=lambda x: x[0].prefixlen, reverse=True)
        new_v6.sort(key=lambda x: x[0].prefixlen, reverse=True)

        self._ipv4_entries = new_v4
        self._ipv6_entries = new_v6
        self._ip_cache.clear()

    def save_to_cache(self) -> None:
        """Persists the current state to the configured dynamic cache file."""
        with self._lock:
            cache_path = self._get_cache_file_path()
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                payload = {
                    "version": 2,
                    "providers": {k: v.to_dict() for k, v in self.providers.items()},
                }
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                logger.info(f"[INTEL] Saved intelligence database to {cache_path}")
            except Exception as e:
                logger.error(f"[INTEL] Failed to save intelligence cache: {e}")

    def update_provider_dataset(self, dataset: ProviderDataset) -> None:
        """Updates or registers a provider dataset and rebuilds lookup indices."""
        with self._lock:
            self.providers[dataset.provider] = dataset
            self._rebuild_indices()

    def lookup_ip(self, ip_clean: str) -> Optional[Tuple[str, bool, bool, str, str, Dict[str, Any]]]:
        """
        Fast CIDR lookup for an IP string.
        Returns (provider_name, is_cdn, is_origin, badge_type, label, provenance) or None.
        """
        if not ip_clean:
            return None

        with self._lock:
            if ip_clean in self._ip_cache:
                return self._ip_cache[ip_clean]

            try:
                ip_obj = ipaddress.ip_address(ip_clean)
            except ValueError:
                self._ip_cache[ip_clean] = None
                return None

            match = None
            if ip_obj.version == 4:
                # 1. Check CDN/WAF entries first
                for net, name, is_cdn, is_origin, badge, label, prov in self._ipv4_entries:
                    if is_cdn and ip_obj in net:
                        match = (name, is_cdn, is_origin, badge, label, prov)
                        break
                # 2. Check Origin entries if no CDN match
                if not match:
                    for net, name, is_cdn, is_origin, badge, label, prov in self._ipv4_entries:
                        if is_origin and ip_obj in net:
                            match = (name, is_cdn, is_origin, badge, label, prov)
                            break
            elif ip_obj.version == 6:
                for net, name, is_cdn, is_origin, badge, label, prov in self._ipv6_entries:
                    if is_cdn and ip_obj in net:
                        match = (name, is_cdn, is_origin, badge, label, prov)
                        break
                if not match:
                    for net, name, is_cdn, is_origin, badge, label, prov in self._ipv6_entries:
                        if is_origin and ip_obj in net:
                            match = (name, is_cdn, is_origin, badge, label, prov)
                            break

            self._ip_cache[ip_clean] = match
            return match


# Global shared instance
GLOBAL_DATABASE = IntelligenceDatabase()
