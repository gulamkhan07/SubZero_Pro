"""
Configuration management for SubZero Dynamic Intelligence Engine.
Developed by: Gulam Khan
"""
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IntelligenceConfig:
    update_interval_hours: int = 24
    high_freq_update_interval_hours: int = 6
    cache_dir: str = ".runtime/intel_cache"
    request_timeout: float = 5.0
    max_stale_days: int = 14
    enable_asn_enrichment: bool = True
    enable_rdap_enrichment: bool = True
    enable_live_updates: bool = False
    proxy_url: str = ""
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "IntelligenceConfig":
        """Loads configuration from environment variables with safe defaults."""
        cache_dir_env = os.environ.get("SUBZERO_INTEL_CACHE_DIR")
        if not cache_dir_env:
            # Default to .runtime/intel_cache inside project root
            base_dir = Path(__file__).resolve().parent.parent.parent
            cache_dir_env = str(base_dir / ".runtime" / "intel_cache")

        return cls(
            update_interval_hours=int(os.environ.get("SUBZERO_INTEL_UPDATE_INTERVAL_HOURS", "24")),
            high_freq_update_interval_hours=int(os.environ.get("SUBZERO_INTEL_HIGH_FREQ_HOURS", "6")),
            cache_dir=cache_dir_env,
            request_timeout=float(os.environ.get("SUBZERO_INTEL_REQUEST_TIMEOUT", "5.0")),
            max_stale_days=int(os.environ.get("SUBZERO_INTEL_MAX_STALE_DAYS", "14")),
            enable_asn_enrichment=os.environ.get("SUBZERO_INTEL_ENABLE_ASN", "true").lower() in ("1", "true", "yes"),
            enable_rdap_enrichment=os.environ.get("SUBZERO_INTEL_ENABLE_RDAP", "true").lower() in ("1", "true", "yes"),
            enable_live_updates=os.environ.get("SUBZERO_INTEL_ENABLE_LIVE_UPDATES", "false").lower() in ("1", "true", "yes"),
            proxy_url=os.environ.get("SUBZERO_INTEL_PROXY", ""),
            log_level=os.environ.get("SUBZERO_INTEL_LOG_LEVEL", "INFO").upper(),
        )


GLOBAL_CONFIG = IntelligenceConfig.from_env()
