"""
Feed validation and sanity checking for downloaded provider datasets.
Prevents corrupted, truncated, or catastrophic drops from replacing trusted data.
Developed by: Gulam Khan
"""
import ipaddress
import logging
from typing import List, Optional, Set, Tuple

logger = logging.getLogger("subzero.intel.validation")


class FeedValidationError(Exception):
    """Raised when downloaded feed fails integrity or sanity checks."""
    pass


def validate_cidr_string(cidr_str: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Validates and parses a CIDR string. Returns ipaddress network or None if invalid."""
    if not cidr_str or not isinstance(cidr_str, str):
        return None
    cleaned = cidr_str.strip()
    try:
        # strict=False allows host bits set (e.g. 1.2.3.4/24 -> 1.2.3.0/24)
        return ipaddress.ip_network(cleaned, strict=False)
    except (ValueError, TypeError):
        return None


def sanitize_and_deduplicate_cidrs(raw_cidrs: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validates a list of CIDR strings.
    Returns (valid_cidrs, rejected_entries).
    """
    valid: List[str] = []
    seen: Set[str] = set()
    rejected: List[str] = []

    for item in raw_cidrs:
        net = validate_cidr_string(item)
        if net is None:
            rejected.append(str(item))
            continue
        canon = str(net)
        if canon not in seen:
            seen.add(canon)
            valid.append(canon)

    return valid, rejected


def validate_dataset_change(
    provider_name: str,
    new_cidrs: List[str],
    previous_cidrs: Optional[List[str]] = None,
    allow_empty: bool = False,
    max_drop_ratio: float = 0.5,
    max_growth_multiplier: float = 10.0,
) -> Tuple[bool, str]:
    """
    Validates the change between previous known-good CIDRs and the new dataset.
    Detects catastrophic drops (e.g., 30 down to 2) and unreasonable spikes.
    Returns (is_valid, reason).
    """
    if not new_cidrs and not allow_empty:
        return False, f"Feed for {provider_name} returned 0 valid CIDRs."

    if not previous_cidrs:
        # First time ingestion or no prior baseline
        return True, "Initial baseline accepted."

    prev_count = len(previous_cidrs)
    new_count = len(new_cidrs)

    # Catastrophic drop detection
    # Example: If prev was 30 and new is 2, new_count < prev_count * 0.5 -> reject
    if prev_count >= 5 and new_count < int(prev_count * max_drop_ratio):
        msg = (
            f"Suspicious catastrophic drop for {provider_name}: "
            f"previous={prev_count} CIDRs, new={new_count} CIDRs (below {int(max_drop_ratio * 100)}% threshold). "
            f"Rejecting new dataset and preserving Last-Known-Good."
        )
        logger.warning(f"[INTEL] {msg}")
        return False, msg

    # Unreasonable massive explosion detection (e.g. malformed data generating 100x CIDRs)
    if prev_count >= 5 and new_count > int(prev_count * max_growth_multiplier):
        msg = (
            f"Suspicious catastrophic expansion for {provider_name}: "
            f"previous={prev_count} CIDRs, new={new_count} CIDRs (> {int(max_growth_multiplier)}x). "
            f"Flagging dataset as suspicious."
        )
        logger.warning(f"[INTEL] {msg}")
        return False, msg

    return True, f"Dataset validated successfully ({prev_count} -> {new_count} CIDRs)."
