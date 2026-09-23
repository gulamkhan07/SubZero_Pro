"""
Direct TLS SAN (Subject Alternative Name) Certificate Scraper.
Connects to port 443 across discovered IP addresses and hosts, extracts
X.509 SSL/TLS certificates, and extracts hidden subdomains from the SAN extension
without relying on any external 3rd-party APIs.
Developed by: Gulam
"""
__author__ = "Gulam"

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket
import ssl
from typing import Iterable, List, Optional, Set, Tuple


def _parse_asn1_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Parses ASN.1 DER length field, returning (length, value_start_offset)."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        return 0, offset + 1
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def extract_sans_from_der(der_bytes: bytes) -> Set[str]:
    """
    Parses raw DER X.509 certificate bytes and extracts dNSName entries
    from Subject Alternative Name (ASN.1 context tag 0x82).
    """
    names: Set[str] = set()
    if not der_bytes:
        return names

    # ASN.1 tag for dNSName in GeneralNames choice is context-specific primitive [2] (0x82)
    # Search for occurrences of \x82 followed by length
    idx = 0
    while True:
        pos = der_bytes.find(b"\x82", idx)
        if pos == -1 or pos + 1 >= len(der_bytes):
            break
        length, val_start = _parse_asn1_length(der_bytes, pos + 1)
        val_end = val_start + length
        if 0 < length <= 255 and val_end <= len(der_bytes):
            raw_name = der_bytes[val_start:val_end]
            try:
                decoded = raw_name.decode("ascii", errors="strict").strip().lower().rstrip(".")
                if re.match(r"^(\*\.)?[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", decoded):
                    if "." in decoded:
                        names.add(decoded)
            except Exception:
                pass
        idx = pos + 1

    return names


def scrape_host_tls(
    target: str,
    target_domain: str,
    port: int = 443,
    timeout: float = 3.0
) -> Set[str]:
    """
    Connects to target:port via SSL/TLS, fetches the peer certificate in DER format,
    and returns discovered subdomains belonging to target_domain.
    """
    subdomains: Set[str] = set()
    clean_domain = target_domain.strip().lower().rstrip(".")
    target_clean = target.strip().rstrip(".")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Set modern cipher suites including legacy fallbacks
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except Exception:
        pass

    try:
        with socket.create_connection((target_clean, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Use SNI if target is hostname, otherwise connect directly
            server_hostname = target_clean if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_clean) else clean_domain
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    return subdomains

                raw_names = extract_sans_from_der(der)
                for name in raw_names:
                    # Strip leading wildcard *. if present
                    clean_name = name[2:] if name.startswith("*.") else name
                    if clean_name == clean_domain or clean_name.endswith("." + clean_domain):
                        if clean_name != clean_domain:
                            subdomains.add(clean_name)
    except Exception:
        pass

    return subdomains


def scrape_tls_sans(
    targets: Iterable[str],
    target_domain: str,
    port: int = 443,
    max_workers: int = 15,
    timeout: float = 3.0
) -> Set[str]:
    """
    Scrapes TLS SAN certificates in parallel across a list of IPs and hosts.
    Returns all validated subdomains belonging to target_domain.
    """
    unique_targets = list(set(t.strip() for t in targets if t and t.strip()))
    if not unique_targets:
        return set()

    found_subs: Set[str] = set()
    workers = min(len(unique_targets), max_workers) or 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scrape_host_tls, target, target_domain, port, timeout): target
            for target in unique_targets
        }
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    found_subs.update(res)
            except Exception:
                pass

    return found_subs
