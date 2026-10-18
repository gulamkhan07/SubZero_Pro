"""
SubZero Scan Orchestration and Enrichment Engine.
Executes passive intelligence, active DNS discovery, multi-resolver validation,
TLS scraping, origin verification, and nested subzone discovery.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set

from services.job_manager import (
    JOBS,
    JOBS_LOCK,
    CACHE,
    _add_log,
)
from enumerator.providers import PROVIDERS
from enumerator.normalizer import normalize_subdomains, clean
from enumerator.active_scanner import dns_brute_force
from enumerator.history_store import save_scan_history
from enumerator.dns_resolver import check_domain_multi_resolver
from enumerator.ip_intel import classify_ips
from enumerator.tls_scraper import scrape_tls_sans
from enumerator.wildcard_detector import detect_wildcard_dns, is_wildcard_false_positive
from enumerator.origin_verifier import verify_origin_candidates
from enumerator.ptr_sweeper import sweep_ips_for_ptrs
from enumerator.shodan_free import harvest_shodan_internetdb
from enumerator.nested_engine import discover_nested_subdomains
from enumerator.axfr_auditor import check_zone_transfer
from enumerator.shodan_exporter import fetch_domain_apex_records

logger = logging.getLogger('subzero')

_CPU_COUNT = os.cpu_count() or 4
SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=min(2, _CPU_COUNT))


def _enrich_subdomain_record(item: Dict[str, Any], dns_res: Dict[str, Any], wc_info: Dict[str, Any]) -> None:
    """Enriches a subdomain result item with DNS resolution and IP intelligence data."""
    item['dns'] = dns_res.get('status', 'not-checked')
    item['dns_resolver'] = dns_res.get('resolver', '')
    item['dns_summary'] = dns_res.get('summary', '')
    ips = dns_res.get('ips', [])
    cname = dns_res.get('cname', '')
    item['dns_ips'] = ips
    is_catchall = is_wildcard_false_positive(ips, cname, wc_info)
    item['is_wildcard_catchall'] = is_catchall
    if is_catchall:
        item['dns'] = 'wildcard-catchall'
        item['is_dead'] = True
        item['is_live'] = False
    elif item['dns'] == 'resolved':
        item['is_dead'] = False
        item['is_live'] = True
    else:
        item['is_dead'] = True
        item['is_live'] = False
    if ips or cname:
        intel = classify_ips(ips, cname=cname)
        item['ip_intel'] = intel
        item['primary_ip'] = intel.get('primary_ip', '')
        item['waf_provider'] = intel.get('waf_provider', 'Direct Server')
        item['is_origin'] = intel.get('is_origin', False)
        item['is_cdn'] = intel.get('is_cdn', False)
        item['country_name'] = intel.get('country_name', 'Global')
        item['country_code'] = intel.get('country_code', '')
        item['country_flag'] = intel.get('country_flag', '🌐')


def _resolve_and_enrich_hosts(
    hosts: List[str],
    source_tag: str,
    selected_res: str,
    wc_info: Dict[str, Any],
    found_by: Dict[str, Set[str]],
    results: List[Dict[str, Any]],
    job: Dict[str, Any],
) -> None:
    """Concurrently resolves newly discovered hosts (e.g. from TLS-SAN or PTR sweeps) and enriches results."""
    _add_log(job, f"[{source_tag.upper()}] Verifying DNS resolution for {len(hosts)} new host(s)...")
    import sys
    resolver_fn = getattr(sys.modules.get('app'), 'check_domain_multi_resolver', check_domain_multi_resolver)
    new_items = []
    with ThreadPoolExecutor(max_workers=min(40, max(1, len(hosts)))) as pool:
        futures = {pool.submit(resolver_fn, s, selected_res): s for s in hosts}
        for future in as_completed(futures):
            s = futures[future]
            found_by.setdefault(s, set()).add(source_tag)
            item = {
                'subdomain': s,
                'sources': [source_tag],
                'confidence': 'single-source',
                'dns': 'not-checked',
            }
            try:
                dns_res = future.result()
                _enrich_subdomain_record(item, dns_res, wc_info)
            except Exception:
                item['dns'] = 'not-checked'
            new_items.append(item)
    results.extend(new_items)


def _run_scan(job_id: str, selected: List[str]) -> None:
    """Core reconnaissance loop for SubZero."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.get('cancelled'):
            return
        active_dns = job.get('active_dns', False)
        total_sources = len(selected) + (1 if active_dns else 0)
        job.update(status='running', progress=f'Querying {total_sources} source(s)')

    _add_log(job, "[*] SubZero v2.2 • High-Speed OSINT Engine")
    _add_log(job, f"[*] Starting reconnaissance job for: {job['domain']}")
    _add_log(job, f"[*] Selected engines: {', '.join(selected + (['active-dns'] if active_dns else []))}")

    main_target = clean(job['domain'])
    selected_res = job.get('selected_resolver', 'all')
    found_by, counts, errors = {}, {}, []

    # 1. Fast, guaranteed audit of Main Target Domain (Apex / Root Domain)
    main_ips = []
    main_cname = ''
    main_summary = ''
    main_resolver = 'System DNS'

    if job.get('dns_validation'):
        try:
            resolver_fn = getattr(sys.modules.get('app'), 'check_domain_multi_resolver', check_domain_multi_resolver)
            main_dns = resolver_fn(main_target, selected_res if selected_res else 'all')
            if main_dns and main_dns.get('status') == 'resolved':
                main_ips = main_dns.get('ips', [])
                main_cname = main_dns.get('cname', '')
                main_summary = main_dns.get('summary', '')
                main_resolver = main_dns.get('resolver', 'System DNS')
        except Exception as exc:
            logger.debug(f"Multi-resolver check on {main_target} failed: {exc}")

    if not main_ips:
        try:
            import socket
            _, _, resolved_ips = socket.gethostbyname_ex(main_target)
            if resolved_ips:
                main_ips = list(dict.fromkeys(resolved_ips))
                if not main_summary:
                    main_summary = f'Live via System DNS -> {main_ips[0]}'
        except Exception:
            pass

    main_item = {
        'domain': main_target,
        'subdomain': main_target,
        'is_main_domain': True,
        'sources': ['Target Apex'],
        'confidence': 'main-target',
        'dns': 'resolved' if main_ips else 'unresolved',
        'dns_resolver': main_resolver,
        'dns_ips': main_ips,
        'cname': main_cname,
        'dns_summary': main_summary,
    }
    if main_ips or main_cname:
        main_intel = classify_ips(main_ips, cname=main_cname)
        main_item['ip_intel'] = main_intel
        main_item['primary_ip'] = main_intel.get('primary_ip', main_ips[0] if main_ips else '')
        main_item['waf_provider'] = main_intel.get('waf_provider', 'Direct Server')
        main_item['is_origin'] = main_intel.get('is_origin', True)
        main_item['is_cdn'] = main_intel.get('is_cdn', False)
        main_item['country_name'] = main_intel.get('country_name', 'Global')
        main_item['country_code'] = main_intel.get('country_code', '')
        main_item['country_flag'] = main_intel.get('country_flag', '🌐')

    if main_item.get('primary_ip'):
        waf_label = main_item.get('waf_provider', 'Direct Server')
        _add_log(job, f"[*] [MAIN TARGET DOMAIN] {main_target} -> IP: {main_item['primary_ip']} | WAF Protection: {waf_label}")
    job['main_domain'] = main_item
    job['main_domain_intel'] = main_item

    # 2. Check for Wildcard DNS (*.target.com) upfront
    wc_info = {'is_wildcard': False, 'wildcard_ips': [], 'wildcard_cnames': []}
    if job.get('dns_validation') or job.get('active_dns'):
        wc_info = detect_wildcard_dns(main_target, timeout=1.5)
        if wc_info.get('is_wildcard'):
            _add_log(job, f"[!] NOTICE: Wildcard DNS (*.{main_target}) is ACTIVE -> IPs: {', '.join(wc_info['wildcard_ips'])}. False-positive catchall filtering enabled.")
    job['wildcard_dns'] = wc_info

    # 2.5 Authoritative Name Servers Open Zone Transfer (AXFR) Pre-Flight Check & Apex DNS Harvest
    if job.get('dns_validation'):
        try:
            _add_log(job, "[*] Auditing authoritative nameservers for DNS Zone Transfer (AXFR)...")
            axfr_fn = getattr(sys.modules.get('app'), 'check_zone_transfer', check_zone_transfer)
            axfr_res = axfr_fn(main_target, timeout=2.5)
            job['axfr_audit'] = axfr_res
            if axfr_res.get('is_vulnerable'):
                axfr_subs = axfr_res.get('subdomains', [])
                _add_log(job, f"[!] 🔥 CRITICAL: Authoritative nameserver allows open DNS Zone Transfer (AXFR)! Leaked {len(axfr_subs)} complete zone records!")
                for s in axfr_subs:
                    if s != main_target:
                        found_by.setdefault(s, set()).add('axfr')
                counts['axfr'] = len(axfr_subs)
            else:
                _add_log(job, "[*] DNS Zone Transfer rejected by authoritative nameservers (Standard/Secure).")
        except Exception as exc:
            _add_log(job, f"[!] AXFR pre-flight notice: {exc}")

        # Harvest authoritative DNS records for Shodan 1:1 schema
        try:
            _add_log(job, "[*] Harvesting authoritative DNS infrastructure records (MX, NS, SOA, TXT, DMARC)...")
            apex_records = fetch_domain_apex_records(main_target, timeout=3.0, specific_resolver=selected_res)
            job['apex_records'] = apex_records
            if apex_records:
                types_found = list(dict.fromkeys(r['type'] for r in apex_records))
                _add_log(job, f"[DNS-INTEL] Captured {len(apex_records)} authoritative records ({', '.join(types_found)})")
        except Exception as exc:
            _add_log(job, f"[!] Apex DNS harvest notice: {exc}")

    # 3. Concurrent Passive & Active Discovery
    def _execute_provider(name: str):
        _add_log(job, f"[{name}] Starting query worker...")
        t0 = time.time()
        try:
            providers_dict = getattr(sys.modules.get('app'), 'PROVIDERS', PROVIDERS)
            values, err, cnt = providers_dict[name](job['domain'])
            dur = round(time.time() - t0, 2)
            if err:
                _add_log(job, f"[{name}] Finished ({dur}s) with notice: {err} | Found {cnt}")
            else:
                _add_log(job, f"[{name}] Finished successfully ({dur}s) | Found {cnt} subdomains")
            for val in values[:25]:
                _add_log(job, f"[{name}] Discovered -> {val}")
            if len(values) > 25:
                _add_log(job, f"[{name}] ... and {len(values) - 25} more subdomains")
            return values, err, cnt
        except Exception as exc:
            dur = round(time.time() - t0, 2)
            _add_log(job, f"[{name}] Exception after {dur}s: {exc}")
            return [], str(exc), 0

    run_active = active_dns
    if active_dns and wc_info.get('is_wildcard'):
        _add_log(job, f"[ACTIVE-DNS] Wildcard DNS active on *.{main_target}. Applying intelligent baseline filtering...")

    pool_workers = min(20, max(1, len(selected) + (1 if run_active else 0)))
    with ThreadPoolExecutor(max_workers=pool_workers) as pool:
        futures = {pool.submit(_execute_provider, name): name for name in selected}
        if run_active:
            _add_log(job, f"[ACTIVE-DNS] 🚀 Starting Active DNS brute-force ({job.get('active_wordlist', '5000')} wordlist) against *.{main_target}...")
            futures[pool.submit(
                dns_brute_force,
                job['domain'],
                None,
                60,
                job.get('active_wordlist', '5000'),
                lambda m: _add_log(job, f"{m}"),
                job.get('verbose_dns', True),
                allow_wildcard_filtering=True,
                wildcard_ips=wc_info.get('wildcard_ips', []),
                rate_limit=job.get('dns_rate_limit', 150),
            )] = 'active-dns'
        for future in as_completed(futures):
            name = futures[future]
            try:
                values, error, count = future.result()
            except Exception as exc:
                values, error, count = [], f'{type(exc).__name__}: {exc}', 0
            counts[name] = count
            for host in normalize_subdomains(values, job['domain']):
                found_by.setdefault(host, set()).add(name)
            if error and not values:
                err_str = str(error).lower()
                if 'wildcard' not in err_str and 'rate limit' not in err_str and 'api count' not in err_str and 'quota' not in err_str:
                    errors.append(f'{name}: {error}')
            with JOBS_LOCK:
                if job['cancelled']:
                    _add_log(job, "[!] Scan was cancelled by user.")
                    return
                job['progress'] = f'Finished {len(counts)}/{total_sources} sources'
                job['live_count'] = len(found_by)

    _add_log(job, "[*] Merging & de-duplicating subdomains across all engines...")
    dns = {}

    # 3. Audit All Discovered Subdomains
    if job['dns_validation']:
        if selected_res and selected_res != 'all':
            _add_log(job, f"[*] Verifying DNS resolution specifically via {selected_res.upper()} for {len(found_by)} unique hosts...")
        else:
            _add_log(job, f"[*] Verifying DNS resolution across Tier-1 resolvers (Cloudflare, Google, OpenDNS, Quad9, AdGuard, Control D, Level3) for {len(found_by)} unique hosts...")
        resolver_fn = getattr(sys.modules.get('app'), 'check_domain_multi_resolver', check_domain_multi_resolver)
        with ThreadPoolExecutor(max_workers=min(50, max(1, len(found_by)))) as pool:
            futures = {pool.submit(resolver_fn, host, selected_res): host for host in found_by}
            total_hosts = len(found_by)
            checked_count = 0
            live_count = 0
            dead_count = 0
            for future in as_completed(futures):
                host = futures[future]
                try:
                    res_info = future.result()
                except Exception:
                    res_info = {'status': 'unresolved', 'ips': [], 'cname': '', 'resolver': 'System DNS'}
                dns[host] = res_info
                checked_count += 1
                is_catchall = is_wildcard_false_positive(res_info.get('ips', []), res_info.get('cname', ''), wc_info)
                if res_info.get('status') == 'resolved' and not is_catchall:
                    live_count += 1
                    resolver_label = res_info.get('resolver', 'Public DNS')
                    ip_part = f" -> {res_info['ips'][0]}" if res_info.get('ips') else ""
                    _add_log(job, f"[DNS-CHECK] 🎯 {host} -> [RESOLVED] via {resolver_label}{ip_part}")
                elif is_catchall:
                    dead_count += 1
                    wc_ip = wc_info.get('wildcard_ips', [''])[0] if wc_info.get('wildcard_ips') else ''
                    wc_ip_str = f" (Points to catchall baseline {wc_ip})" if wc_ip else ""
                    _add_log(job, f"[DNS-CHECK] ⚠️ {host} -> [DEAD / WILDCARD CATCH-ALL]{wc_ip_str}")
                else:
                    dead_count += 1
                    _add_log(job, f"[DNS-CHECK] 🔴 {host} -> [DEAD] (NXDOMAIN across resolvers)")

                if checked_count % 50 == 0 or checked_count == total_hosts:
                    _add_log(job, f"[*] [DNS-PROGRESS] Verified {checked_count}/{total_hosts} hosts ({live_count} Live, {dead_count} Dead across resolvers)...")

    results = []
    for host in sorted(found_by):
        if host == main_target:
            continue
        item = {
            'subdomain': host,
            'sources': sorted(found_by[host]),
            'confidence': 'high' if len(found_by[host]) > 1 else 'single-source',
            'dns': dns[host].get('status', 'unresolved') if host in dns else 'not-checked'
        }
        if host in dns:
            _enrich_subdomain_record(item, dns[host], wc_info)
        results.append(item)

    with JOBS_LOCK:
        job['results'] = list(results)

    # 4. Advanced Discovery & Intelligence Post-Processing
    if job['dns_validation'] and results:
        # A. TLS SAN Certificate Scraping across resolved IPs
        all_resolved_ips = list(set(ip for r in results for ip in r.get('dns_ips', []) if ip))
        if all_resolved_ips:
            _add_log(job, f"[*] Probing TLS SAN certificates across {len(all_resolved_ips[:50])} live IP(s) on ports 443 & 8443...")
            try:
                tls_subs = scrape_tls_sans(all_resolved_ips[:50], main_target, ports=[443, 8443], max_workers=15, timeout=2.5)
                new_tls = [s for s in tls_subs if s not in found_by and s != main_target]
                if new_tls:
                    _add_log(job, f"[TLS-SAN] Discovered {len(new_tls)} hidden host(s) on direct SSL certificates: {', '.join(new_tls[:5])}")
                    _resolve_and_enrich_hosts(new_tls, 'tls-san', selected_res, wc_info, found_by, results, job)
            except Exception as e:
                _add_log(job, f"[!] TLS probe notice: {e}")

        # B. Confirmed True Origin IP (WAF Bypass) Active Verification
        candidate_origin_ips = list(set(r.get('primary_ip') for r in results if r.get('is_origin') and r.get('primary_ip')))
        if candidate_origin_ips:
            _add_log(job, f"[*] Actively verifying True Origin IPs against WAF bypass for {len(candidate_origin_ips[:10])} candidate(s)...")
            try:
                ver_map = verify_origin_candidates(candidate_origin_ips[:10], main_target, max_workers=8, timeout=3.0)
                for r in results:
                    pip = r.get('primary_ip')
                    if pip in ver_map and ver_map[pip].get('is_confirmed_origin'):
                        r['is_confirmed_origin'] = True
                        r['confirmed_origin'] = ver_map[pip]
                        _add_log(job, f"[ORIGIN-CONFIRMED] 🔥 {pip} ({r['subdomain']}) verified as True Origin Server (WAF Bypass)!")
            except Exception as e:
                _add_log(job, f"[!] Origin verification notice: {e}")

        # C. Reverse DNS (PTR) Subnet Sweep
        if candidate_origin_ips:
            _add_log(job, "[*] Running reverse DNS (PTR) sweep on origin subnets...")
            try:
                ptr_res = sweep_ips_for_ptrs(candidate_origin_ips[:5], main_target, sweep_surrounding=True, window=3, max_workers=15)
                ptr_subs = ptr_res.get('discovered_subdomains', [])
                new_ptrs = [s for s in ptr_subs if s not in found_by and s != main_target]
                if new_ptrs:
                    _add_log(job, f"[PTR-SWEEP] Discovered {len(new_ptrs)} reverse DNS hostname(s): {', '.join(new_ptrs[:5])}")
                    _resolve_and_enrich_hosts(new_ptrs, 'ptr-sweep', selected_res, wc_info, found_by, results, job)
            except Exception as e:
                _add_log(job, f"[!] PTR sweep notice: {e}")

        # D. Shodan InternetDB Harvest (100% Free, Zero Key Required)
        if all_resolved_ips:
            _add_log(job, f"[*] Querying Shodan InternetDB across {len(all_resolved_ips[:40])} live IP(s) for free intelligence...")
            try:
                shodan_fn = getattr(sys.modules.get('app'), 'harvest_shodan_internetdb', harvest_shodan_internetdb)
                shodan_res = shodan_fn(all_resolved_ips[:40], main_target, max_workers=15, timeout=3.5)
                shodan_subs = shodan_res.get('subdomains', [])
                new_shodan = [s for s in shodan_subs if s not in found_by and s != main_target]
                if new_shodan:
                    _add_log(job, f"[SHODAN-FREE] 🚀 Discovered {len(new_shodan)} hidden host(s) from Shodan InternetDB: {', '.join(new_shodan[:5])}")
                    _resolve_and_enrich_hosts(new_shodan, 'shodan-free', selected_res, wc_info, found_by, results, job)
            except Exception as e:
                _add_log(job, f"[!] Shodan InternetDB notice: {e}")

        # E. Multi-Level & Multi-Tenant Nested Subdomain Discovery
        current_hosts = list(found_by.keys())
        _add_log(job, "[*] Mining multi-level tenant sub-zones for nested asset discovery...")
        try:
            nested_subs = discover_nested_subdomains(
                main_target,
                current_hosts,
                max_candidates=300,
                max_workers=60,
                dns_resolver=selected_res,
                log_cb=lambda m: _add_log(job, m),
                wildcard_info=wc_info
            )
            new_nested = [s for s in nested_subs if s not in found_by and s != main_target]
            if new_nested:
                _add_log(job, f"[NESTED-ENGINE] 🔥 Discovered {len(new_nested)} verified live nested subdomain(s)!")
                _resolve_and_enrich_hosts(new_nested, 'nested-engine', selected_res, wc_info, found_by, results, job)
        except Exception as e:
            _add_log(job, f"[!] Nested discovery notice: {e}")

    with JOBS_LOCK:
        if job['cancelled']:
            return
        job.update(status='completed', progress='Completed', sources=counts, errors=errors, results=results)
        CACHE[job['cache_key']] = (
            time.time(),
            copy.deepcopy(results),
            counts.copy(),
            errors.copy(),
            copy.deepcopy(main_item),
            copy.deepcopy(wc_info),
            copy.deepcopy(job.get('axfr_audit'))
        )
        save_scan_history(job['id'], job['domain'], results, counts, main_domain=main_item)
    _add_log(job, f"[SUCCESS] Scan completed! Found {len(results)} total unique subdomains.")
