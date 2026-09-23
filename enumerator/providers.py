"""
Passive Subdomain Reconnaissance Providers
Developed by: Gulam
"""
__author__ = "Gulam"

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests
from enumerator.request_utils import retry_request, get_session, random_user_agent, get_provider_last_error

API_URL = 'https://api.certspotter.com/v1/issuances'
CRTSH_API_URL = 'https://crt.sh/?q=%25.{domain}&output=json'
DEFAULT_PROVIDER_ORDER = (
    'amass', 'subfinder', 'subfinder_all', 'sslmate', 'crtsh',
    'rapiddns', 'hackertarget', 'otx', 'urlscan'
)
# Default passive suite: fast, resilient tools (Amass is kept separate by default)
DEFAULT_PASSIVE_PROVIDERS = (
    'subfinder', 'crtsh', 'sslmate', 'rapiddns', 'hackertarget', 'otx', 'urlscan'
)

TOOL_ALIASES = {
    'subfinder': 'subfinder',
    'sub-finder': 'subfinder',
    'subfinder-fast': 'subfinder',
    'subfinder_fast': 'subfinder',
    'subfinder_all': 'subfinder_all',
    'subfinder-all': 'subfinder_all',
    'amass': 'amass',
    'owasp-amass': 'amass',
    'owasp_amass': 'amass',
    'crtsh': 'crtsh',
    'crt.sh': 'crtsh',
    'crt': 'crtsh',
    'sslmate': 'sslmate',
    'certspotter': 'sslmate',
    'cert-spotter': 'sslmate',
    'rapiddns': 'rapiddns',
    'rapid-dns': 'rapiddns',
    'hackertarget': 'hackertarget',
    'hacker-target': 'hackertarget',
    'ht': 'hackertarget',
    'otx': 'otx',
    'alienvault': 'otx',
    'alienvault-otx': 'otx',
    'urlscan': 'urlscan',
    'urlscan.io': 'urlscan',
    'url-scan': 'urlscan',
}
# Amass is the opt-in deep source. Its own timeout is in minutes; allow a
# small process-level grace period so it can flush the final passive results.
AMASS_DEEP_TIMEOUT_MINUTES = 15
PROVIDER_TIMEOUTS = {
    'amass': 930,
    'subfinder': 120,
    'subfinder_all': 180,
    'sslmate': 30,
    'crtsh': 30,
    'rapiddns': 20,
    'hackertarget': 15,
    'otx': 12,
    'urlscan': 30,
}
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUBFINDER_APPDATA = PROJECT_ROOT / '.runtime'


def _filter_valid_subdomains(items, root: str) -> list:
    """Helper to extract, clean, and validate subdomains matching root domain."""
    valid = set()
    for item in items:
        if not item or not isinstance(item, str):
            continue
        host = item.strip().lower().lstrip('*.').rstrip('.')
        if host and (host.endswith('.' + root) or host == root):
            valid.add(host)
    return sorted(valid)


def _discover_go_bin_dirs():
    dirs = []
    seen = set()

    home = os.path.expanduser('~')
    candidates = [
        str(PROJECT_ROOT / 'bin'),
        os.environ.get('GOBIN'),
        os.environ.get('GOPATH') and os.path.join(os.environ.get('GOPATH'), 'bin'),
        os.path.join(home, 'go', 'bin'),
        os.path.join(home, 'go'),
        '/home/' + os.path.basename(home) + '/go/bin' if home and home != '/' else None,
        '/usr/local/go/bin',
        '/usr/local/bin',
        '/usr/bin',
    ]

    if os.name == 'nt':
        candidates.extend([
            r'C:\Program Files\Go\bin',
            r'C:\Go\bin',
            os.path.join(home, 'go', 'bin'),
        ])
        program_files = os.environ.get('ProgramFiles')
        if program_files:
            candidates.append(os.path.join(program_files, 'Go', 'bin'))

    for value in candidates:
        if not value:
            continue
        norm = os.path.normpath(value)
        if norm not in seen and os.path.isdir(norm):
            seen.add(norm)
            dirs.append(norm)

    return dirs


def resolve_binary(name):
    binary = shutil.which(name)
    if binary:
        return binary

    # Honour explicit/discovered Go installation directories before generic
    # system paths. This also makes a user-installed newer tool win over an
    # older bundled copy.
    for directory in _discover_go_bin_dirs():
        candidates = [os.path.join(directory, name)]
        if os.name == 'nt':
            candidates.extend(os.path.join(directory, f'{name}.{ext}') for ext in ('exe', 'cmd', 'bat'))
        for candidate in candidates:
            if os.path.isfile(candidate):
                if os.name == 'nt' and os.path.splitext(candidate)[1].lower() in ('.cmd', '.bat'):
                    continue
                return candidate

    return None


def _run_cmd(args, timeout, label, env=None):
    binary = resolve_binary(args[0])
    if not binary:
        return [], f'{label} is not installed or not in PATH.', 0
    args = [binary] + args[1:]
    try:
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                           check=False, env=process_env)
        values = [x.strip() for x in p.stdout.splitlines() if x.strip()]
        err = _command_error(label, p.returncode, p.stderr)
        return values, err, len(values)
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or '') if isinstance(exc.stdout, str) else (exc.stdout or b'').decode(errors='ignore')
        values = [x.strip() for x in partial.splitlines() if x.strip()]
        err = None if len(values) > 0 else f'{label} timed out after {timeout}s.'
        return values, err, len(values)


def _command_error(label, returncode, stderr):
    if returncode == 0:
        return None
    detail = ' '.join((stderr or '').split())
    if not detail:
        detail = 'no diagnostic output'
    return f'{label} failed (exit {returncode}): {detail[:400]}'


def subfinder(domain):
    # ProjectDiscovery creates its default config under APPDATA. Keeping that
    # state beside this app avoids a missing-profile failure on fresh Windows
    # installations and does not overwrite a user's personal configuration.
    env = {}
    if os.name == 'nt':
        env['APPDATA'] = str(SUBFINDER_APPDATA)
        env['LOCALAPPDATA'] = str(SUBFINDER_APPDATA)
    return _run_cmd(
        ['subfinder', '-d', domain, '-silent', '-duc', '-timeout', '6', '-max-time', '1'],
        PROVIDER_TIMEOUTS['subfinder'], 'Subfinder', env=env
    )


def subfinder_all(domain):
    env = {}
    if os.name == 'nt':
        env['APPDATA'] = str(SUBFINDER_APPDATA)
        env['LOCALAPPDATA'] = str(SUBFINDER_APPDATA)
    return _run_cmd(
        ['subfinder', '-d', domain, '-silent', '-duc', '-all', '-timeout', '15', '-max-time', '2'],
        PROVIDER_TIMEOUTS['subfinder_all'], 'Subfinder (Deep 52 Sources)', env=env
    )


def amass(domain):
    temp_dir = None
    values, err = [], None
    try:
        temp_dir = tempfile.mkdtemp(prefix='amass_run_')
        out_file = os.path.join(temp_dir, 'amass_out.txt')
        values, err, _ = _run_cmd(
            # Passive mode is Amass v4's default. -noalts is not a valid v4 flag;
            # altered-name generation stays off unless -alts is explicitly passed.
            ['amass', 'enum', '-d', domain, '-norecursive', '-silent', '-nocolor',
             '-dir', temp_dir,
             '-o', out_file,
             '-timeout', str(AMASS_DEEP_TIMEOUT_MINUTES)],
            PROVIDER_TIMEOUTS['amass'],
            'Amass'
        )
        if os.path.isfile(out_file):
            try:
                with open(out_file, 'r', encoding='utf-8', errors='ignore') as f:
                    file_lines = [x.strip() for x in f if x.strip()]
                if file_lines:
                    values = file_lines
            except Exception:
                pass
    finally:
        # Immediately clean up the entire temporary directory, DB and output files
        if temp_dir and os.path.isdir(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    cleaned = []
    seen = set()
    for line in values:
        candidate = line.strip()
        if not candidate:
            continue
        if '-->' in candidate:
            if '(FQDN)' not in candidate:
                continue
            candidate = candidate.split(' (FQDN)', 1)[0].strip()
        candidate = candidate.split(' ', 1)[0].strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        cleaned.append(candidate)
    return cleaned, err, len(cleaned)


def sslmate(domain):
    values = set()
    after = None
    pages = 0
    headers = {'User-Agent': random_user_agent()}
    try:
        for _ in range(20):  # Expanded bound for maximum CT log discovery
            params = {'domain': domain, 'include_subdomains': 'true', 'expand': 'dns_names'}
            if after:
                params['after'] = after
            r = retry_request(
                API_URL, provider='sslmate',
                params=params, timeout=12, headers=headers,
                max_retries=2, base_delay=1.5, min_interval=0.4,
            )
            if not r or r.status_code != 200:
                err_detail = f'HTTP {r.status_code}' if r else (get_provider_last_error('sslmate') or 'no response')
                return sorted(values), f'SSLMate CT request issue ({err_detail}); partial results kept.', len(values)
            records = r.json()
            pages += 1
            if not isinstance(records, list) or not records:
                break
            for rec in records:
                for name in rec.get('dns_names') or []:
                    if isinstance(name, str):
                        values.add(name.strip())
            link = r.headers.get('Link', '')
            m = re.search(r'[?&]after=([^&>]+)', link)
            if not m:
                break
            next_after = m.group(1)
            if next_after == after:
                break
            after = next_after
        return sorted(values), None if pages < 20 else 'SSLMate CT page limit reached (20 pages).', len(values)
    except requests.RequestException as exc:
        return sorted(values), f'SSLMate CT request failed: {exc}', len(values)
    except ValueError:
        return sorted(values), 'SSLMate CT returned invalid JSON.', len(values)


def crtsh(domain):
    root = domain.lower().rstrip('.')
    headers = {'User-Agent': random_user_agent()}
    urls = [
        CRTSH_API_URL.format(domain=root),
        f'https://crt.sh/?q={root}&output=json'
    ]
    records = None
    last_err = None

    for url in urls:
        r = retry_request(
            url, provider='crtsh',
            headers=headers, timeout=PROVIDER_TIMEOUTS.get('crtsh', 30),
            max_retries=3, base_delay=2.0, max_delay=12.0, min_interval=1.0,
        )
        if r and r.status_code == 200:
            try:
                records = r.json()
            except Exception:
                last_err = 'crt.sh returned invalid JSON'
        elif r:
            last_err = f'crt.sh returned HTTP {r.status_code}'
        else:
            diag = get_provider_last_error('crtsh')
            last_err = f'crt.sh connection failed ({diag})' if diag else 'crt.sh connection failed after retries'
        if records:
            break

    if not records:
        if last_err:
            return [], f'{last_err}; other engines (SSLMate, Subfinder, Active DNS) preserved.', 0
        return [], None, 0

    if not isinstance(records, list):
        return [], None, 0

    raw_lines = [
        line for rec in records
        if isinstance(rec, dict) and isinstance(rec.get('name_value'), str)
        for line in rec.get('name_value').splitlines()
    ]
    results = _filter_valid_subdomains(raw_lines, root)
    return results, None, len(results)


def rapiddns(domain):
    root = domain.lower().rstrip('.')
    url = f'https://rapiddns.io/subdomain/{root}?full=1'
    headers = {'User-Agent': random_user_agent()}
    r = retry_request(
        url, provider='rapiddns',
        headers=headers, timeout=PROVIDER_TIMEOUTS.get('rapiddns', 20),
        max_retries=2, base_delay=1.5, min_interval=0.5,
    )
    if not r:
        diag = get_provider_last_error('rapiddns')
        return [], f'RapidDNS request failed: {diag}' if diag else 'RapidDNS request failed after retries.', 0
    if r.status_code != 200:
        return [], f'RapidDNS returned HTTP {r.status_code}', 0
    pattern = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+' + re.escape(root), re.IGNORECASE)
    found = set(m.lower().strip() for m in pattern.findall(r.text))
    return sorted(found), None, len(found)

def hackertarget(domain):
    root = domain.lower().rstrip('.')
    url = f'https://api.hackertarget.com/hostsearch/?q={root}'
    headers = {'User-Agent': random_user_agent()}
    r = retry_request(
        url, provider='hackertarget',
        headers=headers, timeout=PROVIDER_TIMEOUTS.get('hackertarget', 15),
        max_retries=2, base_delay=2.0, min_interval=1.0,
    )
    if not r:
        diag = get_provider_last_error('hackertarget')
        return [], f'HackerTarget request failed: {diag}' if diag else 'HackerTarget request failed after retries.', 0
    if r.status_code != 200:
        return [], f'HackerTarget returned HTTP {r.status_code}', 0
    text = r.text.strip()
    if 'API count exceeded' in text:
        return [], 'HackerTarget daily rate limit reached (free tier). Try again after 24h or use other engines.', 0
    if 'error' in text.lower() and len(text.splitlines()) <= 2:
        return [], f'HackerTarget: {text}', 0
    raw = [line.split(',')[0] for line in text.splitlines() if line]
    results = _filter_valid_subdomains(raw, root)
    return results, None, len(results)


def otx(domain):
    """AlienVault OTX passive DNS / URL indicators provider."""
    root = domain.lower().rstrip('.')
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/{root}/url_list?limit=500'
    headers = {'User-Agent': random_user_agent()}
    r = retry_request(
        url, provider='otx',
        headers=headers, timeout=PROVIDER_TIMEOUTS.get('otx', 12),
        max_retries=2, base_delay=1.5, min_interval=0.5,
    )
    if not r:
        diag = get_provider_last_error('otx')
        return [], f'AlienVault OTX request failed: {diag}' if diag else 'AlienVault OTX request failed after retries.', 0
    if r.status_code != 200:
        return [], f'AlienVault OTX returned HTTP {r.status_code}', 0
    try:
        data = r.json()
        raw_hosts = [item.get('hostname') for item in data.get('url_list', []) if item.get('hostname')]
        valid = _filter_valid_subdomains(raw_hosts, root)
        return valid, None, len(valid)
    except Exception as exc:
        return [], f'AlienVault OTX parse error: {exc}', 0


def urlscan(domain):
    """URLScan.io public historical reconnaissance provider."""
    root = domain.lower().rstrip('.')
    url = f'https://urlscan.io/api/v1/search/?q=domain:{root}&size=100'
    headers = {'User-Agent': random_user_agent()}
    r = retry_request(
        url, provider='urlscan',
        headers=headers, timeout=PROVIDER_TIMEOUTS.get('urlscan', 12),
        max_retries=2, base_delay=1.5, min_interval=0.5,
    )
    if not r:
        diag = get_provider_last_error('urlscan')
        return [], f'URLScan request failed: {diag}' if diag else 'URLScan request failed after retries.', 0
    if r.status_code != 200:
        return [], f'URLScan returned HTTP {r.status_code}', 0
    try:
        data = r.json()
        raw_hosts = []
        for item in data.get('results', []):
            page = item.get('page', {})
            for k in ('domain', 'ptr'):
                val = page.get(k)
                if val:
                    raw_hosts.append(val)
        valid = _filter_valid_subdomains(raw_hosts, root)
        return valid, None, len(valid)
    except Exception as exc:
        return [], f'URLScan parse error: {exc}', 0


PROVIDERS = {name: globals()[name] for name in DEFAULT_PROVIDER_ORDER}
