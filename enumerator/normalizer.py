import re

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$', re.I)
SUBDOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$', re.I)

def clean(value: str) -> str:
    v = value.strip().lower()
    if '://' in v:
        v = v.split('://', 1)[1]
    v = v.split('/', 1)[0].rstrip('.').lstrip('*.')
    return v

def valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.match(clean(value)))

def normalize_subdomains(values, root: str):
    root = clean(root)
    out = set()
    suffix = '.' + root
    for value in values:
        host = clean(value)
        if not host or host == root:
            continue
        if not SUBDOMAIN_RE.match(host):
            continue
        if host.endswith(suffix):
            out.add(host)
    return out
