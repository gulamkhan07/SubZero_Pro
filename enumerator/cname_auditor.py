"""
DNS Asset Integrity & Dangling CNAME Auditor.
Performs defensive auditing of DNS CNAME pointers against known cloud asset signatures
(AWS S3, CloudFront, Elastic Beanstalk, GitHub Pages, Heroku, Azure, Shopify, Zendesk,
Fastly, Vercel, Netlify, Fly.io, Ghost, Readme.io, Webflow, Firebase, etc.) to detect
misconfigurations and unclaimed asset takeovers.
"""
__author__ = "SubZero Community"

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket
from typing import Any, Dict, List, Optional, Set
import urllib3

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# Comprehensive Cloud, SaaS & Hosting Provider Asset Signatures (70+ Services)
# ==============================================================================
SERVICE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "service": "AWS S3",
        "cname_patterns": [
            r"s3[\.\-]website[\.\-].*\.amazonaws\.com",
            r".*\.s3\.amazonaws\.com",
            r".*\.s3-website-.*\.amazonaws\.com",
            r".*\.s3-website\..*\.amazonaws\.com",
            r".*\.s3\..*\.amazonaws\.com"
        ],
        "fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
        "remediation": "Remove the dangling CNAME from DNS or claim the S3 bucket in your AWS account."
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": [r".*\.github\.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "404 - Not Found"],
        "remediation": "Remove the CNAME pointing to github.io or configure custom domain in your GitHub repository."
    },
    {
        "service": "Heroku",
        "cname_patterns": [r".*\.herokudns\.com", r".*\.herokuapp\.com"],
        "fingerprints": ["No such app", "Heroku | No such app", "item not found"],
        "remediation": "Delete DNS CNAME pointing to Heroku or attach the domain to an active Heroku app."
    },
    {
        "service": "Microsoft Azure",
        "cname_patterns": [
            r".*\.azurewebsites\.net",
            r".*\.cloudapp\.net",
            r".*\.azure-api\.net",
            r".*\.trafficmanager\.net",
            r".*\.azureedge\.net"
        ],
        "fingerprints": [
            "404 Web Site not found",
            "Web App - Unavailable",
            "The resource you are looking for has been removed"
        ],
        "remediation": "Remove unlinked Azure CNAME from your DNS zone or reconnect custom domain in Azure."
    },
    {
        "service": "Shopify",
        "cname_patterns": [r".*\.myshopify\.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "remediation": "Remove Shopify CNAME or reconnect your domain in Shopify admin."
    },
    {
        "service": "Zendesk",
        "cname_patterns": [r".*\.zendesk\.com"],
        "fingerprints": ["Help Center Closed", "No such app"],
        "remediation": "Update Zendesk host mapping or delete the obsolete CNAME."
    },
    {
        "service": "Fastly",
        "cname_patterns": [r".*\.fastly\.net", r".*\.fastlylb\.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "remediation": "Add domain to active Fastly service or remove CNAME."
    },
    {
        "service": "Pantheon",
        "cname_patterns": [r".*\.pantheonsite\.io"],
        "fingerprints": ["404 error unknown site", "The gods are wise, but do not know of the site which you seek"],
        "remediation": "Remove decommissioned Pantheon CNAME."
    },
    {
        "service": "Surge.sh",
        "cname_patterns": [r".*\.surge\.sh"],
        "fingerprints": ["project not found"],
        "remediation": "Remove surge.sh CNAME or deploy your project."
    },
    {
        "service": "Bitbucket",
        "cname_patterns": [r".*\.bitbucket\.io"],
        "fingerprints": ["Repository not found"],
        "remediation": "Configure repository or delete dangling Bitbucket pointer."
    },
    {
        "service": "Amazon CloudFront",
        "cname_patterns": [r".*\.cloudfront\.net"],
        "fingerprints": ["Bad Request: ERROR: The request could not be satisfied"],
        "remediation": "Associate domain with an active CloudFront distribution or remove CNAME."
    },
    {
        "service": "AWS Elastic Beanstalk",
        "cname_patterns": [r".*\.elasticbeanstalk\.com"],
        "fingerprints": ["404 Not Found", "NoSuchHost"],
        "remediation": "Claim the Elastic Beanstalk environment or remove the dangling CNAME."
    },
    {
        "service": "Ghost",
        "cname_patterns": [r".*\.ghost\.io"],
        "fingerprints": [
            "The thing you are looking for is no longer here",
            "The domain you are trying to visit is not hosted at Ghost"
        ],
        "remediation": "Remove CNAME pointing to ghost.io or configure custom domain in Ghost."
    },
    {
        "service": "Netlify",
        "cname_patterns": [r".*\.netlify\.app", r".*\.netlify\.com"],
        "fingerprints": ["Not Found - Request ID", "page not found", "Netlify - Page Not Found"],
        "remediation": "Attach domain to your Netlify site or remove the CNAME record."
    },
    {
        "service": "Vercel",
        "cname_patterns": [r".*\.vercel\.app", r".*\.vercel-dns\.com", r".*\.cname\.vercel-dns\.com"],
        "fingerprints": [
            "The deployment could not be found on Vercel",
            "DEPLOYMENT_NOT_FOUND",
            "404: NOT_FOUND"
        ],
        "remediation": "Configure domain in Vercel project settings or delete the DNS record."
    },
    {
        "service": "Fly.io",
        "cname_patterns": [r".*\.fly\.dev"],
        "fingerprints": ["404 Not Found", "Fly.io"],
        "remediation": "Allocate certificate and domain in Fly.io dashboard or delete pointer."
    },
    {
        "service": "Readme.io",
        "cname_patterns": [r".*\.readme\.io"],
        "fingerprints": ["Project doesnt exist... yet!", "Project doesn't exist... yet!"],
        "remediation": "Claim project on Readme.io or remove the dangling pointer."
    },
    {
        "service": "WordPress.com",
        "cname_patterns": [r".*\.wordpress\.com"],
        "fingerprints": ["Do you want to register"],
        "remediation": "Claim custom domain on WordPress.com or delete the CNAME."
    },
    {
        "service": "Webflow",
        "cname_patterns": [r".*\.webflow\.io", r".*\.proxy\.webflow\.io", r".*\.ssl\.webflow\.io"],
        "fingerprints": [
            "The page you are looking for doesn't exist or has been moved",
            "The page you are looking for doesn't exist"
        ],
        "remediation": "Attach custom domain in Webflow dashboard or remove CNAME."
    },
    {
        "service": "Strikingly",
        "cname_patterns": [r".*\.strikinglydns\.com"],
        "fingerprints": ["page not found", "Page not found - Strikingly"],
        "remediation": "Claim domain in Strikingly or delete the dangling CNAME."
    },
    {
        "service": "Cargo Collective",
        "cname_patterns": [r".*\.cargocollective\.com", r".*\.cargo\.site"],
        "fingerprints": ["404 Not Found", "cargocollective.com"],
        "remediation": "Configure custom URL in Cargo admin or remove CNAME."
    },
    {
        "service": "HelpScout",
        "cname_patterns": [r".*\.helpscoutdocs\.com"],
        "fingerprints": ["No settings were found for this company"],
        "remediation": "Configure docs subdomain in HelpScout or delete CNAME."
    },
    {
        "service": "Statuspage",
        "cname_patterns": [r".*\.statuspage\.io"],
        "fingerprints": ["You are being redirected", "Statuspage | Page Not Found"],
        "remediation": "Claim Statuspage or remove the obsolete pointer."
    },
    {
        "service": "UserVoice",
        "cname_patterns": [r".*\.uservoice\.com"],
        "fingerprints": ["This UserVoice subdomain is currently available"],
        "remediation": "Claim UserVoice subdomain or remove DNS pointer."
    },
    {
        "service": "Unbounce",
        "cname_patterns": [r".*\.unbouncepages\.com"],
        "fingerprints": [
            "The requested URL was not found on this server",
            "The page you were looking for doesn't exist"
        ],
        "remediation": "Link domain in Unbounce or delete obsolete CNAME."
    },
    {
        "service": "Tumblr",
        "cname_patterns": [r".*\.tumblr\.com"],
        "fingerprints": ["Whatever you were looking for doesn't exist", "There's nothing here"],
        "remediation": "Configure custom domain in Tumblr or delete CNAME pointer."
    },
    {
        "service": "SmartJobBoard",
        "cname_patterns": [r".*\.smartjobboard\.com", r".*\.custom\.smartjobboard\.com"],
        "fingerprints": ["This job board is currently unavailable", "Job board not found"],
        "remediation": "Update job board settings or remove CNAME."
    },
    {
        "service": "SurveyGizmo",
        "cname_patterns": [r".*\.sgizmo\.com", r".*\.surveygizmo\.com"],
        "fingerprints": ["data-html2canvas-ignore", "SurveyGizmo"],
        "remediation": "Link domain in SurveyGizmo or delete CNAME."
    },
    {
        "service": "Tictail",
        "cname_patterns": [r".*\.tictail\.com"],
        "fingerprints": ["Building a brand of your own?", "to target URL: https://tictail.com"],
        "remediation": "Update custom domain or remove CNAME."
    },
    {
        "service": "TeamWork",
        "cname_patterns": [r".*\.teamwork\.com"],
        "fingerprints": ["Oops - We didn't find your site"],
        "remediation": "Update TeamWork site configuration or remove CNAME."
    },
    {
        "service": "Big Cartel",
        "cname_patterns": [r".*\.bigcartel\.com"],
        "fingerprints": ["The page you are looking for cannot be found"],
        "remediation": "Configure domain in Big Cartel admin or delete CNAME."
    },
    {
        "service": "Campaign Monitor",
        "cname_patterns": [r".*\.createsend\.com"],
        "fingerprints": ["Trying to access your account?"],
        "remediation": "Configure custom domain in Campaign Monitor or delete CNAME."
    },
    {
        "service": "Acquia",
        "cname_patterns": [r".*\.acquia-test\.co", r".*\.acquiasites\.com"],
        "fingerprints": ["The site you are looking for could not be found", "Site not found"],
        "remediation": "Link domain in Acquia Cloud or delete CNAME."
    },
    {
        "service": "Anima",
        "cname_patterns": [r".*\.animaapp\.io"],
        "fingerprints": [
            "If this is your website and you've just created it",
            "The site you are looking for is not found"
        ],
        "remediation": "Configure custom domain in Anima or delete CNAME."
    },
    {
        "service": "Agorapulse",
        "cname_patterns": [r".*\.agorapulse\.com"],
        "fingerprints": ["This page is not configured yet"],
        "remediation": "Link domain in Agorapulse or delete CNAME."
    },
    {
        "service": "Bitly",
        "cname_patterns": [r".*\.bitly\.com", r".*\.cname\.bitly\.com"],
        "fingerprints": ["404: Not Found", "bitly"],
        "remediation": "Configure custom short domain in Bitly or remove CNAME."
    },
    {
        "service": "Canny",
        "cname_patterns": [r".*\.canny\.io"],
        "fingerprints": ["Company not found"],
        "remediation": "Link custom domain in Canny or delete CNAME."
    },
    {
        "service": "Feedpress",
        "cname_patterns": [r".*\.feedpress\.me"],
        "fingerprints": ["The feed has not been found"],
        "remediation": "Claim feed on Feedpress or delete CNAME."
    },
    {
        "service": "Freshdesk",
        "cname_patterns": [r".*\.freshdesk\.com"],
        "fingerprints": ["May be this page has moved", "Helpdesk not found"],
        "remediation": "Update portal settings in Freshdesk or delete CNAME."
    },
    {
        "service": "GetResponse",
        "cname_patterns": [r".*\.gr8\.com"],
        "fingerprints": ["With GetResponse Landing Pages, lead generation has never been easier"],
        "remediation": "Claim landing page in GetResponse or delete CNAME."
    },
    {
        "service": "Hatena",
        "cname_patterns": [r".*\.hatenablog\.com"],
        "fingerprints": ["404 Blog is not found"],
        "remediation": "Configure custom domain in Hatena or delete CNAME."
    },
    {
        "service": "Helpjuice",
        "cname_patterns": [r".*\.helpjuice\.com"],
        "fingerprints": ["We could not find what you're looking for"],
        "remediation": "Configure custom domain in Helpjuice or delete CNAME."
    },
    {
        "service": "Intercom",
        "cname_patterns": [r".*\.custom\.intercom\.help"],
        "fingerprints": ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"],
        "remediation": "Configure Help Center domain in Intercom or delete CNAME."
    },
    {
        "service": "JetBrains Hub / YouTrack",
        "cname_patterns": [r".*\.myjetbrains\.com"],
        "fingerprints": ["is not found", "No account found"],
        "remediation": "Configure custom domain in JetBrains Cloud or delete CNAME."
    },
    {
        "service": "Kinsta",
        "cname_patterns": [r".*\.kinsta\.cloud"],
        "fingerprints": ["No Site For Domain"],
        "remediation": "Add domain to active Kinsta site or remove CNAME."
    },
    {
        "service": "LaunchRock",
        "cname_patterns": [r".*\.launchrock\.com"],
        "fingerprints": ["It looks like you may have taken a wrong turn"],
        "remediation": "Claim page on LaunchRock or delete CNAME."
    },
    {
        "service": "Leadpages",
        "cname_patterns": [r".*\.leadpages\.net"],
        "fingerprints": ["Double check that you've entered the URL correctly"],
        "remediation": "Configure domain in Leadpages or delete CNAME."
    },
    {
        "service": "Ngrok",
        "cname_patterns": [r".*\.ngrok\.io", r".*\.ngrok-free\.app"],
        "fingerprints": ["Tunnel .* not found", "ERR_NGROK_3200"],
        "remediation": "Claim tunnel address on ngrok or delete CNAME."
    },
    {
        "service": "Pingdom",
        "cname_patterns": [r".*\.pingdom\.com", r".*\.stats\.pingdom\.com"],
        "fingerprints": ["Sorry, couldn't find the status page"],
        "remediation": "Configure custom status page in Pingdom or delete CNAME."
    },
    {
        "service": "Read The Docs",
        "cname_patterns": [r".*\.readthedocs\.io"],
        "fingerprints": ["unknown to Read the Docs", "is unknown to Read the Docs"],
        "remediation": "Configure custom domain in Read The Docs or delete CNAME."
    },
    {
        "service": "Short.io",
        "cname_patterns": [r".*\.short\.gy", r".*\.cname\.short\.io"],
        "fingerprints": ["Link does not exist", "Short.io"],
        "remediation": "Link domain in Short.io or delete CNAME."
    },
    {
        "service": "Simplebooklet",
        "cname_patterns": [r".*\.simplebooklet\.com"],
        "fingerprints": ["We can't find this simplebooklet"],
        "remediation": "Claim booklet on Simplebooklet or delete CNAME."
    },
    {
        "service": "SmugMug",
        "cname_patterns": [r".*\.smugmug\.com"],
        "fingerprints": ["Page Not Found", "SmugMug"],
        "remediation": "Configure custom domain in SmugMug or delete CNAME."
    },
    {
        "service": "Tave",
        "cname_patterns": [r".*\.tave\.com"],
        "fingerprints": ["Checking your browser before accessing", "tave.com"],
        "remediation": "Configure domain in Táve or delete CNAME."
    },
    {
        "service": "Teachable",
        "cname_patterns": [r".*\.teachable\.com"],
        "fingerprints": ["The page you were looking for doesn't exist"],
        "remediation": "Configure custom domain in Teachable or delete CNAME."
    },
    {
        "service": "Thinkific",
        "cname_patterns": [r".*\.thinkific\.com"],
        "fingerprints": ["You may have mistyped the address or the page may have moved"],
        "remediation": "Configure custom domain in Thinkific or delete CNAME."
    },
    {
        "service": "Uberflip",
        "cname_patterns": [r".*\.uberflip\.com"],
        "fingerprints": ["Hub not found"],
        "remediation": "Configure custom domain in Uberflip or delete CNAME."
    },
    {
        "service": "Uptimerobot",
        "cname_patterns": [r".*\.uptimerobot\.com"],
        "fingerprints": ["page not found", "UptimeRobot"],
        "remediation": "Configure custom status page in UptimeRobot or delete CNAME."
    },
    {
        "service": "Wishpond",
        "cname_patterns": [r".*\.wishpond\.com"],
        "fingerprints": ["https://www.wishpond.com/404?campaign=true"],
        "remediation": "Configure custom domain in Wishpond or delete CNAME."
    },
    {
        "service": "Wix",
        "cname_patterns": [r".*\.wixcustomdomain\.com"],
        "fingerprints": ["Looks Like This Domain Isn't Connected To A Website Yet"],
        "remediation": "Connect domain in Wix site manager or delete CNAME."
    },
    {
        "service": "Worksites",
        "cname_patterns": [r".*\.worksites\.net"],
        "fingerprints": ["Company Not Found"],
        "remediation": "Configure domain in Worksites or delete CNAME."
    },
    {
        "service": "Wufoo",
        "cname_patterns": [r".*\.wufoo\.com"],
        "fingerprints": ["Profile not found"],
        "remediation": "Configure custom domain in Wufoo or delete CNAME."
    },
    {
        "service": "Firebase Hosting",
        "cname_patterns": [r".*\.web\.app", r".*\.firebaseapp\.com"],
        "fingerprints": ["Site Not Found", "The requested site does not exist", "Firebase Hosting Setup"],
        "remediation": "Claim custom domain in Firebase project settings or remove CNAME."
    },
    {
        "service": "Notion",
        "cname_patterns": [r".*\.notion\.site"],
        "fingerprints": ["This page doesn’t exist", "Notion – The all-in-one workspace"],
        "remediation": "Configure custom domain in Notion workspace or delete CNAME."
    },
    {
        "service": "GitBook",
        "cname_patterns": [r".*\.gitbook\.io"],
        "fingerprints": ["Domain not found", "This documentation domain is not configured"],
        "remediation": "Configure custom domain in GitBook space or delete CNAME."
    },
    {
        "service": "ClickFunnels",
        "cname_patterns": [r".*\.target\.clickfunnels\.com"],
        "fingerprints": ["Oops! This page does not exist"],
        "remediation": "Configure custom domain in ClickFunnels or delete CNAME."
    },
    {
        "service": "DigitalOcean Spaces",
        "cname_patterns": [r".*\.digitaloceanspaces\.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "remediation": "Create the Space in your DigitalOcean account or remove CNAME."
    },
    {
        "service": "Google Cloud Storage",
        "cname_patterns": [r".*\.storage\.googleapis\.com", r"c\.storage\.googleapis\.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "remediation": "Claim bucket in Google Cloud Storage or delete CNAME."
    },
    {
        "service": "Render",
        "cname_patterns": [r".*\.onrender\.com"],
        "fingerprints": ["Not Found - Render", "Render | Not Found"],
        "remediation": "Configure custom domain on Render web service or delete CNAME."
    },
    {
        "service": "Railway",
        "cname_patterns": [r".*\.up\.railway\.app", r".*\.railway\.app"],
        "fingerprints": ["Application not found", "Railway - Not Found"],
        "remediation": "Configure custom domain in Railway dashboard or delete CNAME."
    },
    {
        "service": "Flywheel",
        "cname_patterns": [r".*\.flywheelsites\.com"],
        "fingerprints": ["We're sorry, you've reached an unconfigured flywheel domain"],
        "remediation": "Configure domain in Flywheel dashboard or delete CNAME."
    },
    {
        "service": "Instapage",
        "cname_patterns": [r".*\.pageserve\.co"],
        "fingerprints": ["You've Reached The End Of The Internet"],
        "remediation": "Configure domain in Instapage or delete CNAME."
    },
    {
        "service": "Landingi",
        "cname_patterns": [r".*\.landingi\.com"],
        "fingerprints": ["The page you are looking for does not exist"],
        "remediation": "Configure domain in Landingi or delete CNAME."
    }
]


def resolve_cname(host: str) -> str:
    """
    Resolves the canonical name (CNAME) for a given hostname.
    Uses dnspython if available, with socket fallback.
    Returns the final target in the CNAME chain.
    """
    chain = resolve_cname_chain(host, max_depth=5)
    return chain[-1] if chain else ""


def resolve_cname_chain(host: str, max_depth: int = 5) -> List[str]:
    """
    Recursively resolves the CNAME chain for a given hostname up to max_depth hops.
    Guards against circular references and returns the list of intermediate and target CNAMEs.
    """
    clean_host = host.strip().lower().rstrip('.')
    if not clean_host:
        return []

    chain: List[str] = []
    seen: Set[str] = {clean_host}
    current = clean_host

    for _ in range(max_depth):
        next_hop = ""
        if HAS_DNSPYTHON:
            for ns in [None, ['1.1.1.1'], ['8.8.8.8']]:
                try:
                    resolver = dns.resolver.Resolver(configure=(ns is None))
                    if ns:
                        resolver.nameservers = ns
                    resolver.timeout = 2.0
                    resolver.lifetime = 2.0
                    answers = resolver.resolve(current, 'CNAME')
                    for rdata in answers:
                        next_hop = rdata.target.to_text().rstrip('.').lower()
                        break
                    if next_hop:
                        break
                except Exception:
                    continue

        if not next_hop:
            # Socket fallback
            try:
                cname, _, _ = socket.gethostbyname_ex(current)
                if cname and cname.lower() != current:
                    next_hop = cname.lower().rstrip('.')
            except Exception:
                pass

        if not next_hop or next_hop in seen:
            break

        chain.append(next_hop)
        seen.add(next_hop)
        current = next_hop

    return chain


def _check_target_resolves(cname: str) -> bool:
    """Verifies whether a CNAME target resolves to any IPv4/IPv6 address."""
    clean = cname.strip().rstrip('.')
    if not clean:
        return False
    if HAS_DNSPYTHON:
        for ns in [['1.1.1.1', '8.8.8.8'], None]:
            try:
                r = dns.resolver.Resolver(configure=(ns is None))
                if ns:
                    r.nameservers = ns
                r.timeout = 1.5
                r.lifetime = 1.5
                for qtype in ('A', 'AAAA'):
                    try:
                        ans = r.resolve(clean, qtype)
                        if ans and len(ans) > 0:
                            return True
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
            except Exception:
                pass
    try:
        socket.gethostbyname(clean)
        return True
    except Exception:
        pass
    return False


def _audit_single_host(host: str) -> dict:
    host = host.strip().lower()
    if not host:
        return {}

    cname = resolve_cname(host)
    if not cname:
        return {
            "host": host,
            "cname": "None (Direct A/AAAA)",
            "service": "Internal / Direct",
            "status": "safe",
            "status_label": "Direct Record",
            "evidence": "No external CNAME alias detected.",
            "remediation": "None required."
        }

    chain = resolve_cname_chain(host, max_depth=5)
    if not chain:
        chain = [cname]
    elif cname not in chain:
        chain.append(cname)

    # Match CNAME against cloud service patterns across entire chain
    matched_rule = None
    target_cname = cname
    for hop in reversed(chain):
        for rule in SERVICE_SIGNATURES:
            for pattern in rule["cname_patterns"]:
                if re.search(pattern, hop, re.IGNORECASE):
                    matched_rule = rule
                    target_cname = hop
                    break
            if matched_rule:
                break
        if matched_rule:
            break

    if not matched_rule:
        # Check if CNAME target itself is an orphaned dead pointer (NXDOMAIN)
        target_resolves = _check_target_resolves(cname)
        if not target_resolves:
            return {
                "host": host,
                "cname": cname,
                "service": "Orphaned Pointer / NXDOMAIN",
                "status": "dangling",
                "status_label": "Dangling Pointer (Risk)",
                "evidence": f"CNAME target '{cname}' does not resolve (NXDOMAIN / orphaned asset).",
                "remediation": f"Remove obsolete DNS CNAME record pointing to non-existent target '{cname}'."
            }

        return {
            "host": host,
            "cname": cname,
            "service": "Third-Party CNAME",
            "status": "info",
            "status_label": "Active CNAME",
            "evidence": f"Points to {cname} (No known unclaimed signature match).",
            "remediation": "Monitor CNAME target lifecycle."
        }

    service_name = matched_rule["service"]
    fingerprints = matched_rule["fingerprints"]
    remediation = matched_rule["remediation"]

    # Verify if CNAME is dangling or returning unclaimed asset signature
    evidence = ""
    is_dangling = False
    connection_failed = False

    if HAS_REQUESTS:
        endpoints = [f"https://{host}", f"http://{host}"]
        for url in endpoints:
            resp = None
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubZero/2.2"},
                    timeout=2.5,
                    verify=False,
                    allow_redirects=True,
                    stream=True
                )
                body = ""
                try:
                    chunk = next(resp.iter_content(32768), b"")
                    body = chunk.decode('utf-8', errors='ignore')
                except Exception:
                    body = getattr(resp, 'text', '') or ''

                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        is_dangling = True
                        evidence = f"Matched '{fp}' fingerprint in {resp.status_code} response."
                        break
                if is_dangling:
                    break
            except Exception:
                connection_failed = True
                continue
            finally:
                if resp is not None:
                    try:
                        resp.close()
                    except Exception:
                        pass

    # If HTTP connection failed, verify whether CNAME target itself resolves
    if not is_dangling and connection_failed:
        target_resolves = _check_target_resolves(target_cname)
        if not target_resolves:
            is_dangling = True
            evidence = f"CNAME target '{target_cname}' does not resolve (NXDOMAIN / orphaned asset)."

    if is_dangling:
        return {
            "host": host,
            "cname": cname,
            "service": service_name,
            "status": "dangling",
            "status_label": "Dangling Pointer (Risk)",
            "evidence": evidence or f"Points to unclaimed {service_name} asset.",
            "remediation": remediation
        }

    return {
        "host": host,
        "cname": cname,
        "service": service_name,
        "status": "safe",
        "status_label": "Claimed / Active",
        "evidence": f"CNAME points to active {service_name} infrastructure.",
        "remediation": "None required (service is active)."
    }


def audit_hosts(hosts: list, max_workers: int = 15) -> list:
    """
    Audits a list of hostnames concurrently for dangling CNAME pointers.
    Optimized for low-spec standard computers.
    """
    unique_hosts = sorted(set(h.strip().lower() for h in hosts if h.strip()))
    if not unique_hosts:
        return []

    effective_workers = max(1, min(int(max_workers) if max_workers else 15, 20, len(unique_hosts)))
    results = []
    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        futures = [pool.submit(_audit_single_host, h) for h in unique_hosts]
        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)

    # Sort: dangling risks first, then third-party, then safe direct records
    def sort_order(item):
        st = item.get("status")
        if st == "dangling":
            return 0
        if st == "info":
            return 1
        return 2

    return sorted(results, key=sort_order)
