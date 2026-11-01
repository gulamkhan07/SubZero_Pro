---
name: subdomain-finder
description: >-
  Operational runbook, architecture guide, and troubleshooting skill for SubZero (Subdomain Finder Pro).
  Use when starting the server or CLI, running recon scans, debugging DNS resolution or rate limiting,
  auditing CNAMEs, managing dynamic WAF intelligence, or executing the test suite.
---

# SubZero — Architecture & Operational Skill Guide

Comprehensive operational guide for running, debugging, testing, and automating SubZero (by Gulam Khan).

---

## 1. Quick Startup Workflows

### Method A: Web UI (Zero Setup)
```powershell
# Windows
.\run.bat

# Linux / macOS
chmod +x run.sh
./run.sh
```
- Starts the modular Flask server on `http://127.0.0.1:5000`.

### Method B: Terminal CLI & Interactive Cyber Wizard
```powershell
# Launch Interactive Cyber Wizard (step-by-step guidance)
.\subzero.bat -i

# Run fast silent scan (pipeable to httpx / nuclei)
.\subzero.bat -d example.com -silent

# Active DNS brute-force with multi-resolver verification
.\subzero.bat -d example.com -a -w 5000 -r --only-resolved -o live_subs.txt
```
*(See [COMMANDS.md](../../../COMMANDS.md) for the complete 10-second command cheat sheet).*

### Method C: Fast Ephemeral Run via `uv`
```powershell
uv run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
```

### Method D: Standard Python Virtualenv
```powershell
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

## 2. Testing & Verification

Run the full **159-test unit test suite**:
```powershell
# Standard Python unittest (zero extra dependencies):
python -m unittest discover -s tests -p "test_*.py"

# Or with uv:
uv run --with requests --with dnspython --with flask python -m unittest discover -s tests -p "test_*.py"

# Or with pytest:
pytest tests/ -v
```
All **159 test cases across 15 test modules** must pass with 100% green status, covering:
- **`test_cli.py`**: Terminal CLI Engine, Wizard, silent piping, and Tool Exclusions.
- **`test_dynamic_intelligence.py`**: Dynamic WAF/Cloud IP intelligence updater, ETag handling, and drop prevention.
- **`test_ip_intel.py`**: IP Intelligence, ASN classification, and Origin Server vs CDN/WAF.
- **`test_dns_resolver.py`**: Multi-Resolver DNS Integrity across Tier-1 public resolvers & Dead-Domain Verification.
- **`test_axfr.py`**: DNS Zone Transfer (AXFR) pre-flight detection & nameserver checks.
- **`test_shodan_exporter.py`**: Shodan 1:1 schema generation & Apex DNS record harvesting.
- **`test_nested_engine.py`**: Multi-tenant & cloud-native recursive subdomain engine.
- **`test_permutations.py`**: Subdomain permutations & mutation engine.
- **`test_shodan_free.py`**: Shodan Free InternetDB harvester querying live IP addresses.
- **`test_batch_live_check.py` & `test_batch_options.py`**: Multi-domain batch streaming and DNS fallbacks.
- **`test_download_filter.py`**: ZIP packaging, staleness checking, and results filtering.
- **`test_advanced_features.py`**: Database history pruning, timeout adapters, and project metadata constants.
- **`test_requirements.py`**: Passive OSINT providers, Subfinder timeouts, CNAME takeover auditor, and History Store.

---

## 3. Core Architecture & Components

The application uses a **modular, decoupled architecture**:

### A. Modular Web Application Layer (`routes/` & `services/`)
- **`app.py`**: Coordinates Flask configuration, blueprints registration, and background daemon cleanup threads.
- **`routes/scan.py`**: Core scan initiation (`/api/scan`), progress polling (`/api/scan/<id>`), and cancellation.
- **`routes/batch.py`**: Multi-domain concurrent batch scanner with real-time SSE event streaming.
- **`routes/advanced.py`**: Dedicated endpoints for Permutations, Nested Sub-zones, AXFR audits, and Shodan InternetDB.
- **`routes/audit.py`**: Dangling CNAME takeover auditing and live HTTP service prober.
- **`routes/history.py`**: Scan history timeline, attack surface diff comparisons, and deletion.
- **`routes/download.py`**: Instant project ZIP bundle generator with automatic mtime staleness invalidation.
- **`routes/export.py`**: Plaintext (`.txt`), CSV, JSON, and executive HTML export endpoints.
- **`routes/graph.py`**: 3D force-directed attack surface topology graph endpoint.
- **`services/scan_engine.py`**: Core scan orchestration loop (`_run_scan`), concurrency dispatch, and data enrichment.
- **`services/job_manager.py`**: Thread-safe in-memory job store (`JOBS`), TTL caching, and automatic garbage collection.
- **`services/filter_service.py`**: Fast live/dead asset classification and search-query filtering.
- **`services/batch_manager.py`**: Concurrent batch execution engine for up to 25 target domains.

### B. Dynamic WAF & Cloud Intelligence Engine (`enumerator/intelligence/`)
- **`updater.py`**: Synchronizes official machine-readable IP feeds (AWS, Google Cloud, Cloudflare, Oracle, Fastly, BunnyCDN) using HTTP ETags and conditional GETs.
- **`database.py`**: High-speed Radix/Interval tree indexing 6,100+ IPv4 and 2,800+ IPv6 subnets across 45 cataloged cloud and WAF vendors.
- **`validation.py`**: Catastrophic drop protection preventing corrupted or partial feeds from wiping known-good CIDRs.
- **`registry.py`**: Metadata catalog for 45 cloud providers, WAF signatures, and vendor IP feed endpoints.
- **`data/lkg_intelligence.json`**: Built-in Last-Known-Good baseline dataset for offline resilience.

### C. Reconnaissance & Security Auditing (`enumerator/`)
- **`cli.py`**: Terminal command-line interface with `-silent` stdout piping, interactive wizard, tool exclusions, and export pipeline.
- **`providers.py`**: Coordinates high-yield passive sources (Subfinder, crt.sh, SSLMate, RapidDNS, HackerTarget, AlienVault OTX, URLScan, Amass).
- **`active_scanner.py`**: Multi-threaded active DNS wordlist brute-force engine with wildcard auto-suppression.
- **`dns_resolver.py`**: Cascaded validation across 10 Tier-1 public anycast resolvers (Cloudflare, Google, OpenDNS, Quad9, AdGuard, Control D, Level3).
- **`axfr_auditor.py`**: Authoritative nameserver DNS Zone Transfer pre-flight auditor.
- **`shodan_exporter.py`**: Shodan schema export & apex infrastructure DNS harvesting (MX, NS, SOA, TXT, DMARC).
- **`shodan_free.py`**: 100% Free, zero-API-key Shodan InternetDB harvester querying all resolved IP addresses.
- **`nested_engine.py`**: Multi-tenant, cloud-native recursive subdomain engine extracting sub-zones and candidate permutations.
- **`tls_scraper.py`**: Direct TLS SAN certificate scraper probing ports 443 and 8443 across all live IPs.
- **`cname_auditor.py`**: Detects dangling CNAME records for cloud takeovers (AWS S3, GitHub Pages, Azure, Shopify, etc.).
- **`http_prober.py`**: Live HTTP/HTTPS status, page title, and server headers extraction with 32KB streaming RAM cap.
- **`origin_verifier.py`**: Actively verifies whether an IP is a True Origin Server bypassing WAF protection.
- **`ptr_sweeper.py`**: Reverse DNS (PTR) subnet sweep across surrounding origin IP blocks.
- **`ip_intel.py`**: Classifies IPs as CDN/WAF vs Direct Origin IP.
- **`history_store.py`**: SQLite database with Write-Ahead Logging (`WAL`) mode for concurrent reads/writes and scan diff tracking.

---

## 4. REST API Quick Reference

| Endpoint | Method | Payload / Query | Description |
| :--- | :--- | :--- | :--- |
| `/api/scan` | POST | `{"domain": "example.com", "sources": ["subfinder", "crtsh"]}` | Starts background scan |
| `/api/scan/<id>` | GET | `?since=<index>` | Polls scan progress and live logs |
| `/api/scan/<id>/cancel` | POST | — | Cancels active scan job |
| `/api/batch/start` | POST | `{"domains": ["a.com", "b.com"]}` | Starts multi-domain batch scan |
| `/api/batch/stream/<id>` | GET | — | Server-Sent Events (SSE) real-time stream |
| `/api/probe` | POST | `{"hosts": ["api.example.com"]}` | HTTP alive probe & banner capture |
| `/api/audit/cname` | POST | `{"hosts": ["dev.example.com"]}` | Dangling CNAME takeover audit |
| `/api/advanced/permutations` | POST | `{"domain": "example.com", "seeds": [...]}` | Dynamic subdomain mutation scan |
| `/api/advanced/nested` | POST | `{"domain": "example.com", "hosts": [...]}` | Multi-tenant recursive sub-zone discovery |
| `/api/advanced/shodan` | POST | `{"ips": ["1.2.3.4"]}` | Shodan InternetDB open port harvester |
| `/api/advanced/axfr` | POST | `{"domain": "example.com"}` | Authoritative nameserver AXFR audit |
| `/api/history` | GET | `?domain=example.com` | Lists historical scans from SQLite |
| `/api/history/diff` | GET | `?old_id=<id>&new_id=<id>` | Calculates added / removed / persistent attack surface |
| `/api/download/zip` | GET | — | Downloads clean project ZIP archive |
| `/api/results.txt` | GET | `?job_id=<id>` | Plaintext newline-delimited export |
| `/api/results.csv` | GET | `?job_id=<id>` | Spreadsheet audit CSV export |
| `/api/results.json` | GET | `?job_id=<id>` | Full structured JSON export |

---

## 5. CLI Operational Diagnostic Commands

```powershell
# 1. Check network connectivity and pre-flight DNS health
.\subzero.bat --check-network

# 2. Check dynamic WAF/Cloud intelligence database status
.\subzero.bat --intel-status

# 3. Synchronize dynamic WAF/Cloud IP ranges from upstream feeds
.\subzero.bat --update-intel

# 4. List all available reconnaissance engines and binary status
.\subzero.bat -ls

# 5. Interactive Cyber Wizard
.\subzero.bat -i

# 6. Active DNS Brute-Force with Rate Limiting (Anti-Flagging)
.\subzero.bat -d example.com -a -w 5000 --rate 150

# 7. Live HTTP Probing with Anti-WAF Rate Limiting & Micro-Jitter
.\subzero.bat -d example.com -r --probe --probe-rate 15
```

---

## 6. Troubleshooting & Operational Runbook

- **HTTP Prober Rate Limiting & Anti-WAF Jitter**:
  Live HTTP/HTTPS probing uses a thread-safe token-bucket rate limiter with micro-jitter (±20% variance) and adaptive 429/WAF cooldown backoff. Protects your IP from Cloudflare Error 1015/1020, HTTP 429 rate limits, and edge firewall bans. Configurable via `--probe-rate <QPS>` in CLI or the UI rate limit dropdown.
- **Active DNS Rate Limiting & Anti-Flagging**:
  Active DNS brute-forcing uses a thread-safe token-bucket rate limiter (default: 150 QPS) to prevent upstream Google DoH 429 rate-limiting and ISP UDP throttling, especially during bulk/batch scans. Configurable via `--rate <QPS>` in CLI or the UI rate limit dropdown.
- **Subfinder Timeouts**:
  Subfinder timeout is set to 70s to match its internal 60s `-max-time`. Zero premature kills.
- **Tool Exclusions**:
  Users can skip any tool via `-x <tools>`, `--no-<tool>`, or through the interactive wizard. Excluded tools are **never called**.
- **Amass Separation**:
  OWASP Amass is decoupled from default passive recon and does not run unless explicitly passed via `--amass`.
- **Dynamic Intelligence Failsafe**:
  If an upstream provider feed returns 404 or fails validation, SubZero's `validate_dataset_change()` rejects the drop and safely preserves the Last-Known-Good dataset.
- **Memory & Job Lifecycle**:
  `app.py` runs a background daemon thread that purges jobs older than 30 minutes and invalidates expired cache entries every 5 minutes.
- **DNS Resolution on Windows**:
  Always use UDP resolver queries across `PUBLIC_RESOLVERS`. Avoid invoking `socket.getaddrinfo()` for non-existent domains (`NXDOMAIN`) to prevent Windows NetBIOS/LLMNR 12-second broadcast delays.
