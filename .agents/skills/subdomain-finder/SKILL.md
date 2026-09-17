---
name: subdomain-finder
description: >-
  Operational runbook, architecture guide, and troubleshooting skill for Subdomain Finder Pro.
  Use when starting the server, running recon scans, debugging DNS resolution or rate limiting,
  auditing CNAMEs, or executing test suites.
---

# Subdomain Finder Pro — Skill Guide

Comprehensive operational guide for running, debugging, and testing Subdomain Finder Pro.

---

## 1. Quick Startup Workflows

### Method A: Windows Batch Launcher (Zero Setup)
From Command Prompt or PowerShell:
```powershell
.\run.bat
```
- Automatically detects `uv` or creates an isolated `.venv` using the `py` launcher.
- Installs requirements and starts the Flask server on `http://127.0.0.1:5000`.

### Method B: Fast Ephemeral Run via `uv`
```powershell
uv run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
```

### Method C: Standard Python Virtualenv
```powershell
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

## 2. Testing & Verification

Run the full pytest suite:
```powershell
uv run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" --with "pytest>=8.0" pytest tests/ -v
```
All 34 test cases should pass, covering:
- IP Intelligence (`test_ip_intel.py`)
- DNS multi-resolver resolution & early exit (`test_dns_resolver.py`)
- Archive mining & host extraction (`test_archive_miner.py`)
- Permutation engine mutations (`test_permutations.py`)
- Provider rate-limiting, CNAME auditor, new OSINT sources, and history store (`test_requirements.py`)

---

## 3. Core Architecture & Components

### Reconnaissance Engine (`enumerator/`)
- **`providers.py`**: Coordinates 9 high-yield, active passive sources:
  - `subfinder` (local CLI binary)
  - `subfinder_all` (deep mode)
  - `amass` (passive mode)
  - `sslmate` (CertSpotter API)
  - `crt.sh` (Certificate Transparency log search)
  - `rapiddns` (Web scraping)
  - `hackertarget` (Host search API)
  - `otx` (AlienVault OTX passive DNS indicators)
  - `urlscan` (URLScan.io public historical records)
- **`request_utils.py`**: Central HTTP dispatcher with:
  - Exponential backoff + jitter (30% randomize)
  - Connection-pooled `requests.Session`
  - Per-provider throttle timers (`time.monotonic()`)
  - Random User-Agent rotation
- **`dns_resolver.py`**: Parallel queries across 10 public DNS resolvers (Cloudflare, Google, OpenDNS, Quad9, AdGuard, Control D, Level3) with early-exit cancellation when resolved.
- **`active_scanner.py`**: DNS brute force with wildcard detection and sliding worker pool.
- **`cname_auditor.py`**: Detects dangling CNAME records for cloud takeovers (AWS S3, GitHub Pages, Heroku, etc.).
- **`http_prober.py`**: Live HTTP/HTTPS status, page title, and server headers extraction.
- **`ip_intel.py`**: Classifies IPs as CDN/WAF (Cloudflare, CloudFront, Fastly, etc.) vs Origin IP.
- **`history_store.py`**: SQLite database with Write-Ahead Logging (`WAL`) mode for concurrent reads/writes.

---

## 4. REST API Quick Reference

| Endpoint | Method | Payload / Params | Description |
| :--- | :--- | :--- | :--- |
| `/api/scan` | POST | `{"domain": "example.com", "sources": ["subfinder", "crtsh"]}` | Starts background scan |
| `/api/scan/<id>` | GET | `?since=<index>` | Polls scan progress and logs |
| `/api/scan/<id>/cancel`| POST | — | Cancels active scan |
| `/api/batch/start` | POST | `{"domains": ["a.com", "b.com"]}` | Batch scan |
| `/api/probe` | POST | `{"hosts": ["api.example.com"]}` | HTTP alive probe |
| `/api/audit/cname` | POST | `{"hosts": ["dev.example.com"]}` | Dangling CNAME audit |
| `/api/archive/mine` | POST | `{"domain": "example.com"}` | Wayback & AlienVault URLs |
| `/api/graph/data` | POST | `{"results": [...]}` | 3D visual graph node data |
| `/api/results.txt` | GET | `?job_id=<id>` | Plaintext export |
| `/api/results.csv` | GET | `?job_id=<id>` | CSV export |
| `/api/results.json` | GET | `?job_id=<id>` | JSON export |

---

## 5. Troubleshooting & Common Issues

- **Rate Limits (429 / 503 from OSINT APIs)**:
  Handled automatically by `enumerator/request_utils.py` using exponential backoff and jitter. If an API is temporarily down, the other providers continue running uninterrupted.
- **Missing Dependencies**:
  `app.py` has a built-in startup check. Run `pip install -r requirements.txt` or start via `.\run.bat`.
- **Memory Management**:
  `app.py` runs a background daemon thread that purges jobs older than 30 minutes and invalidates expired cache entries every 5 minutes.
