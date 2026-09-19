---
name: subdomain-finder
description: >-
  Operational runbook, architecture guide, and troubleshooting skill for SubZero (Subdomain Finder Pro).
  Use when starting the server or CLI, running recon scans, debugging DNS resolution or rate limiting,
  auditing CNAMEs, or executing test suites.
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
- Starts the Flask server on `http://127.0.0.1:5000`.

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

Run the full 46-test unit test suite:
```powershell
# Standard Python unittest (zero extra dependencies):
python -m unittest discover -s tests -p "test_*.py"

# Or with uv:
uv run --with requests --with dnspython --with flask python -m unittest discover -s tests -p "test_*.py"

# Or with pytest:
pytest tests/ -v
```
All **46 test cases** must pass with 100% green status, covering:
- Terminal CLI Engine, Wizard & Tool Exclusions (`test_cli.py`)
- IP Intelligence & Origin Server vs CDN/WAF (`test_ip_intel.py`)
- Multi-Resolver DNS Integrity & Dead-Domain Verification (`test_dns_resolver.py`)
- Wayback & AlienVault Historical URL Mining (`test_archive_miner.py`)
- Subdomain Permutations & Mutation Engine (`test_permutations.py`)
- Passive OSINT providers, Subfinder timeouts, CNAME takeover auditor, and History Store (`test_requirements.py`)

---

## 3. Core Architecture & Components

### Reconnaissance Engine (`enumerator/`)
- **`cli.py`**: Terminal command-line interface with `-silent` stdout piping, interactive wizard, tool exclusions, and export pipeline.
- **`providers.py`**: Coordinates high-yield passive sources:
  - `subfinder` (Subprocess binary with 70s timeout)
  - `crt.sh` (Certificate Transparency log search)
  - `sslmate` (CertSpotter API)
  - `rapiddns` (Web scraping)
  - `hackertarget` (Host search API)
  - `otx` (AlienVault OTX passive DNS indicators)
  - `urlscan` (URLScan.io public historical records)
  - `amass` (*Decoupled / OFF by default*, only enabled with `--amass` or `-all`)
- **`request_utils.py`**: Central HTTP dispatcher with exponential backoff + jitter, session pooling, and network pre-flight check (`check_network_connectivity()`).
- **`dns_resolver.py`**: Parallel queries across 11 public DNS resolvers (Cloudflare, Google, OpenDNS, Quad9, AdGuard, Control D, Level3).
- **`active_scanner.py`**: High-speed DNS wordlist brute-forcer with sequence telemetry (`#0001` to `#5000`) and wildcard DNS auto-suppression.
- **`cname_auditor.py`**: Detects dangling CNAME records for cloud takeovers (AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Zendesk, Surge.sh).
- **`http_prober.py`**: Live HTTP/HTTPS status, page title, and server headers extraction with 32KB streaming RAM cap.
- **`ip_intel.py`**: Classifies IPs as CDN/WAF (Cloudflare, CloudFront, Fastly, Akamai) vs Direct Origin IP.
- **`history_store.py`**: SQLite database with Write-Ahead Logging (`WAL`) mode for concurrent reads/writes and scan diff tracking.

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

- **Subfinder Timeouts**:
  Subfinder timeout is set to 70s to match its internal 60s `-max-time`. Zero premature kills.
- **Tool Exclusions**:
  Users can skip any tool via `-x <tools>`, `--no-<tool>`, or through the interactive wizard. Excluded tools are **never called**.
- **Amass Separation**:
  OWASP Amass is decoupled from default passive recon and does not run unless explicitly passed via `--amass`.
- **Memory Management**:
  `app.py` runs a background daemon thread that purges jobs older than 30 minutes and invalidates expired cache entries every 5 minutes.
