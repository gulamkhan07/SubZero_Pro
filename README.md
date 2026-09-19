# SubZero ⚡

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/Framework-Flask_3.0-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Windows_|_Linux_|_macOS_|_Docker-blue?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge" alt="PRs Welcome" />
  <img src="https://img.shields.io/badge/Contributor_Covenant-v2.1-orange?style=for-the-badge" alt="Code of Conduct" />
</p>

> **Enterprise-Grade OSINT Reconnaissance, Multi-Resolver DNS Integrity, Permutations Engine, Wayback URL Miner & Cloud Asset Auditor.**  
> **Designed & Developed by: Gulam Khan**  
> **Version: 2.2.0 (High-Performance & Low-Spec PC Calibrated)**

---

## 👨‍💻 Creator & Lead Architect

<table>
  <tr>
    <td>
      <h3>Gulam Khan</h3>
      <p><b>Founder & Lead Architect</b> of SubZero</p>
      <p>
        <a href="https://github.com/gulamkhan07"><img src="https://img.shields.io/badge/GitHub-Profile-181717?style=flat&logo=github" alt="GitHub"></a>
        <a href="https://linkedin.com/"><img src="https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin" alt="LinkedIn"></a>
      </p>
      <p><i>Passionate about high-performance cybersecurity tooling, passive reconnaissance, and decentralized OSINT engineering.</i></p>
    </td>
  </tr>
</table>

---

## 🌟 Modules & Features

SubZero is a modular, decoupled cybersecurity reconnaissance platform featuring 9 integrated engines:

```
                      ┌─────────────────────────────────┐
                      │    SubZero (UI)                 │
                      └────────────────┬────────────────┘
                                       │
         ┌───────────────┬─────────────┼─────────────┬───────────────┐
         │               │             │             │               │
  ┌──────▼──────┐ ┌──────▼──────┐ ┌────▼────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │Single Recon │ │Permutations │ │ Archive │ │Batch Scanner│ │CNAME Auditor│
  │OSINT+Active │ │  & Mutation │ │  Miner  │ │ Multi-Domain│ │ Takeover    │
  └──────┬──────┘ └──────┬──────┘ └────┬────┘ └──────┬──────┘ └──────┬──────┘
         │               │             │             │               │
         └───────────────┴─────────────┼─────────────┴───────────────┘
                                       │
                      ┌────────────────▼────────────────┐
                      │ 11-Tier Tier-1 Public Resolvers │
                      │  Cloudflare, Google, OpenDNS... │
                      └─────────────────────────────────┘
```

### 1. 🎯 Single Domain Reconnaissance (Passive + Active)
- **7 Passive OSINT Sources**: Subfinder, SSLMate CertSpotter, crt.sh, RapidDNS, HackerTarget, and OWASP Amass.
- **High-Speed Active DNS Brute-Force**: Thread-safe DNS resolver with sequence-numbered live telemetry logs (`#0001` to `#5000`) and wildcard DNS auto-detection.
- **One-Click Export**: Save reports in **Executive HTML, CSV, TXT, and JSON**.

### 2. ⚡ Multi-Resolver DNS Integrity Engine
- Validates discovered assets across **11 Tier-1 Recursive Anycast Resolvers**:
  - `Cloudflare` (`1.1.1.1`, `1.0.0.1`)
  - `Google Public DNS` (`8.8.8.8`, `8.8.4.4`)
  - `OpenDNS / Cisco Umbrella` (`208.67.222.222`, `208.67.220.220`)
  - `Quad9` (`9.9.9.9`, `149.112.112.112`)
  - `AdGuard DNS` (`94.140.14.14`)
  - `Control D` (`76.76.2.0`)
  - `Level3 / Lumen` (`4.2.2.1`)
- **Definitive Dead Domain Proof**: A domain is marked `Dead` only when confirmed unreachable across all configured resolvers.
- **Targeted Resolver Selection**: Allows auditing resolution behavior through a specific provider (e.g. testing Cloudflare vs. Google).

### 3. 🧬 Subdomain Permutations & Mutations Engine
- Generates intelligent permutation candidates from seed subdomains using:
  - Prefix/suffix mutations (`api-dev`, `dev-api`, `api-test`, `admin-portal`).
  - Numeric sequence variations (`api1`, `api-01`, `dev2`).
  - Depth-level subdomain mutations (`dev.api.target.com`).
- Direct one-click import from Single Recon results into the Permutations engine.
- Concurrently resolves candidate subdomains with dead/alive filtering.

### 4. 📜 Historical Archive & Wayback URL Intelligence Miner
- Mines historical endpoints from **Wayback Machine CDX API** and **AlienVault OTX**.
- Automatically categorizes results into:
  - 🔴 **Sensitive & Leaked Files**: `.env`, `.git`, `.sql`, `.zip`, `.bak`, and configuration files.
  - 🔑 **Parameter Endpoints**: URLs with query parameters (`?token=`, `?redirect=`, `?id=`) for vulnerability hunting.
  - 🌐 **Historical Subdomains**: Dormant or forgotten infrastructure.
  - ⚡ **API Endpoints**: `/api/v1`, `/graphql`, `/rest` routes.
  - 📂 **Complete URL Inventory**: Filterable table with in-place one-click copy.

### 5. 🗂️ Multi-Domain Batch Queue Scanner
- Run continuous reconnaissance on up to 25 root domains concurrently.
- Real-time queue telemetry with aggregated subdomain totals.

### 6. 🔄 History & Attack Surface Diff Tracker
- SQLite-backed historical timeline of all reconnaissance scans.
- Calculates additions (newly emerged assets), removals (decommissioned subdomains), and common assets between any two dates.

### 7. 🛡️ DNS Asset Integrity & Dangling CNAME Auditor
- Defensive auditing against cloud service signatures: **AWS S3, GitHub Pages, Heroku, Microsoft Azure, Shopify, Zendesk, Fastly, and Surge.sh**.
- Detects orphaned pointers and dangling CNAME records vulnerable to subdomain takeover.

### 8. 🌐 Live HTTP Web Service Status Prober
- Decoupled on-demand HTTP/HTTPS status inspector (200, 301, 403, 500).
- Captures web server banners, round-trip latency, and HTML `<title>` tags.
- **Streaming RAM Cap (32KB)** prevents high memory consumption on large target sets.

### 9. 🕸️ Interactive 3D Attack Surface Graph
- Force-directed topological graph clustering subdomains into functional security categories: `api`, `dev`, `auth`, `web`, and `infra`.

---

## 📂 Systematic Project Structure

```text
subzero/
├── enumerator/               # Core reconnaissance & intelligence modules
│   ├── active_scanner.py     # Multi-threaded active DNS wordlist brute-forcer
│   ├── archive_miner.py      # Wayback Machine & AlienVault URL intelligence
│   ├── cli.py                # Terminal command-line interface & cyber wizard
│   ├── cname_auditor.py      # Dangling CNAME takeover vulnerability auditor
│   ├── dns_resolver.py       # Multi-resolver engine (Cloudflare, Google, Quad9...)
│   ├── history_store.py      # SQLite historical persistence & snapshot diffs
│   ├── http_prober.py        # Concurrent HTTP/HTTPS service inspector
│   ├── ip_intel.py           # Origin server vs. CDN/WAF classification
│   ├── normalizer.py         # Subdomain regex hygiene & root domain filtering
│   ├── permutation_engine.py # Subdomain permutation & mutation generator
│   ├── providers.py          # OSINT source query workers & binary execution
│   └── request_utils.py      # Connection diagnostics, session pooling & retries
├── static/                   # Web platform front-end assets
│   └── style.css             # Modern tactile monochrome UI stylesheet
├── templates/                # Server-rendered HTML templates
│   ├── index.html            # Main web dashboard interface
│   └── report_template.html  # Exportable executive HTML report template
├── tests/                    # Automated test suite (46 comprehensive unit tests)
│   ├── conftest.py
│   ├── test_archive_miner.py
│   ├── test_cli.py
│   ├── test_dns_resolver.py
│   ├── test_ip_intel.py
│   ├── test_permutations.py
│   └── test_requirements.py
├── wordlists/                # Curated SecLists DNS brute-force dictionaries
│   ├── subdomains_5000.txt   # Top 5,000 SecLists prefixes (recommended)
│   ├── subdomains_10000.txt  # Extended 10,000 SecLists prefixes
│   └── subdomains_20000.txt  # Deep 20,000 brute-force dictionary
├── app.py                    # Flask Web application & REST API server
├── cli.py                    # CLI runner entrypoint
├── subzero.bat               # Windows CLI launcher (modular & auto-bootstrap)
├── subzero                   # Linux / macOS CLI executable launcher
├── run.bat                   # Windows Web UI server launcher
├── run.sh                    # Linux / macOS Web UI server launcher
├── install_tools.py          # Cross-platform installer for external binaries
├── pyproject.toml            # Standard packaging, metadata & scripts config
├── requirements.txt          # Python runtime dependencies
├── Dockerfile                # Production container definition
└── docker-compose.yml        # Docker Compose deployment stack
```

---

## ⚡ Low-Spec Hardware & Performance Calibration
- **Zero GPU Overhead**: Replaced heavy Gaussian blur filters and infinite geometry morphing loops with hardware-accelerated static CSS radial gradients. Idle GPU consumption is **0% – 1%**.
- **Bounded Thread Pools**: Concurrency capped at 15–30 threads to prevent socket exhaustion and packet loss on consumer Wi-Fi routers.
- **Memory Capping**: Response streaming capped at 32KB to ensure RAM usage remains strictly below 60MB.
- **Log Buffer Optimization**: Constant-time slice pruning prevents array reallocation lag on 10,000+ log events.

---

## 🚀 Quick Start (Installation & Execution)

### Option 1: On Windows (Automated Launcher)
Simply double-click `run.bat` or run:
```cmd
run.bat
```
*Detects Python or `uv`, verifies dependencies, and opens the application at `http://127.0.0.1:5000`.*

---

### Option 2: On Linux / macOS
```bash
chmod +x run.sh bootstrap.sh
./run.sh
```

---

### Option 3: Docker / Docker Compose
Run the entire platform in an isolated container:
```bash
docker compose up -d
```
Access the dashboard at `http://localhost:5000`.

---

### Option 4: Manual Python Installation
```bash
# 1. Clone the repository
git clone https://github.com/gulamkhan07/subdomain_finder_pro.git
cd subdomain_finder_pro

# 2. Install dependencies
pip install -r requirements.txt

# 3. Download external binaries & wordlists (Optional)
python install_tools.py

# 4. Start the server
python app.py
```
Open your browser at:
👉 **`http://127.0.0.1:5000`**

---

## 💻 Terminal CLI Interface (For Cybersecurity Professionals)

SubZero includes a dedicated, high-speed command-line interface designed for penetration testers, bug bounty hunters, and red teamers. It supports clean stdout piping (`-silent`), active DNS wordlist brute-forcing, multi-resolver validation, CNAME takeover audits, live HTTP probing, and JSON/CSV/TXT file exports.

### Quick Launchers

- **Windows**: `subzero.bat -d example.com -silent`
- **Linux / macOS**: `./subzero -d example.com -silent`
- **Universal Python**: `python cli.py -d example.com -silent`

### Security Pipeline Examples

```bash
# 1. Silent enumeration piped directly into httpx and nuclei:
subzero -d target.com -silent | httpx -silent -title -tech-detect -status-code

# 2. Active DNS brute-force with 5,000-word wordlist, multi-resolver check, and plaintext export:
subzero -d target.com -a -w 5000 -r --only-resolved -o live_subdomains.txt

# 3. Target list scan with CNAME takeover auditing and IP intelligence:
subzero -dL domains.txt -all --cname --ip-intel -oCSV attack_surface.csv

# 4. Full security audit with HTTP probing, Wayback archive URLs, and structured JSON output:
subzero -d target.com -r --probe --cname --archive -oJ full_recon.json

# 5. Pipeline stdin input (pipe targets directly):
cat roots.txt | subzero -silent | httpx -silent | nuclei -t cves/

# 6. Pre-flight connectivity diagnostic:
subzero --check-network
```

### CLI Command Flags & Options

| Flag | Description |
| :--- | :--- |
| `-d, --domain <domain>` | Target root domain to enumerate (e.g. `example.com`) |
| `-dL, -l, --list <file>` | Path to file containing target domains (one per line) |
| `-s, --sources <s1,s2>` | Comma-separated list of passive sources to query (defaults to all fast passive tools) |
| `-x, --exclude <tools>` | Exclude/remove specific tools by name (e.g. `-x subfinder,urlscan`) |
| `--no-<tool>` | Directly skip any individual tool (e.g. `--no-subfinder`, `--no-urlscan`, `--no-crtsh`) |
| `--amass` | Explicitly enable OWASP Amass (kept separate by default) |
| `-all, --deep` | Enable deep, slow passive sources (`subfinder_all`, `amass`) |
| `-ls, --list-sources` | Display table of all reconnaissance sources and installation status |
| `-a, --active` | Enable high-speed active DNS wordlist brute-forcing |
| `-w, --wordlist <size>` | Wordlist size (`100`, `1000`, `5000`, `20000`) or custom wordlist file |
| `-t, --threads <int>` | Concurrency for active DNS scanning (default: `500`) |
| `--permute` | Mutate discovered subdomains with permutation engine |
| `-r, --resolve` | Resolve discovered subdomains across Tier-1 public multi-resolvers |
| `--resolver <name>` | Specific resolver (`cloudflare`, `google`, `quad9`, `opendns`, `all`) |
| `--only-resolved` | Filter output to strictly live/resolved subdomains |
| `--cname` | Audit for dangling CNAME records (subdomain takeover) |
| `--probe` | Probe HTTP/HTTPS status code, page title, and server headers |
| `--ip-intel` | Classify IPs as Direct Origin server vs Cloudflare/CDN/WAF |
| `--archive` | Mine historical URLs from Wayback Machine and AlienVault |
| `-o, --output <file>` | Plaintext output file path (one subdomain per line) |
| `-oJ, --json <file>` | Structured JSON report output file path |
| `-oCSV, --csv <file>` | CSV report output file path |
| `-silent, -q, --quiet` | Clean stdout output (pure subdomains, 100% pipe-friendly) |
| `-v, --verbose` | Enable verbose diagnostic logging and timings |
| `--check-network` | Test internet connectivity and DNS resolution reachability |
| `--no-color` | Disable ANSI terminal color codes |

---

## 📡 REST API Reference

| Method | Endpoint | Description | Sample Payload / Query |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/scan` | Initiate single domain reconnaissance scan | `{"domain": "example.com", "active_dns": true, "dns_resolver": "all"}` |
| `GET` | `/api/scan/<id>` | Poll scan progress & telemetry logs | `?since=0` |
| `POST` | `/api/permutations/generate` | Generate mutation candidate subdomains | `{"domain": "example.com", "seeds": ["api", "dev"], "limit": 300}` |
| `POST` | `/api/permutations/scan` | Generate and actively resolve mutations | `{"domain": "example.com", "seeds": ["api"], "dns_resolver": "all"}` |
| `POST` | `/api/archive/mine` | Extract Wayback & AlienVault URLs | `{"domain": "example.com", "limit": 2500}` |
| `POST` | `/api/batch/start` | Queue multi-domain batch scan | `{"domains": ["target1.com", "target2.com"]}` |
| `POST` | `/api/probe` | Inspect live HTTP status & server headers | `{"hosts": ["api.example.com", "app.example.com"]}` |
| `POST` | `/api/audit/cname` | Audit CNAME records for dangling takeovers | `{"hosts": ["s3.example.com"]}` |
| `GET` | `/api/history` | Retrieve previous scan summaries | `?limit=50` |
| `GET` | `/api/history/diff` | Compare two historical scan snapshots | `?old=<id1>&new=<id2>` |
| `GET` | `/api/download/zip` | Download complete project source code as zip | `None` |

---

## 🧪 Testing

SubZero includes a comprehensive unit test suite:
```bash
pytest tests/
```
All tests validate provider error handling, multi-resolver logic, candidate generation rules, and archive parsing.

---

---

## 🤝 Contributing & Community

We warmly welcome contributions from bug bounty hunters, security researchers, and software engineers!

- 📖 **Contribution Guidelines**: Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting code.
- 📜 **Code of Conduct**: Review our community standards in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- 🛡️ **Security Inquiries**: To report vulnerabilities responsibly, see [SECURITY.md](SECURITY.md).
- 🏆 **Hall of Fame**: Check out our project contributors in [CONTRIBUTORS.md](CONTRIBUTORS.md).

---

## ⚖️ Legal & Ethical Use Disclaimer

> [!WARNING]
> **SubZero is designed for educational, defensive security auditing, and authorized penetration testing purposes only.**  
> Usage of SubZero for scanning targets without prior mutual consent is strictly illegal. The developer (**Gulam Khan**) and contributors assume no liability and are not responsible for any misuse, damage, or legal consequences caused by this program. Always obtain proper authorization before assessing external infrastructure.

---

## 📄 License
This project is open-source software licensed under the **[MIT License](LICENSE)**.  
Copyright (c) 2026 **Gulam Khan**. All rights reserved.

