# ⚡ SubZero CLI: Complete Commands & Cheat Sheet Guide

> **Official Command-Line Interface (CLI) Manual & Quick Reference Guide**  
> **Platform: SubZero v2.2.0 • Developed by Gulam Khan**

---

## 📑 Table of Contents
1. [⚡ Quick Start (In 10 Seconds)](#-quick-start-in-10-seconds)
2. [🎯 Top 10 Real-World Recon Commands (Copy & Paste)](#-top-10-real-world-recon-commands-copy--paste)
3. [💻 Platform Launchers (Windows, Linux, macOS)](#-platform-launchers-windows-linux-macos)
4. [🛠️ Complete CLI Flags & Options Table](#️-complete-cli-flags--options-table)
5. [🚫 How to Exclude / Turn Off Specific Tools](#-how-to-exclude--turn-off-specific-tools)
6. [🔗 Chaining & Piping with Other Tools (`httpx`, `nuclei`, `naabu`)](#-chaining--piping-with-other-tools-httpx-nuclei-naabu)
7. [🩺 Diagnostic & Network Health Commands](#-diagnostic--network-health-commands)

---

## ⚡ Quick Start (In 10 Seconds)

### Option A: Interactive Wizard (Sabse Aasan - No Flags Required!)
Agar aapko koi command ya flags yaad nahi rakhne, toh direct interactive wizard chalayein. Yeh aapse step-by-step target domain, tools, aur outputs poochega:

```bash
# Windows
subzero.bat -i

# Linux / macOS
./subzero -i

# Standard Python
python cli.py -i
```

*(Note: Agar aap Windows par bina arguments ke `subzero.bat` double click karenge, tab bhi yeh interactive wizard automatically open ho jata hai!)*

### Option B: Simplest Fast Recon Command
```bash
subzero.bat -d example.com
```

---

## 🎯 Top 10 Real-World Recon Commands (Copy & Paste)

### 1. ⚡ Fast Passive Recon (Default 7 Fast Engines)
Sabhi fast passive engines (Subfinder, crt.sh, SSLMate, RapidDNS, HackerTarget, AlienVault OTX, URLScan) se subdomains khojein:
```bash
subzero.bat -d example.com
```

---

### 2. 🤫 Silent Pipeable Mode (Pure Subdomains for Scripts)
Bina kisi banner ya logs ke sirf clean subdomains print karta hai (Bug bounty automation ke liye best):
```bash
subzero.bat -d example.com -silent
```

---

### 3. 💥 Active DNS Wordlist Brute-Force
Passive recon ke saath 5,000 common prefixes par high-speed multi-threaded active brute-force chalayein:
```bash
subzero.bat -d example.com -a -w 5000 -t 500
```
*Wordlist options: `-w 100` (~2 sec), `-w 1000` (~5 sec), `-w 5000` (~15 sec), `-w 20000` (~45 sec), ya apni custom file ka path: `-w C:\SecLists\subdomains.txt`.*

---

### 4. 🛡️ Multi-Resolver Verification (Only Confirmed Alive Subdomains)
Cloudflare, Google, OpenDNS, Quad9 resolvers par verify karein aur sirf **Alive / Resolved** subdomains output karein:
```bash
subzero.bat -d example.com -r --only-resolved
```

---

### 5. 🎯 Specific DNS Resolver Test
Kisi ek specific DNS resolver (jaise Cloudflare ya Google) se resolve karke test karein:
```bash
subzero.bat -d example.com -r --resolver cloudflare
```
*(Options: `cloudflare`, `google`, `quad9`, `opendns`, `adguard`, `controld`, `level3`)*

---

### 6. 🔍 Security Audit: Dangling CNAME Takeover + HTTP Prober
Orphaned pointers aur HTTP status codes (200, 301, 403, 500), page titles, server banners inspect karein:
```bash
subzero.bat -d example.com --cname --probe
```

---

### 7. 🌐 IP Intelligence: Origin Server vs. Cloudflare/CDN
Pata lagayein ki kaunse subdomains Cloudflare/WAF ke peeche hain aur kaunse direct **Origin Server IP** par hain:
```bash
subzero.bat -d example.com --ip-intel
```

---

### 8. 📜 Historical Archive Miner (Wayback Machine + AlienVault)
Puraane URLs, sensitive leaked files (`.env`, `.git`, `.sql`, `.bak`), API endpoints aur parameter URLs (`?token=`, `?id=`) extract karein:
```bash
subzero.bat -d example.com --archive
```

---

### 9. 🗂️ Multi-Domain Batch Scan
Ek text file se 20+ targets ko ek sath scan karein:
```bash
subzero.bat -dL targets.txt -o live_subs.txt
```

---

### 10. 💾 Full Reconnaissance with All Export Formats (TXT + JSON + CSV)
Saare modules ek saath chala kar report files save karein:
```bash
subzero.bat -d example.com -a -r --cname --probe --ip-intel -o subdomains.txt -oJ report.json -oCSV report.csv
```

---

## 💻 Platform Launchers (Windows, Linux, macOS)

Aap jis bhi terminal ya OS par hain, SubZero har jagah easily chalta hai:

| Operating System / Environment | Command Syntax |
| :--- | :--- |
| **Windows (CMD / PowerShell)** | `subzero.bat [flags]` |
| **Windows (Direct Python)** | `python cli.py [flags]` |
| **Linux / macOS (Bash / Zsh)** | `./subzero [flags]` |
| **Linux / macOS (Direct Python)** | `python3 cli.py [flags]` |
| **Fast UV Runner** | `uv run python cli.py [flags]` |
| **Installed Package (pip install .)** | `subzero [flags]` |

---

## 🛠️ Complete CLI Flags & Options Table

### 1. Target Specification
| Flag | Alternative | Description | Example |
| :--- | :--- | :--- | :--- |
| `-d` | `--domain` | Ek target root domain scan karein | `-d target.com` |
| `-dL` | `-l`, `--list` | Targets ki file scan karein (ek line me ek domain) | `-dL targets.txt` |
| `-i` | `--interactive`, `--wizard` | Interactive step-by-step menu wizard open karein | `-i` |

---

### 2. Recon Engines & Source Control
| Flag | Alternative | Description | Example |
| :--- | :--- | :--- | :--- |
| `-s` | `--sources` | Sirf chune hue engines chalayein (comma-separated) | `-s crtsh,sslmate,otx` |
| `-x` | `--exclude`, `--skip` | Kisi bhi tool ko exclude/band karein (kabhi call nahi hoga) | `-x urlscan,hackertarget` |
| `--amass` | *(none)* | OWASP Amass deep scanner ko explicitly enable karein | `--amass` |
| `-all` | `--deep` | Sabhi high-exhaustion engines enable karein | `-all` |
| `-ls` | `--list-sources` | Available sources aur unka status check karein | `-ls` |

---

### 3. Individual Tool Off Flags (Direct Toggle)
Agar aap kisi ek tool ko band karna chahte hain:
| Toggle Flag | Description |
| :--- | :--- |
| `--no-subfinder` | Subfinder ko bilkul call mat karo |
| `--no-crtsh` | crt.sh query mat karo |
| `--no-sslmate` | SSLMate CertSpotter skip karo |
| `--no-rapiddns` | RapidDNS ko band rakho |
| `--no-hackertarget` | HackerTarget skip karo |
| `--no-otx` | AlienVault OTX call mat karo |
| `--no-urlscan` | URLScan.io skip karo |

---

### 4. Active Brute-Force & Permutations
| Flag | Alternative | Description | Example |
| :--- | :--- | :--- | :--- |
| `-a` | `--active` | Active DNS wordlist brute-forcing enable karein | `-a` |
| `-w` | `--wordlist` | Wordlist size (`100`, `1000`, `5000`, `20000`) ya file path | `-w 5000` |
| `-t` | `--threads` | Concurrent active worker threads (Default: `500`) | `-t 300` |
| `--permute` | *(none)* | Discovered subdomains par mutation algorithm chalayein | `--permute` |
| `--nested` | *(none)* | Multi-tenant SaaS & multi-level subzones discover karein | `--nested` |


---

### 5. DNS Resolution & Dead Domain Elimination
| Flag | Alternative | Description | Example |
| :--- | :--- | :--- | :--- |
| `-r` | `--resolve` | 11 Public Tier-1 Resolvers par verify karein | `-r` |
| `--resolver` | *(none)* | Kisi specific resolver se test karein (`cloudflare`, `google`) | `--resolver google` |
| `--only-resolved` | *(none)* | Output me sirf confirmed ALIVE subdomains dikhayein | `--only-resolved` |

---

### 6. Security Auditing Modules
| Flag | Description | Output Details |
| :--- | :--- | :--- |
| `--cname` | Dangling CNAME audit (Subdomain Takeover) | AWS S3, GitHub, Azure, Shopify orphaned pointers |
| `--probe` | HTTP/HTTPS web services prober | HTTP Status (`200`, `403`), HTML Title, Server Banner |
| `--ip-intel` | IP classification | Direct Origin Server vs Cloudflare / CloudFront / Akamai |
| `--archive` | Historical URL Mining | `.env`, `.git`, `.sql`, API endpoints, parameters (`?token=`) |

---

### 7. Output, Piping & Display
| Flag | Alternative | Description | Example |
| :--- | :--- | :--- | :--- |
| `-silent` | `-q`, `--quiet` | Clean stdout (Piping ke liye sirf subdomains) | `-silent` |
| `-o` | `--output` | Plaintext list export karein | `-o subs.txt` |
| `-oJ` | `--json` | Full structured JSON report save karein | `-oJ report.json` |
| `-oCSV` | `--csv` | Audit spreadsheet CSV save karein | `-oCSV report.csv` |
| `-v` | `--verbose` | Live debug telemetry aur DNS logs dikhayein | `-v` |
| `--no-color` | *(none)* | Terminal ANSI colors disable karein | `--no-color` |

---

## 🚫 How to Exclude / Turn Off Specific Tools

SubZero me aap kisi bhi tool ko easily exclude kar sakte hain taaki scan fast ho aur rate limits na lagein:

### Tareeqa 1: `-x` Flag Use Karke
```bash
# URLScan aur HackerTarget ko skip karein:
subzero.bat -d target.com -x urlscan,hackertarget

# Subfinder ko skip karein:
subzero.bat -d target.com -x subfinder
```

### Tareeqa 2: `--no-<tool>` Flag Use Karke
```bash
# Sirf crt.sh aur SSLMate ko band karein:
subzero.bat -d target.com --no-crtsh --no-sslmate
```

### Tareeqa 3: Interactive Wizard Me
Jab aap `subzero.bat -i` chalate hain, toh wizard aapse poochega:
```text
[?] Kisi tool ko remove / band karna hai? (e.g. 'urlscan, hackertarget' ya '1,7'):
```
Aap tool ka naam ya uska number daal kar seedha [ENTER] daba sakte hain.

---

## 🔗 Chaining & Piping with Other Tools (`httpx`, `nuclei`, `naabu`)

SubZero ka `-silent` mode UNIX standard pipeline ke sath 100% compatible hai:

### 1. Live Web Servers & Status Titles Check Karein (`httpx`)
```bash
subzero.bat -d uber.com -silent | httpx -title -status-code -tech-detect
```

### 2. Direct Vulnerability Scan (`nuclei`)
```bash
subzero.bat -d hackerone.com -silent | nuclei -t http/cves/ -severity critical,high
```

### 3. Open Ports Port-Scanning (`naabu` ya `nmap`)
```bash
subzero.bat -d example.com -silent | naabu -p 80,443,8080,8443
```

### 4. Alive Host Filter Karke Save Karna
```bash
subzero.bat -d target.com -r --only-resolved -silent > live_targets.txt
```

---

## 🩺 Diagnostic & Network Health Commands

Agar kabhi internet slow ho ya API drop ho rahi ho, toh SubZero ka pre-flight health diagnostic chalayein:

```bash
subzero.bat --check-network
```

Output:
```text
[*] Running network connectivity and DNS diagnostic pre-flight...
[+] Internet connectivity: ACTIVE (verified via https://1.1.1.1)
```

Available tools ka live status dekhne ke liye:
```bash
subzero.bat -ls
```

---

### 💡 Pro Tips:
1. **Low-Spec PCs par fast scan ke liye**:
   ```bash
   subzero.bat -d target.com -s crtsh,sslmate,rapiddns -r --only-resolved
   ```
2. **Bug Bounty Hunt ke liye maximum coverage**:
   ```bash
   subzero.bat -d target.com -a -w 5000 -r --cname --probe --archive -oCSV audit.csv
   ```

---
*Created with ❤️ by **Gulam Khan** for Cybersecurity Researchers & Ethical Hackers.*
