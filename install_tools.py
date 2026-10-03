#!/usr/bin/env python3
"""
Cross-Platform Auto-Installer script for Subfinder, Amass & SecLists Wordlists.
Supports Windows, Linux, and macOS (x86_64 and arm64).
"""
import io
import os
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(PROJECT_ROOT, 'bin')
GO_BIN = os.path.join(os.path.expanduser('~'), 'go', 'bin')

SUBFINDER_VERSION = '2.16.0'
AMASS_VERSION = '5.1.1'

def _detect_platform():
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = 'arm64' if ('arm' in machine or 'aarch64' in machine) else 'amd64'

    if system == 'windows':
        return 'windows', arch, '.exe'
    elif system == 'darwin':
        return 'macOS', arch, ''
    else:
        return 'linux', arch, ''

def _extract_binary_from_archive(archive_bytes, target_bin_name, destination_path):
    """Extracts a specific binary file from in-memory zip or tar.gz archive."""
    # Try zip first
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
            for name in z.namelist():
                base = os.path.basename(name).lower()
                if base == target_bin_name.lower():
                    with z.open(name) as src, open(destination_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                    if not target_bin_name.endswith('.exe'):
                        os.chmod(destination_path, 0o755)
                    return True
    except (zipfile.BadZipFile, Exception):
        pass

    # Try tar.gz
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:*') as tar:
            for member in tar.getmembers():
                base = os.path.basename(member.name).lower()
                if base == target_bin_name.lower():
                    f = tar.extractfile(member)
                    if f:
                        with open(destination_path, 'wb') as dst:
                            shutil.copyfileobj(f, dst)
                        if not target_bin_name.endswith('.exe'):
                            os.chmod(destination_path, 0o755)
                        return True
    except Exception:
        pass

    return False

def install(verbose=True):
    """Installs missing Subfinder, Amass, and SecLists wordlists automatically."""
    os.makedirs(BIN_DIR, exist_ok=True)
    os.makedirs(GO_BIN, exist_ok=True)
    headers = {'User-Agent': 'SubZero-AutoInstaller/2.2'}

    os_name, arch, ext = _detect_platform()
    subfinder_bin = f'subfinder{ext}'
    amass_bin = f'amass{ext}'

    # 1. Subfinder Installation
    subfinder_path = os.path.join(BIN_DIR, subfinder_bin)
    if os.path.isfile(subfinder_path):
        if verbose:
            print(f"[OK] Subfinder is already installed at: {subfinder_path}")
    else:
        if verbose:
            print(f"[*] Downloading Subfinder v{SUBFINDER_VERSION} for {os_name}_{arch}...")
        subfinder_url = f'https://github.com/projectdiscovery/subfinder/releases/download/v{SUBFINDER_VERSION}/subfinder_{SUBFINDER_VERSION}_{os_name}_{arch}.zip'
        try:
            req = urllib.request.Request(subfinder_url, headers=headers)
            with urllib.request.urlopen(req, timeout=35) as resp:
                data = resp.read()
            if _extract_binary_from_archive(data, subfinder_bin, subfinder_path):
                if verbose:
                    print(f"[+] Successfully installed Subfinder: {subfinder_path}")
                # Optional mirror to ~/go/bin
                try:
                    go_dst = os.path.join(GO_BIN, subfinder_bin)
                    shutil.copyfile(subfinder_path, go_dst)
                    if ext == '':
                        os.chmod(go_dst, 0o755)
                except Exception:
                    pass
        except Exception as e:
            if verbose:
                print(f"[!] Notice: Precompiled Subfinder download skipped ({e}). Passive discovery will use fallback APIs.")

    # 2. Amass Installation
    amass_path = os.path.join(BIN_DIR, amass_bin)
    if os.path.isfile(amass_path):
        if verbose:
            print(f"[OK] Amass is already installed at: {amass_path}")
    else:
        if verbose:
            print(f"[*] Downloading OWASP Amass for {os_name}_{arch}...")
        
        # Try latest v5 tar.gz, then v4 zip
        amass_urls = [
            f'https://github.com/owasp-amass/amass/releases/download/v{AMASS_VERSION}/amass_{os_name}_{arch}.tar.gz',
            f'https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_{"Windows" if os_name=="windows" else ("macOS" if os_name=="macOS" else "Linux")}_{arch}.zip'
        ]
        installed = False
        for url in amass_urls:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=40) as resp:
                    data = resp.read()
                if _extract_binary_from_archive(data, amass_bin, amass_path):
                    if verbose:
                        print(f"[+] Successfully installed Amass: {amass_path}")
                    installed = True
                    break
            except Exception:
                continue

        if not installed and verbose:
            print(f"[i] Amass precompiled download skipped. Active & passive engines continue normally.")

    # 3. Active DNS Wordlists (SecLists)
    wordlist_dir = os.path.join(PROJECT_ROOT, 'wordlists')
    os.makedirs(wordlist_dir, exist_ok=True)
    wl_5k = os.path.join(wordlist_dir, 'subdomains_5000.txt')
    wl_10k = os.path.join(wordlist_dir, 'subdomains_10000.txt')
    if os.path.isfile(wl_5k) and os.path.isfile(wl_10k):
        if verbose:
            print(f"[OK] Active DNS Wordlists already present in: {wordlist_dir}")
    else:
        if verbose:
            print("[*] Downloading SecLists Active DNS wordlists (5,000 & 10,000 subdomains)...")
        try:
            url_20k = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt'
            req = urllib.request.Request(url_20k, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode('utf-8', errors='ignore')
            lines = [w.strip() for w in text.splitlines() if w.strip()]
            with open(wl_5k, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines[:5000]))
            with open(wl_10k, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines[:10000]))
            with open(os.path.join(wordlist_dir, 'subdomains_20000.txt'), 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            if verbose:
                print(f"[+] Saved SecLists wordlists (5k, 10k, 20k) to {wordlist_dir}")
        except Exception as e:
            if verbose:
                print(f"[!] Notice: Could not download external wordlist ({e}). Built-in permutations will be used.")

    if verbose:
        print("[SUCCESS] Auto-installer verification complete!\n")

if __name__ == '__main__':
    install(verbose=True)
