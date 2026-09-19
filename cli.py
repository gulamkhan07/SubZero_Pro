#!/usr/bin/env python3
"""
SubZero - Fast OSINT & Active DNS Reconnaissance Engine (CLI Edition)
Developed by: Gulam Khan
Version: 2.2.0

Usage:
  python cli.py -d example.com -silent
  python cli.py -d example.com -r --ip-intel
  python cli.py -dL domains.txt -a -w 5000 -o live_subs.txt -oJ results.json
"""
import os
import sys
import subprocess
import importlib.util

# Auto-bootstrap missing dependencies if run directly outside venv
_REQUIRED_PACKAGES = [
    ('requests', 'requests>=2.31,<3'),
    ('dns.resolver', 'dnspython>=2.6,<3')
]
_missing = [pkg for mod, pkg in _REQUIRED_PACKAGES if importlib.util.find_spec(mod) is None]
if _missing:
    sys.stderr.write(f"[*] SubZero CLI: Installing missing dependencies: {', '.join(_missing)}...\n")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", *_missing])
        sys.stderr.write("[+] Dependencies successfully installed!\n\n")
    except Exception as _e:
        sys.stderr.write(f"[!] Auto-installation failed: {_e}. Run: pip install -r requirements.txt\n\n")

from enumerator.cli import main

if __name__ == "__main__":
    main()
