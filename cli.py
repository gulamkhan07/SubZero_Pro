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
import sys

try:
    from enumerator.cli import main
except ImportError as err:
    sys.stderr.write(f"[!] SubZero Dependency Error: {err}\n")
    sys.stderr.write("[*] Please run: pip install -r requirements.txt\n")
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main() or 0)
