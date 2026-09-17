#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "========================================================"
echo "    SubZero v2.2 - OSINT & DNS Reconnaissance Platform"
echo "    Developed by: Gulam Khan"
echo "========================================================"
echo ""

mkdir -p bin wordlists

# Priority 1: Check for uv
if command -v uv >/dev/null 2>&1; then
    echo "[*] Detected uv runtime engine."
    echo "[*] Checking and downloading missing tools / wordlists..."
    uv run python install_tools.py
    echo "[*] Starting SubZero on http://127.0.0.1:5000..."
    exec uv run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
fi

# Priority 2: Check for python3 or python
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

if [ -n "$PYTHON_BIN" ]; then
    echo "[*] Using system Python: $($PYTHON_BIN --version)"
    if [ ! -d ".venv" ]; then
        echo "[*] Creating isolated virtual environment (.venv)..."
        $PYTHON_BIN -m venv .venv || true
    fi
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    fi
    echo "[*] Verifying dependencies..."
    python -m pip install -q -r requirements.txt || true
    echo "[*] Checking and downloading discovery tools / wordlists..."
    python install_tools.py
    echo "[*] Starting SubZero on http://127.0.0.1:5000..."
    exec python app.py
fi

# Priority 3: No Python found - auto install uv
echo "[!] Python 3 not found in PATH. Downloading standalone uv runner..."
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

if command -v uv >/dev/null 2>&1; then
    echo "[+] uv installed successfully!"
    uv run python install_tools.py
    exec uv run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
fi

echo "[ERROR] Could not automatically configure Python environment."
echo "Please install Python 3.10+ using your package manager (e.g. sudo apt install python3 python3-pip)"
exit 1
