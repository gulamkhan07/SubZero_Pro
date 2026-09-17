#!/usr/bin/env bash
set -euo pipefail

log(){ printf '[setup] %s\n' "$1"; }

command -v apt-get >/dev/null 2>&1 || true
command -v sudo >/dev/null 2>&1 || { echo 'sudo is required for first-time Go installation.' >&2; exit 1; }

if ! command -v go >/dev/null 2>&1; then
  log 'Go not found; installing Go from the system package manager...'
  sudo apt-get update
  sudo apt-get install -y golang-go
fi

export PATH="$HOME/go/bin:$PATH"
mkdir -p "$HOME/go/bin"

install_go_tool(){
  local name="$1" package="$2"
  if command -v "$name" >/dev/null 2>&1; then
    log "$name already installed."
    return
  fi
  log "Installing $name..."
  go install "$package"
  command -v "$name" >/dev/null 2>&1 || { echo "$name installation finished but binary is not on PATH." >&2; exit 1; }
}

# Current upstream installation paths.
install_go_tool subfinder 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
install_go_tool amass 'github.com/owasp-amass/amass/v4/...@master'

log 'Tool setup complete.'
