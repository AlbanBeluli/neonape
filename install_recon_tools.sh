#!/usr/bin/env bash
set -euo pipefail

detect_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt-get"
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    echo "pacman"
    return
  fi
  if command -v brew >/dev/null 2>&1; then
    echo "brew"
    return
  fi
  echo ""
}

manager="${1:-$(detect_manager)}"

if [[ -z "$manager" ]]; then
  echo "No supported package manager detected. Install tools manually." >&2
  exit 1
fi

echo "Neon Ape recon tooling bootstrap"
echo "Package manager: $manager"
echo

case "$manager" in
  apt-get)
    echo "Installing base packages for Debian/Kali/Parrot..."
    sudo apt-get update
    sudo apt-get install -y nmap whois dnsutils gobuster amass
    ;;
  pacman)
    echo "Installing base packages for Arch/BlackArch..."
    sudo pacman -Sy --needed nmap whois dnsutils gobuster amass
    ;;
  brew)
    echo "Installing base packages for Homebrew..."
    brew install nmap whois gobuster amass
    ;;
  *)
    echo "Unsupported package manager: $manager" >&2
    exit 1
    ;;
esac

echo
echo "ProjectDiscovery tools are typically installed separately."
echo "Suggested follow-up:"
echo "  brew install projectdiscovery/tap/httpx projectdiscovery/tap/subfinder projectdiscovery/tap/naabu projectdiscovery/tap/dnsx projectdiscovery/tap/nuclei projectdiscovery/tap/katana"
echo "or use the official releases for your distribution."
