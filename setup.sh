#!/bin/bash
# HTB Auto Pwn - Quick Setup Script for Kali Linux

echo "╔═══════════════════════════════════════════════╗"
echo "║   HTB Auto Pwn - Dependency Installer        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] This script should be run as root or with sudo${NC}"
    echo "Usage: sudo ./setup.sh"
    exit 1
fi

echo "[*] Updating package lists..."
apt-get update -qq

# List of required packages
PACKAGES=(
    "nmap"
    "nikto"
    "gobuster"
    "smbclient"
    "curl"
    "sshpass"
    "lftp"
    "python3"
    "python3-pip"
)

echo ""
echo "[*] Checking and installing required tools..."
echo ""

MISSING=0
INSTALLED=0

for package in "${PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $package "; then
        echo -e "${GREEN}[✓]${NC} $package is already installed"
    else
        echo -e "${YELLOW}[+]${NC} Installing $package..."
        apt-get install -y "$package" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓]${NC} $package installed successfully"
            ((INSTALLED++))
        else
            echo -e "${RED}[✗]${NC} Failed to install $package"
            ((MISSING++))
        fi
    fi
done

echo ""
echo "[*] Checking for wordlists..."

# Check for common wordlists
WORDLIST_DIR="/usr/share/wordlists"
if [ ! -d "$WORDLIST_DIR/dirb" ]; then
    echo -e "${YELLOW}[+]${NC} Installing dirb wordlists..."
    apt-get install -y dirb > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓]${NC} Dirb wordlists installed"
    else
        echo -e "${RED}[✗]${NC} Failed to install dirb wordlists"
    fi
else
    echo -e "${GREEN}[✓]${NC} Dirb wordlists found"
fi

if [ ! -d "$WORDLIST_DIR/dirbuster" ]; then
    echo -e "${YELLOW}[+]${NC} Installing dirbuster wordlists..."
    apt-get install -y dirbuster > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓]${NC} Dirbuster wordlists installed"
    else
        echo -e "${YELLOW}[!]${NC} Dirbuster wordlists not available (optional)"
    fi
else
    echo -e "${GREEN}[✓]${NC} Dirbuster wordlists found"
fi

echo ""
echo "[*] Setting up Python environment..."

# Make the main script executable
if [ -f "htb_auto_pwn.py" ]; then
    chmod +x htb_auto_pwn.py
    echo -e "${GREEN}[✓]${NC} Made htb_auto_pwn.py executable"
else
    echo -e "${YELLOW}[!]${NC} htb_auto_pwn.py not found in current directory"
fi

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║            Installation Summary               ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "Newly installed packages: $INSTALLED"
echo "Failed installations: $MISSING"
echo ""

if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}[✓] All dependencies installed successfully!${NC}"
    echo ""
    echo "You can now run the tool with:"
    echo "  python3 htb_auto_pwn.py -t <target_ip>"
    echo ""
    echo "Example:"
    echo "  python3 htb_auto_pwn.py -t 10.10.10.100"
    echo "  python3 htb_auto_pwn.py -t 10.10.10.100 -o results.json -v"
    echo ""
    echo "Note: The tool can also automatically detect and install"
    echo "      missing tools when you run it for the first time."
else
    echo -e "${RED}[!] Some dependencies failed to install${NC}"
    echo "Please install them manually or let the tool install them"
    echo "automatically when you run it:"
    echo "  python3 htb_auto_pwn.py -t <target_ip>"
fi

echo ""
echo "[*] Setup complete!"
