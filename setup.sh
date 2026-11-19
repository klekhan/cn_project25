#!/bin/bash
# One-time setup for Ubuntu 22.04 / 24.04.   Run:  bash setup.sh
# Installs Mininet, Open vSwitch, attack tools and the OS-Ken controller (in a venv).
set -e

echo "[1/4] Installing system packages (needs sudo password)..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    mininet openvswitch-switch nmap hping3 tcpdump wireshark xterm \
    python3-venv python3-pip python3-matplotlib unzip net-tools

echo "[2/4] Starting Open vSwitch..."
if pidof systemd >/dev/null 2>&1; then
    sudo systemctl enable --now openvswitch-switch
else
    sudo service openvswitch-switch start      # WSL without systemd
fi

echo "[3/4] Creating controller virtualenv at ~/ids-venv (OS-Ken 3.1.1)..."
# NOTE: os-ken 4.x removed the 'osken-manager' command, so we pin 3.1.1.
python3 -m venv ~/ids-venv
~/ids-venv/bin/pip install --upgrade pip
~/ids-venv/bin/pip install "os-ken==3.1.1"

echo "[4/4] Checking..."
~/ids-venv/bin/osken-manager --version || true
which mn nmap hping3 tcpdump
sudo ovs-vsctl show >/dev/null && echo "Open vSwitch OK"
echo
echo "Setup finished. Next: follow README.md section 'Run'."
