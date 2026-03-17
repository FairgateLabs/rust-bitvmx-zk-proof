#!/bin/bash
set -e

## Install dependencies
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release build-essential pkg-config libssl-dev

## Install Docker
if ! command -v docker >/dev/null 2>&1; then
    sudo mkdir -p /etc/apt/keyrings

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    sudo usermod -aG docker $USER

    if ! systemctl is-active --quiet docker; then
        sudo systemctl enable docker
        sudo systemctl start docker
    fi
fi

## Install Rust
if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

echo ""
echo "========================================"
echo "Setup COMPLETE"
echo ""
echo "Before running install_risc_zero.sh run:"
echo ""
echo "1) Reload your shell (recommended):"
echo "   exec \$SHELL"
echo ""
echo "OR reconnect via SSH."
echo ""
echo "2) Load Rust environment:"
echo "   source \$HOME/.cargo/env"
echo ""
echo "3) Verify Docker works without sudo:"
echo "   docker --version"
echo ""
echo "Then run:"
echo "   bash install_risc_zero.sh"
echo "========================================"