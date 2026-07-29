#!/bin/bash
# install.sh — drop this on the nginx-manager LXC and run as root
set -e

echo "=== nginx-manager installer ==="

# Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs git

# Clone app
mkdir -p /opt/nginx-manager
cd /opt/nginx-manager

# If re-running, just pull
if [ -d ".git" ]; then
  git pull
else
  git clone https://github.com/GITHUB_USER/nginx-manager.git .
fi

npm install --production

# Setup .env if missing
if [ ! -f ".env" ]; then
  cp .env.example .env
  # Set a random session secret
  SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=')
  sed -i "s/change-me-to-something-random/$SECRET/" .env
fi

# Systemd service
cp nginx-manager.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nginx-manager

echo ""
echo "=== Done! ==="
echo "nginx-manager running on port 3000"
echo "Default password: [REDACTED] (set ADMIN_PASSWORD in /opt/nginx-manager/.env)"
systemctl status nginx-manager --no-pager
