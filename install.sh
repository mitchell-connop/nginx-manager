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
  git clone https://github.com/mitchell-connop/nginx-manager.git .
fi

npm install --production

# Setup .env if missing
if [ ! -f ".env" ]; then
  cp .env.example .env

  # Set a random session secret
  SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=')
  sed -i "s/change-me-to-something-random/$SECRET/" .env

  # Prompt user to set an admin password
  echo ""
  echo "========================================="
  echo "  Set your nginx-manager admin password"
  echo "========================================="
  while true; do
    read -rsp "Enter admin password: " PASS1; echo
    read -rsp "Confirm admin password: " PASS2; echo
    if [ -z "$PASS1" ]; then
      echo "Password cannot be empty. Please try again."
    elif [ "$PASS1" != "$PASS2" ]; then
      echo "Passwords do not match. Please try again."
    else
      break
    fi
  done
  echo "ADMIN_PASSWORD=${PASS1}" >> .env
  echo "Password set."
fi

# Systemd service
cp nginx-manager.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nginx-manager

echo ""
echo "=== Done! ==="
echo "nginx-manager running on port 3000"
echo "Login with the password you just set."
echo "To change it later: edit ADMIN_PASSWORD in /opt/nginx-manager/.env and restart the service."
systemctl status nginx-manager --no-pager
