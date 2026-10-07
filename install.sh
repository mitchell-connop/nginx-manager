#!/bin/bash
# install.sh — run as root on the nginx-manager host (Debian/Ubuntu)
set -euo pipefail

echo "=== nginx-manager installer ==="

APP_DIR=/opt/nginx-manager

# Node.js 22 LTS
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 18 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi
apt-get install -y git openssl
# certbot + DNS plugins for managed certificates (issued here, deployed through the agents)
apt-get install -y certbot python3-certbot-dns-cloudflare python3-certbot-dns-route53

# Clone app (or update an existing checkout)
mkdir -p "$APP_DIR"
cd "$APP_DIR"
if [ -d ".git" ]; then
  git pull --ff-only
else
  git clone https://github.com/mitchell-connop/nginx-manager.git .
fi

npm ci --omit=dev

# .env — secrets are generated or prompted for here and never stored in the repo
if [ ! -f ".env" ]; then
  install -m 600 .env.example .env

  SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=')
  sed -i "s|^SESSION_SECRET=.*|SESSION_SECRET=${SECRET}|" .env

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
  # Store only a bcrypt hash (password passed on stdin, not the command line)
  HASH=$(printf '%s' "$PASS1" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(require("bcryptjs").hashSync(s,12)))')
  unset PASS1 PASS2
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${HASH}|" .env
  echo "Password set (stored as a bcrypt hash)."
fi
chmod 600 .env
mkdir -p data && chmod 700 data

# Systemd service
cp nginx-manager.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable nginx-manager
systemctl restart nginx-manager

PORT=$(grep -E '^PORT=' .env | cut -d= -f2); PORT=${PORT:-3000}
GRPC_PORT=$(grep -E '^GRPC_PORT=' .env | cut -d= -f2); GRPC_PORT=${GRPC_PORT:-8443}
echo ""
echo "=== Done! ==="
echo "Web UI:            http://$(hostname -I | awk '{print $1}'):${PORT}"
echo "Agent gRPC (TLS):  port ${GRPC_PORT} — nginx servers' NGINX Agent connects here"
echo "Add each nginx server in the UI (＋ Add Server) and run the setup commands it shows on that server."
echo "To change the admin password later: re-run the hash command in .env.example, edit ADMIN_PASSWORD in ${APP_DIR}/.env, restart."
systemctl status nginx-manager --no-pager || true
