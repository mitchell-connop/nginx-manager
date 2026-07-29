# Nginx Manager

A self-hosted web GUI for managing nginx servers — push configs, validate, reload, and sync — all from a clean browser interface.

Built for ConnopNetworking homelab infrastructure.

## Features

- 🖥️ **Multi-server** — manage multiple nginx servers from one interface
- 📄 **Config editor** — edit `.conf` files with syntax-friendly textarea
- 📤 **Push** — push config files to remote servers via SSH
- ✅ **Validate** — run `nginx -t` on remote servers before pushing
- 🔄 **Sync** — pull live configs from remote servers into local store
- ↩ **Reload** — trigger `nginx -s reload` on remote servers
- 📊 **Status** — live nginx status via `systemctl status nginx`
- 🖥️ **Live log** — Socket.IO real-time operation output
- 🔐 **Auth** — single password authentication

## Installation

### Requirements

- Node.js 18+
- SSH access to your nginx servers (password or key auth)
- The SSH user must have sudo access to nginx commands

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/nginx-manager.git
cd nginx-manager
npm install
cp .env.example .env
# Edit .env — set PORT and ADMIN_PASSWORD
node server.js
```

Open http://localhost:3000

### Running as a systemd service

```bash
sudo cp nginx-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nginx-manager
```

## Configuration

Edit `.env`:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `SESSION_SECRET` | (required) | Session cookie secret |
| `ADMIN_PASSWORD` | `admin` | Login password |

## Nginx Agent SSH Setup

The nginx user on each managed server must be able to run nginx commands via sudo without a password prompt:

```bash
# On each managed nginx server:
echo "mconnop ALL=(ALL) NOPASSWD: /usr/sbin/nginx, /bin/systemctl * nginx, /usr/bin/tee /etc/nginx/*" \
  | sudo tee /etc/sudoers.d/nginx-manager
```

## Architecture

```
Browser ──── WebSocket (Socket.IO) ──── nginx-manager (Node.js)
                                              │
                                         SSH (node-ssh)
                                         /            \
                              nginx-lb-01          nginx-lb-02
                              172.16.40.51         172.16.40.52
```

Data is stored in `./data/`:
- `agents.json` — server definitions
- `configs/<agent-id>/` — config files per server
