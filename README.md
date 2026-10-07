# Nginx Manager

A self-hosted web GUI for managing nginx servers through **[NGINX Agent](https://github.com/nginx/agent) v3** — edit configs, build sites visually, manage certificates, and push changes that are validated and rolled back automatically.

Built for ConnopNetworking homelab infrastructure.

## Features

- 🖥️ **Multi-server** — manage multiple nginx servers from one interface, grouped in the sidebar
- ➕ **Manual enrolment** — servers are added by hand in the UI; each gets its own agent token. Agents with unknown tokens are rejected.
- 🔐 **No passwords in the repo or on disk** — no SSH, no host credentials. Agent tokens are stored only as SHA-256 hashes; the admin password as a bcrypt hash.
- 📄 **Config editor** — edit every file nginx references, as reported by the agent
- 🏗️ **Visual Site Builder** — reverse proxy / static / redirect sites, with SSL + HSTS
- 🔐 **Certificate manager** — see certs (and expiry) the agent reports, upload new cert/key pairs
- 📤 **Apply** — staged changes are pushed in one go; the agent writes them, runs `nginx -t`, reloads, and **rolls back automatically** if anything fails
- 🔄 **Live sync** — hand edits on the server show up automatically (agent file watcher)
- 📊 **Status** — agent connection, nginx version and instance health
- 🖥️ **Live log** — Socket.IO real-time operation output (session-authenticated)

## Architecture

```
Browser ── HTTP + Socket.IO ──▶ nginx-manager (Node.js)
                                  │  gRPC/TLS :8443  (NGINX Agent management-plane protocol, mpi.v1)
                                  ▲
               ┌──────────────────┴──────────────────┐
         nginx-agent (dials in)                nginx-agent (dials in)
         nginx-lb-01                           nginx-lb-02
```

The agents connect **out** to the manager — the manager never logs in to the nginx servers.
Each agent:

1. authenticates with its per-server token (`authorization` gRPC metadata, TLS only),
2. reports its nginx instance and uploads the config files nginx references (inside its `allowed_directories`),
3. on **Apply**, downloads changed files, runs `nginx -t`, reloads, and reports success — or rolls back and reports the error.

## Installation

### Manager

Requirements: Debian/Ubuntu, Node.js 18+, `openssl`.

```bash
curl -fsSL https://raw.githubusercontent.com/mitchell-connop/nginx-manager/main/install.sh -o install.sh
sudo bash install.sh
```

The installer generates `SESSION_SECRET`, prompts for the admin password and stores it as a bcrypt hash in `/opt/nginx-manager/.env` (mode 600, git-ignored), and installs the systemd service.

On first start the manager creates a private CA and a TLS certificate for the agent gRPC listener in `data/tls/` (covering the host's name and IPv4 addresses — see `GRPC_TLS_SANS`).

Manual install:

```bash
git clone https://github.com/mitchell-connop/nginx-manager.git && cd nginx-manager
npm ci --omit=dev
cp .env.example .env && chmod 600 .env   # set SESSION_SECRET and ADMIN_PASSWORD
node server.js
```

### Adding an nginx server

1. In the UI click **＋ Add Server**, give it a name (and optional group).
2. A one-time **agent token** and a setup script are shown. Run the script as root on the nginx server — it:
   - installs `nginx-agent` from the nginx.org repo,
   - writes the token to `/etc/nginx-agent/manager.token` (mode 600) and the manager's CA to `/etc/nginx-agent/manager-ca.pem`,
   - writes `/etc/nginx-agent/nginx-agent.conf` pointing at the manager, and restarts the agent.
3. The server turns green in the sidebar and its config files appear within a few seconds.

Lost the token? **🔑 Agent Setup → New Token** issues a new one (the old one stops working immediately).

Make sure the nginx servers can reach the manager on `GRPC_PORT` (default 8443/tcp).

## Configuration

Edit `.env` (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Web UI port |
| `SESSION_SECRET` | **(required)** | Session cookie secret — long random string |
| `ADMIN_PASSWORD` | **(required)** | Login password — a bcrypt hash (recommended) or plain text |
| `GRPC_PORT` | `8443` | Port NGINX Agent connects to (gRPC over TLS) |
| `AGENT_CONNECT_HOST` | browser hostname | Host/IP agents use to reach the manager (used in setup instructions) |
| `GRPC_TLS_SANS` | hostname + IPv4s | Names/IPs in the generated gRPC certificate, e.g. `DNS:nginx-manager.lan,IP:172.16.40.10` |
| `GRPC_TLS_CERT` / `GRPC_TLS_KEY` / `GRPC_TLS_CA` | — | Use your own certificate instead |
| `COOKIE_SECURE` / `TRUST_PROXY` | — | Set when serving the UI over HTTPS behind a proxy |

## Notes

- **Allowed directories** — the agent can only read/write files under its `allowed_directories`. The generated config allows `/etc/nginx`, `/etc/letsencrypt` and `/etc/ssl/nginx` (plus nginx's runtime/log dirs). Upload certificates to a path under one of those, e.g. `/etc/nginx/ssl/`.
- **Upgrading from v1 (SSH)** — on first start, stored SSH passwords are removed from `data/agents.json`. Open each server, click **🔑 Agent Setup → New Token**, and run the setup on that server.
- **Data** lives in `./data/` (git-ignored, mode 700): server list, synced file contents, certificate registry, site definitions, and the gRPC TLS material. Synced files can include TLS private keys referenced by nginx — protect backups accordingly.
- `proto/` contains the NGINX Agent `mpi.v1` protobuf definitions (Apache-2.0, from [nginx/agent](https://github.com/nginx/agent)) with `buf.validate` annotations removed.

## Development

```bash
npm install
npm test        # management-plane protocol test (fake agent)
npm run dev
```
