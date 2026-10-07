# Nginx Manager

A self-hosted web GUI for managing nginx servers through **[NGINX Agent](https://github.com/nginx/agent) v3** — edit configs, build sites visually, manage certificates, and push changes that are validated and rolled back automatically.

Built for ConnopNetworking homelab infrastructure.

## Features

- 🖥️ **Multi-server** — manage multiple nginx servers from one interface, grouped in the sidebar
- ➕ **Manual enrolment** — servers are added by hand in the UI; each gets its own agent token. Agents with unknown tokens are rejected.
- 🔐 **No passwords in the repo or on disk** — no SSH, no host credentials. Agent tokens are stored only as SHA-256 hashes; the admin password as a bcrypt hash.
- 📄 **Config editor** — edit every file nginx references, as reported by the agent
- 🔀 **Reverse proxies** — add and edit sites from a popup; they live in `conf.d/reverse-proxies.conf` (created if missing), edited in place with a live diff preview
- 🏗️ **Visual Site Builder** — every server block on the server is listed live; static sites and redirects get their own generated file
- 🧭 **Forward proxies** — HTTPS (CONNECT) forward proxies with client allowlists, logins and destination allowlists, in `conf.d/forward-proxies.conf` — **requires nginx 1.31.0+** on that server
- 🔄 **Managed certificates** — certbot runs on the manager (Let's Encrypt by default; ZeroSSL, Google Trust Services, DigiCert, Sectigo or any ACME CA with EAB; or exportable AWS ACM certificates), deploys to every server in the group through the agents, and renews automatically
- 🔐 **Certificates** — every cert nginx references, live, with SANs, issuer, expiry and which sites use it; upload new cert/key pairs
- 📤 **Apply** — staged changes are pushed in one go; the agent writes them, runs `nginx -t`, reloads, and **rolls back automatically** if anything fails
- 🔄 **Live, no scanning** — the Builder, Certificates and Raw Configs tabs are derived from what the agent reports, so hand edits on the server show up within seconds (agent file watcher)
- 📊 **Status** — agent connection, nginx version and instance health
- 🎨 **Branding** — your own logo (also the browser tab icon), app name and login text; stored in `data/` so updates keep it
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
- **Reverse proxies are edited in place** — a site is the `# ===` header comment plus its `upstream` (if any), HTTP→HTTPS redirect and HTTPS `server` blocks, grouped by `server_name`. The popup only rewrites the directives its fields own (`server_name`, upstream `server` lines, `proxy_pass`, cert paths, timeouts, body size, HSTS, WebSocket headers); comments and everything else — keepalive, `proxy_next_upstream`, … — stay byte-for-byte. New proxies are appended to `conf.d/reverse-proxies.conf` in the same layout. Sites whose `proxy_pass` uses variables, and non-proxy server blocks, are read-only cards that open the file.
- **Applying** writes the files, runs `nginx -t` and does a graceful `nginx -s reload` (no dropped connections). The agent then watches the error log for ~10 s before reporting success, and rolls back if anything fails. **Save & Apply** in the popup does both in one click.
- **Static sites and redirects** made in the builder own their whole generated `.conf` file and are edited in the form.
- **Forward proxies** use `ngx_http_tunnel_module`, added in **nginx 1.31.0** (built by default unless nginx was configured `--without-http_tunnel_module`). The section is enabled per server only when its agent reports nginx ≥ 1.31.0 — nginx.org's *stable* packages (1.30.x) don't have it yet; the *mainline* repo does.
  - Clients send `CONNECT host:443` and nginx tunnels the TLS connection. Plain `http://` through the proxy isn't supported by the module (it answers 405/403).
  - Each proxy is a header comment, two `map`s (allowed destination ports and hosts — `*.example.com` wildcards; IP-literal destinations blocked by default so a name allowlist can't be bypassed) and a `server` with `allow`/`deny` for client networks, optional proxy login, and `tunnel_pass`.
  - Proxy login uses `auth_basic`, which answers CONNECT requests with `407 Proxy-Authenticate`. Users are kept as **bcrypt hashes** in `/etc/nginx/forward-proxy/<name>.htpasswd` (mode 640, readable by the nginx workers through the `nginx-agent` group); plaintext passwords are never stored. Leaving a password blank on edit keeps it.
  - An open proxy is refused: you must restrict client networks, require a login, or both. Destinations are matched by name — with "any host", allowed clients can also reach internal services by DNS name.
  - Editing regenerates the proxy's blocks but keeps any directives you added to its `server` block by hand, and a customised `access_log` path.
- **Managed certificates** are issued once, on the manager — so an HA pair always serves the same certificate — and pushed to each target server as two files (default `/etc/nginx/ssl/<name>/fullchain.pem` + `privkey.pem`; the key is mode 600). A deployment applies only those two files, never unrelated pending edits, and the agent still runs `nginx -t`, reloads and rolls back on failure. Renewal is checked every 10 minutes (default: renew when 30 days are left); servers that were offline get the new certificate when they reconnect.
  - **Validation is DNS-01** (works for wildcards and for servers not reachable from the internet): Cloudflare (API token with Zone → DNS → Edit), Route 53, or custom hook scripts for any other DNS host.
  - **Other CAs**: ZeroSSL, Google Trust Services, DigiCert and Sectigo use ACME with External Account Binding — paste the EAB key ID and HMAC from your CA account (DigiCert/Sectigo: also the account's ACME directory URL).
  - **AWS Certificate Manager**: the certificate must be requested with export enabled (or come from AWS Private CA). AWS renews it; nginx-manager checks the serial every 6 hours and re-exports + redeploys when it changes. IAM: `acm:DescribeCertificate`, `acm:ExportCertificate`.
  - **Use for sites…** switches every `ssl_certificate`/`ssl_certificate_key` that points at an old certificate to the managed one (staged for review, then Apply).
  - Secrets (DNS tokens, EAB HMAC, AWS keys) live only in `data/cert-secrets.json` (mode 600) and are never returned by the API. ACME account keys and issued certificates live in `data/certbot/`.
- **Keys the agent doesn't report** (NGINX Agent never uploads private keys) are remembered by the manager and included in every later apply — otherwise the agent would delete them.
- **Data** lives in `./data/` (git-ignored, mode 700): server list, synced file contents, uploaded-cert labels, builder site definitions, and the gRPC TLS material. Synced files can include TLS private keys referenced by nginx — protect backups accordingly.
- `proto/` contains the NGINX Agent `mpi.v1` protobuf definitions (Apache-2.0, from [nginx/agent](https://github.com/nginx/agent)) with `buf.validate` annotations removed.

## Development

```bash
npm install
npm test        # unit + protocol tests (fake agent)

# managed-certificate pipeline against Let's Encrypt's Pebble test CA:
#   run pebble + pebble-challtestsrv, then
NM_TEST_PEBBLE=1 CERTBOT_BIN=$(which certbot) REQUESTS_CA_BUNDLE=pebble.minica.pem NM_TEST_HOOKS=<dir with auth-hook.sh/cleanup-hook.sh> \
  node --test test/certmanager.test.js
npm run dev
```
