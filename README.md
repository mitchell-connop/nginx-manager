# Nginx Manager

A self-hosted web GUI for managing nginx servers through **[NGINX Agent](https://github.com/nginx/agent) v3** — edit configs, build sites visually, manage certificates, watch traffic and backends, and push changes that are validated and rolled back automatically.

Built for ConnopNetworking homelab infrastructure; usable anywhere you run open-source nginx on Linux.

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation) — manager, adding nginx servers, network ports, firewall rules
- [Configuration (.env)](#configuration-env)
- [Setup guides](#setup-guides) — how to configure each feature
- [Notes](#notes) · [Limitations](#limitations) · [Development](#development)

## Features

**Managing servers and config**

- 🖥️ **Multi-server** — manage many nginx servers from one interface, grouped in the sidebar (e.g. a keepalived pair per group)
- ➕ **Manual enrolment** — servers are added by hand; each gets its own agent token. Agents with unknown tokens are rejected
- 🐧 **Debian/Ubuntu and RHEL/Rocky/Alma/Amazon Linux** nginx servers — every install script the manager hands out detects `apt-get` vs `dnf`/`yum`; SELinux-aware
- 🔐 **No host credentials** — no SSH. Agent tokens are stored only as SHA-256 hashes, passwords as bcrypt hashes
- 📄 **Config editor** — edit every file nginx references, as reported by the agent
- 📤 **Apply** — staged changes are pushed in one go; the agent writes them, runs `nginx -t`, reloads, and **rolls back automatically** if anything fails
- 🔄 **Live, no scanning** — the Builder, Certificates and Raw Configs tabs are derived from what the agent reports, so hand edits on the server show up within seconds
- 🔁 **Group sync & drift detection** — members of a group are compared continuously; the sidebar flags drift, **Compare & sync** shows the differing files (with diffs) and copies the right version to the others, and **Apply → Whole group** carries one server's edits to every member one at a time, stopping at the first failure. Files changed separately on another member are flagged as conflicts instead of being overwritten
- 🕘 **Config history & rollback** — a snapshot every time a server's files change (applied here, or edited on the server itself), with who, what and a diff; **Restore** stages any earlier version for review and apply

**Visual Builder**

- 🔀 **Reverse proxies** — add and edit sites from a popup; they live in `conf.d/reverse-proxies.conf`, edited in place with a live diff preview
- 🛡️ **Per-site protection** — rate limiting (`limit_req`), concurrent-connection limits (`limit_conn`), and SSO via `auth_request` (presets for Authelia, Authentik and oauth2-proxy)
- 🏗️ **Static sites and redirects** — each gets its own generated file; every other server block is listed live
- 🧭 **Forward proxies** — HTTPS (CONNECT) forward proxies with client allowlists, logins and destination allowlists — **requires nginx 1.31.0+**
- 📹 **RTSP streams** — relay camera RTSP feeds as TCP proxies in nginx's `stream {}` context, one upstream + server per camera with optional fallback (e.g. an NVR)
- 🚧 **Unknown hosts** — a managed `default_server` catch-all so a request for a host no site serves (or for the bare IP) never lands on the first site: drop it, return a status, or redirect

**Certificates**

- 🔄 **Managed certificates** — certbot runs on the manager (Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert, Sectigo or any ACME CA with EAB; or exportable AWS ACM certificates), deploys to every server in the group through the agents, and renews automatically
- 🔐 **Certificate inventory** — every cert nginx references, live, with SANs, issuer, expiry and which sites use it; upload new cert/key pairs

**Observability**

- 📡 **Connections** — live request log per server: client, site, request, status and upstream, with allowed / denied / error counts and filters. Query strings are never logged
- 💓 **Keepalived log & VIP holder** — keepalived's journal per server (MASTER/BACKUP transitions highlighted), and which server holds each group's VIP — reported by the servers themselves, so it works when the manager is on another subnet. Split brain and a stopped keepalived are flagged
- ❤️ **Backend health checks from the data plane** — a small helper on each nginx server probes every upstream / `proxy_pass` backend (TCP or HTTP) and reads a loopback-only `stub_status`. The manager never needs to reach the backends, so it can sit in a separate control-plane network. Up/down with fall/rise thresholds, 24 h availability, live connections
- 📈 **Usage dashboard** — requests by result (allowed / 4xx / 5xx / denied), data sent, median and p95 response time, top sites, clients, status codes, upstreams and RTSP streams, over 1 h – 30 days, per server or per group
- 🛡️ **CVE detection** — matches each server's nginx version against the [nginx.org security advisories](https://nginx.org/en/security_advisories.html) and nginx-agent against [OSV.dev](https://osv.dev). Module-specific advisories are checked against the server's config, so a vulnerable version whose module isn't used is shown as such
- 🔔 **Alerts** — email (SMTP) and webhooks (generic JSON, Slack/Mattermost, Discord, ntfy, Teams) for VIP failover, server offline, failed applies, certificate problems, new CVEs, backends down/recovered, 5xx and denied-request spikes, and group drift
- 📊 **Status** and 🖥️ **live operation log** (Socket.IO, session-authenticated)

**Access**

- 👥 **Users, roles & audit log** — viewer (read-only, never sees private keys), operator (edit / apply / rollback / sync), admin (users, sign-in, alerts, branding, enrolment). Every change, apply and sign-in is recorded
- 🔑 **Directory sign-in** — LDAP / Active Directory and RADIUS; directory groups map to roles at every sign-in
- 🎨 **Branding** — your own logo (also the browser tab icon), app name and login text

## Architecture

```
Browser ── HTTPS/HTTP :3000 + Socket.IO ──▶ nginx-manager (Node.js)  ── LDAP/RADIUS, SMTP, webhooks, ACME, CVE feeds ──▶
                                              ▲               ▲
                       gRPC/TLS :8443/tcp ────┘               └──── syslog :5514/udp (request log, keepalived, health)
                                              │               │
               ┌──────────────────────────────┴───────────────┴──────────┐
         nginx server A                                           nginx server B
         nginx + nginx-agent (dials in)                           nginx + nginx-agent
         [nginx-manager-helper]  [keepalived + forwarder]         [helper]  [keepalived + forwarder]
```

The agents connect **out** to the manager — the manager never logs in to the nginx servers. Each agent:

1. authenticates with its per-server token (`authorization` gRPC metadata, TLS only),
2. reports its nginx instance and uploads the config files nginx references (inside its `allowed_directories`),
3. on **Apply**, downloads changed files, runs `nginx -t`, reloads, and reports success — or rolls back and reports the error.

Everything else the servers send (request log, keepalived journal and VIP state, health results) is UDP syslog to the manager. Packets are accepted only from enrolled agents' addresses.

## Installation

### Manager

Requirements: **Debian 12+ or Ubuntu 22.04+**, Node.js 20+, `openssl`, `git`. (certbot and its DNS plugins are installed by the installer for managed certificates.)

```bash
curl -fsSL https://raw.githubusercontent.com/mitchell-connop/nginx-manager/main/install.sh -o install.sh
sudo bash install.sh
```

The installer installs Node.js 22 if needed, clones to `/opt/nginx-manager`, generates `SESSION_SECRET`, prompts for the admin password and stores it as a bcrypt hash in `.env` (mode 600, git-ignored), and installs the systemd service.

On first start the manager creates a private CA and a TLS certificate for the agent gRPC listener in `data/tls/` (covering the host's name and IPv4 addresses — see `GRPC_TLS_SANS`).

Manual install:

```bash
git clone https://github.com/mitchell-connop/nginx-manager.git && cd nginx-manager
npm ci --omit=dev
cp .env.example .env && chmod 600 .env   # set SESSION_SECRET and ADMIN_PASSWORD
node server.js
```

**Upgrading:** `cd /opt/nginx-manager && git pull --ff-only && npm ci --omit=dev && systemctl restart nginx-manager`. A restart signs everyone out (sessions are held in memory).

### Adding an nginx server

Supported: **Debian / Ubuntu**, **RHEL / Rocky / Alma 8–10**, **Amazon Linux 2 / 2023**, with nginx from the distro or from nginx.org.

1. Click **＋ Add Server**, give it a name and (optionally) a group — servers in the same group are compared for drift and can be applied to together.
2. A one-time **agent token** and a setup script are shown. Run the script as root on the nginx server. It:
   - adds the nginx.org `nginx-agent` repository for that distro (apt or dnf/yum) and installs the agent,
   - writes the token to `/etc/nginx-agent/manager.token` (mode 600) and the manager's CA to `/etc/nginx-agent/manager-ca.pem`,
   - writes `/etc/nginx-agent/nginx-agent.conf` pointing at the manager, and restarts the agent.
3. The server turns green in the sidebar and its config files appear within a few seconds.

Lost the token? **🔑 Agent Setup → New Token** issues a new one (the old one stops working immediately).

### Network ports

| From | To | Port | Needed for |
|---|---|---|---|
| Browsers | manager | `PORT` (3000/tcp) | Web UI |
| nginx servers | manager | `GRPC_PORT` (8443/tcp) | Agent connection — always |
| nginx servers | manager | `LOG_RECEIVER_PORT` (5514/udp) | Connections log, keepalived log + VIP holder, health checks, usage |
| manager | VIP | the group's VIP port (tcp) | VIP reachability check (optional) |
| manager | directory | 636/389 tcp, 1812/udp | LDAP / RADIUS sign-in (if used) |
| manager | internet | 443/tcp | CVE feeds, ACME CAs, DNS APIs, webhooks; SMTP port for email |
| nginx server | itself | 127.0.0.1:8099/tcp | Health helper ↔ `stub_status` (loopback only) |

The manager never connects to the nginx servers or their backends, so it can live in a separate management VLAN as long as the servers can reach it on 8443/tcp and 5514/udp.

### Firewall rules (manager in a different network / VLAN)

Example: management VLAN `10.0.10.0/24` with the manager at `10.0.10.5`, nginx servers in a DMZ `10.0.20.0/24` (VIP `10.0.20.50`), admins on `10.0.30.0/24`. Substitute your own ranges.

**On the router / inter-VLAN firewall** (stateful — return traffic is allowed automatically):

| # | Action | Source | Destination | Protocol / port | Purpose |
|---|---|---|---|---|---|
| 1 | allow | nginx servers `10.0.20.0/24` | manager `10.0.10.5` | TCP 8443 | Agent → management plane (required) |
| 2 | allow | nginx servers `10.0.20.0/24` | manager `10.0.10.5` | UDP 5514 | Request log, keepalived log + VIP state, health results |
| 3 | allow | admins `10.0.30.0/24` | manager `10.0.10.5` | TCP 3000 (or 443 if proxied) | Web UI |
| 4 | allow *(optional)* | manager `10.0.10.5` | VIP `10.0.20.50` | TCP 443 (the group's VIP port) | VIP reachability on the badge |
| 5 | allow *(if used)* | manager | domain controllers / RADIUS | TCP 636 (or 389), UDP 1812 | Directory sign-in |
| 6 | allow | manager | internet | TCP 443 (+ SMTP 587/465 to your mail relay) | ACME + DNS APIs, CVE feeds, webhooks, email |
| — | **not needed** | manager | nginx servers | *anything* | The manager never connects to the servers (no SSH, no agent port) |
| — | **not needed** | manager | backends | *anything* | Health checks run on the nginx servers, which already reach their backends |

Rules 1–2 are the only ones the nginx servers need. Rule 2 is one-way UDP: no reply is sent, so a stateful firewall needs no return rule. Nothing needs to be opened **towards** the nginx servers for management.

Through a **stateful** firewall these rules are complete — every connection is opened from the allowed side, so replies ride the connection state:

- **Agent (TCP 8443)** is one long-lived gRPC connection per server, opened by the server. The agent sends an HTTP/2 keepalive ping every 20 s (NGINX Agent default), so firewall idle timeouts never expire it. If a firewall does drop it, the agent reconnects by itself within seconds.
- **Syslog (UDP 5514)** creates a short UDP state entry per server that is refreshed by every packet; nothing is ever sent back.
- **Manager-initiated traffic** (rules 4–6) gets its replies the same way.
- Avoid **asymmetric routing** (e.g. a server with a second NIC whose route to the manager differs from the path the firewall saw), which stateful firewalls drop. No ICMP or other return rules are required.

**Don't NAT between the servers and the manager.** The manager identifies each server by the source IP it sees on the gRPC connection and accepts syslog only from those addresses. With SNAT/masquerade every server appears as the same address, so log lines, health results and VIP state can't be told apart (or are dropped). Route the VLANs instead. If the manager itself is reached through a NAT/VIP address, set `LOG_RECEIVER_HOST` (where servers send syslog) and `AGENT_CONNECT_HOST` (where agents connect) to that address.

**On the manager's own host firewall** — e.g. `ufw`:

```bash
ufw allow from 10.0.20.0/24 to any port 8443 proto tcp
ufw allow from 10.0.20.0/24 to any port 5514 proto udp
ufw allow from 10.0.30.0/24 to any port 3000 proto tcp
```

or `firewalld`:

```bash
firewall-cmd --permanent --new-zone=nginx-servers
firewall-cmd --permanent --zone=nginx-servers --add-source=10.0.20.0/24
firewall-cmd --permanent --zone=nginx-servers --add-port=8443/tcp --add-port=5514/udp
firewall-cmd --reload
```

**On the nginx servers' host firewalls:** no inbound rules are needed for nginx-manager (outbound to the manager is allowed by default on Debian/Ubuntu and RHEL). If you filter outbound traffic, allow TCP 8443 and UDP 5514 to the manager. The helper's `stub_status` port (8099) is bound to 127.0.0.1 only and must **not** be opened. keepalived itself still needs VRRP (IP protocol 112) between the pair as usual — unrelated to the manager.

**Checking it:** from an nginx server, `nc -zv 10.0.10.5 8443` should connect; the server turns green in the sidebar once the agent is in. For UDP, enable Connections and make a request through nginx — it should appear in the Log tab within a second. Nothing arriving while the agent is connected means UDP 5514 is blocked or NATed.

## Configuration (.env)

Edit `.env` (see `.env.example`) and restart the service.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Web UI port |
| `SESSION_SECRET` | **(required)** | Session cookie secret — long random string |
| `ADMIN_PASSWORD` | **(required)** | Built-in `admin` password — a bcrypt hash (recommended) or plain text |
| `GRPC_PORT` | `8443` | Port NGINX Agent connects to (gRPC over TLS) |
| `AGENT_CONNECT_HOST` | browser hostname | Host/IP agents use to reach the manager (written into setup scripts) — set it when you browse the UI by a name the servers can't resolve |
| `GRPC_TLS_SANS` | hostname + IPv4s | Names/IPs in the generated gRPC certificate, e.g. `DNS:nginx-manager.lan,IP:10.0.0.10`. The certificate is re-issued automatically on restart when this changes (same CA, so agents keep working) |
| `GRPC_TLS_CERT` / `GRPC_TLS_KEY` / `GRPC_TLS_CA` | — | Use your own gRPC certificate instead |
| `GRPC_TLS_SERVER_NAME` | — | Name in your own certificate, if the agents connect by IP |
| `LOG_RECEIVER_PORT` | `5514` | UDP syslog port; `off` disables the receiver (and Connections, keepalived, health checks, usage) |
| `LOG_RECEIVER_HOST` | auto | Address the servers send syslog to. Default: the manager's own address on the route to each server. Set it when the manager is behind NAT |
| `COOKIE_SECURE` | — | `true` when the UI is served over HTTPS (cookies marked Secure) |
| `TRUST_PROXY` | — | e.g. `1` when behind a reverse proxy, so client IPs (login lockout, audit log) are right |
| `DATA_DIR` | `./data` | Where all state lives |
| `CERTBOT_BIN` | `certbot` | certbot executable for managed certificates |

## Setup guides

Everything below is configured in the UI. Changes to nginx files are **staged** — review them and click **Apply** (or **Apply → Whole group**).

### Groups and the keepalived VIP

1. Put both servers of an HA pair in the same group (set when adding a server, or edit it later).
2. Right-click the group in the sidebar → **🛜 Set VIP…** and enter the virtual IP and a port it serves (e.g. 443).
3. Install the **keepalived forwarder** on each server (next section) so the manager is told which server holds the VIP.

The badge under the group shows the holder (green), a member with keepalived stopped — no standby (amber), split brain or nobody holding it (red), or that the VIP doesn't answer the manager. Without the forwarder, the manager falls back to matching the VIP's MAC address in its own ARP table, which only works when it is on the same L2 subnet as the servers.

### Keepalived log forwarder

**Log tab → Keepalived → Forwarder setup** shows a script. Run it as root on **every** keepalived server. It installs `nginx-manager-keepalived-log.service` (unprivileged), which:

- streams keepalived's journal to the manager (MASTER/BACKUP transitions are highlighted; the last 200 lines are replayed on restart and de-duplicated), and
- every 10 s reports the server's IPv4 addresses and whether keepalived is running — this is what names the VIP holder.

Re-run the script if the manager's address changes.

### Connections (request log)

**Log tab → Connections → Enable & apply**, on each server (members of a group are separate). This adds `conf.d/00-nginx-manager-logging.conf` — a JSON `log_format` and an `access_log syslog:` line pointing at the manager — alongside nginx's normal access log. It also feeds the **Usage** tab. Denied = 401/403/407/429/444. Query strings are never logged.

### Backend health checks

1. **Health tab → Helper install script**: run it as root on each nginx server **before** enabling checks. It installs Python 3 if missing, the helper (`/usr/local/lib/nginx-manager/nm-helper.py`) and `nginx-manager-helper.service` (unprivileged, `DynamicUser`). On SELinux hosts it labels port 8099 as `http_port_t` so nginx may listen there.
2. **Health tab → Enable & apply** (choose **Whole group** for a pair). This stages a loopback-only `stub_status` on 127.0.0.1:8099 and the helper's target list (`nginx-manager/helper.json`), both delivered by the agent.
3. Backends are found automatically from `upstream` blocks and fixed `proxy_pass` / `grpc_pass` addresses, and kept in step with every apply. Use **Edit check** on a backend to switch it from a TCP connect check to an **HTTP** check (path, expected status such as `200-399`, Host header, TLS) or to disable it.
4. **⚙ Settings → Health checks** sets interval, timeout, *fall* (failures before down) and *rise* (successes before up) for all servers.

A backend's row also shows how the other group members see it — useful when only one LB can't reach something.

### Alerts

**⚙ Settings → Alerts** (admin):

- **Email (SMTP)** — server, port, security (`starttls` on 587, `tls` on 465, or none), optional username/password, From, and comma-separated To addresses.
- **Webhooks** — **＋ Add webhook**, name, URL and format:
  | Format | URL to paste |
  |---|---|
  | `json` | any endpoint; receives `{event, severity, title, message, …}` |
  | `slack` | Slack or Mattermost incoming-webhook URL |
  | `discord` | Discord channel webhook URL |
  | `ntfy` | `https://ntfy.sh/<topic>` or your own ntfy server |
  | `teams` | Teams incoming webhook / Workflows URL |
- **When to alert** — tick the events you want and tune the thresholds: certificate expiry warning (days), 5xx and denied spikes (% of requests within the spike window, with a minimum number of requests), minutes offline before alerting, how long drift must last, and **Repeat the same alert after** (cool-down, so a flapping backend doesn't flood you; recoveries are always sent).
- **📨 Send test** saves and sends a test alert to every enabled channel. Passwords are stored in `data/alerts.json` and never shown again.

Spike alerts need Connections enabled; backend alerts need health checks; VIP alerts need a VIP set.

### Users and roles

**⚙ Settings → Users** (admin) → **＋ Add user**. Roles: **viewer** (read-only, private keys hidden), **operator** (edit, apply, rollback, sync), **admin** (also users, sign-in, alerts, branding, enrolment). Local passwords must be 10+ characters; users change their own under **My account**.

The built-in `admin` account always works with `ADMIN_PASSWORD` from `.env` — keep it as a break-glass account and use named or directory accounts day to day. After 10 failed sign-ins an IP is locked out for 15 minutes (a service restart clears it). **⚙ Settings → Audit log** lists every sign-in and change.

### Directory sign-in — LDAP / Active Directory

**⚙ Settings → Sign-in** (admin). Turn **LDAP / Active Directory** on to show its settings.

1. **Server URL** — `ldaps://dc01.example.com:636` (recommended) or `ldap://…:389` with **StartTLS**. Plain `ldap://` without StartTLS sends passwords in clear text and is warned about.
2. **Certificate** — keep **Verify the server certificate** on. For an internal CA (e.g. AD CS), paste the root CA PEM into **CA certificate**. If the URL uses an IP address, put the name the DC's certificate is issued to (e.g. `dc01.example.com`) in **Certificate name**.
3. **Directory type** — *Active Directory* fills the AD user filter; *OpenLDAP / FreeIPA* uses `uid`.
4. **How users are found**:
   - *Service account searches* (recommended) — create a plain domain user (e.g. `svc-nginx-manager`, no admin rights, password never expires) and enter it as `svc-nginx-manager@example.com` or its DN, with its password. **Base DN** is where users are searched, e.g. `DC=example,DC=com`.
   - *Bind directly as the user* — no service account; **Bind as** is a template such as `{{username}}@example.com`.
5. **User filter** — the AD default `(|(sAMAccountName={{username}})(userPrincipalName={{upn}}))` lets people sign in as `user`, `DOMAIN\user` or `user@domain`.
6. **Groups → role** — create security groups (e.g. `nginx-manager-admins`, `-operators`, `-viewers`), add people, and paste each group's full DN (e.g. `CN=nginx-manager-admins,OU=Groups,DC=example,DC=com`). Turn on **Include nested groups** for AD. **Users in none of these groups** is normally *refuse sign-in*.
7. **💾 Save**, then **Test a sign-in** — it shows each step (connect, bind, search, groups, role) without creating a session.

The role is re-read from the directory at every sign-in. A local user with the same name takes precedence over the directory.

### Directory sign-in — RADIUS

Turn **RADIUS** on in **⚙ Settings → Sign-in**:

1. **Server** / **Port** (1812) / **Shared secret** — add the manager as a RADIUS client on the server (NPS: *RADIUS Clients*; FreeRADIUS: `clients.conf`) with the same secret.
2. **Role comes from the reply attribute** `Class` or `Filter-Id`. On the RADIUS server, return a value per role — e.g. an NPS network policy per AD group with *Settings → RADIUS Attributes → Standard → Class* = `nginx-admin` — and enter the same values under **value for admin / operator / viewer**.
3. Authentication is PAP with Message-Authenticator; push-style MFA proxies that accept PAP work, challenge/response prompts don't.

With both providers on, **Try in this order** chooses which is asked first.

### Managed certificates

**Certificates tab → ＋ Request Certificate**:

1. **Name**, **domains** (wildcards allowed, e.g. `example.com *.example.com`) and an optional contact email.
2. **CA** — Let's Encrypt (default) or another ACME CA. ZeroSSL, Google Trust Services, DigiCert and Sectigo need **EAB** credentials (key ID + HMAC from your CA account; DigiCert/Sectigo also the ACME directory URL). Or choose **AWS Certificate Manager** for an exportable ACM certificate (IAM: `acm:DescribeCertificate`, `acm:ExportCertificate`).
3. **DNS validation** (DNS-01, works for wildcards and private servers):
   - *Cloudflare* — an API token with **Zone → DNS → Edit** on the zone.
   - *Route 53* — access key with `route53:ListHostedZones`, `route53:GetChange`, `route53:ChangeResourceRecordSets` (or an instance role).
   - *Custom hook scripts* — absolute paths to an auth and a cleanup script on the manager; certbot runs them with `CERTBOT_DOMAIN` and `CERTBOT_VALIDATION`, and they must create/remove the TXT record `_acme-challenge.$CERTBOT_DOMAIN`.
4. **Deploy to** — the servers (usually the whole group) — and the paths to write (default `/etc/nginx/ssl/<name>/fullchain.pem` + `privkey.pem`); **Renew when fewer than (days) left** defaults to 30.
5. **🔄 Save & Issue**, then **🔀 Use for sites…** to point existing `ssl_certificate` lines at it (staged, then Apply).

### Reverse proxies and per-site protection

**Visual Builder → 🔀 Add Reverse Proxy**: name, domain(s), backend(s), optional backend path, certificate, and options (HSTS, WebSockets, upload size, read timeout). Under **Protection**:

- **Rate limit** — rate (`10r/s` or `300r/m`) and burst, per client IP. Excess requests get 429. Zones live in `conf.d/00-nginx-manager-limits.conf`.
- **Connection limit** — max simultaneous connections per client IP.
- **SSO** — pick Authelia, Authentik or oauth2-proxy (or fill in your own): the **Check URL** nginx calls for every request (`auth_request`) and the **Sign-in page** users are sent to. `Remote-User`, `Remote-Groups`, `Remote-Email` and `Remote-Name` are passed to the backend.

### Unknown hosts (catch-all)

**Visual Builder → Unknown hosts → Set up**:

- **Drop** (recommended) — HTTP gets `444` (connection closed), HTTPS refuses the TLS handshake (`ssl_reject_handshake`, no certificate needed or revealed).
- **Return a status code** — e.g. 404.
- **Redirect to a URL** — 301/302/307/308, optionally keeping the path.

For a status or redirect over HTTPS, choose a certificate to answer with; otherwise HTTPS listeners still reject the handshake. The file `conf.d/00-nginx-manager-default.conf` covers every address:port your name-based sites listen on and is updated automatically as sites change; a port that already has a `default_server` elsewhere is reported as a conflict and left alone. Do it on each group member (or **Apply → Whole group**).

### Group sync and drift

Drift is checked every minute; a group with differences shows a badge. Right-click the group → **🔁 Compare & sync…** to see each differing file, pick the source server, and **Copy & apply**. Under **Ignore files that are meant to differ**, list glob patterns (one per line, e.g. `/etc/nginx/conf.d/local-*.conf`) for per-server files.

### Forward proxies

**Visual Builder → 🧭 Add Forward Proxy** (only on servers running nginx ≥ 1.31.0): listen address/port, allowed client networks and/or proxy logins (at least one is required — open proxies are refused), and optionally allowed destination hosts/ports. Clients use it as an HTTPS proxy (`CONNECT`).

### RTSP streams

**Visual Builder → 📹 Add RTSP Stream**: name, listen port (e.g. 8554), the camera or RTSP server, optional fallback servers (e.g. the NVR), and the client networks allowed (required). Clients must use RTSP over TCP. The first stream adds a `stream {}` block to `nginx.conf`.

### CVE detection

Nothing to configure — the **CVEs** tab refreshes advisories daily (needs outbound HTTPS to nginx.org and osv.dev); **🔄 Check now** refreshes immediately. Enable the *New CVE* alert to be told.

### Branding

**🎨 Branding** (admin, top bar): logo (PNG/JPEG/WebP/GIF up to 512 KB; SVG refused), app name and login-page text. Stored in `data/`, so upgrades keep it.

### Serving the UI over HTTPS

Put the UI behind a reverse proxy (it can be one of your managed nginx servers) and set `COOKIE_SECURE=true` and `TRUST_PROXY=1` in `.env`. Proxy WebSockets (`/socket.io/`) too.

## Notes

- **Allowed directories** — the agent can only read/write files under its `allowed_directories`: `/etc/nginx`, `/etc/letsencrypt`, `/etc/ssl/nginx` (plus nginx's runtime/log dirs). Upload certificates under one of those, e.g. `/etc/nginx/ssl/`.
- **Applying** writes the files, runs `nginx -t` and does a graceful reload (no dropped connections). The agent then watches the error log for ~10 s before reporting success, and rolls back if anything fails.
- **Reverse proxies are edited in place** — a site is the `# ===` header comment plus its `upstream`, HTTP→HTTPS redirect and HTTPS `server` blocks, grouped by `server_name`. The popup only rewrites the directives its fields own; comments and everything else stay byte-for-byte. Sites whose `proxy_pass` uses variables, and non-proxy server blocks, are read-only cards that open the file.
- **Files the agent doesn't report back** (private keys, htpasswd files, the health helper's `helper.json`) are remembered by the manager and included in every later apply — otherwise the agent would delete them.
- **Managed files** are named `00-nginx-manager-*.conf` in `conf.d/` and are excluded from the Builder's site list. Edit them through their feature, not by hand.
- **Forward proxies** use `ngx_http_tunnel_module` (nginx 1.31.0+, mainline). Proxy logins are bcrypt hashes in `/etc/nginx/forward-proxy/<name>.htpasswd`. Destinations are matched by name; IP-literal destinations are blocked by default.
- **Managed certificates** are issued once, on the manager, so an HA pair always serves the same certificate. A deployment applies only the certificate files, never unrelated pending edits. Servers that were offline get the new certificate when they reconnect. Secrets (DNS tokens, EAB HMAC, AWS keys) live only in `data/cert-secrets.json` (mode 600).
- **SELinux** — the only change needed is the status-port label done by the helper script; nginx's syslog to the manager is plain UDP and needs no boolean. Your own `proxy_pass` targets need `httpd_can_network_connect` as usual.
- **Data and backups** — everything lives in `data/` (mode 700): servers, synced file contents (**including TLS private keys**), history, users, sign-in and alert settings (with secrets), certbot accounts and certificates, and the gRPC CA. Back it up and protect the backups; losing `data/tls/` means re-enrolling every agent.
- **Upgrading from v1 (SSH)** — on first start, stored SSH passwords are removed from `data/agents.json`. Open each server, click **🔑 Agent Setup → New Token**, and run the setup on that server.
- `proto/` contains the NGINX Agent `mpi.v1` protobuf definitions (Apache-2.0, from [nginx/agent](https://github.com/nginx/agent)) with `buf.validate` annotations removed.

## Limitations

- One manager instance; state is JSON files in `data/`, and sessions are in memory (a restart signs everyone out).
- No MFA for local accounts and no API tokens for automation yet.
- Open-source nginx only (not NGINX Plus' API).
- Log/health/VIP reports are plain, unauthenticated UDP syslog identified by source IP — keep them on a trusted network and avoid NAT between the servers and the manager.
- Tested on Debian 13 and Rocky Linux 9 nginx servers; the SELinux step has not been tested on an enforcing host.

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
