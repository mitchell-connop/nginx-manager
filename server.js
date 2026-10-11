/**
 * nginx-manager — server.js
 *
 * Web GUI + management plane for nginx servers running NGINX Agent v3.
 *
 *  - Servers are added manually in the UI. Each gets a random agent token (shown once,
 *    stored only as a SHA-256 hash). No SSH, no host passwords.
 *  - NGINX Agent on each server dials in over gRPC/TLS (lib/mpi.js), reports its nginx
 *    instance and uploads the config files nginx references.
 *  - Edits (raw files, visual-builder sites, certificates) are staged as a draft and pushed
 *    with "Apply": the agent writes the files, runs `nginx -t`, reloads, and rolls back
 *    automatically if anything fails.
 *
 *  REST
 *   /api/agents                      list / add (manual) / edit / remove servers
 *   /api/agents/:id/token            issue a new agent token
 *   /api/agents/:id/setup            agent install instructions
 *   /api/agents/:id/files            file list (live + pending changes)
 *   /api/agents/:id/file?path=       read / stage edit / stage delete one file
 *   /api/agents/:id/discard          drop pending changes
 *   /api/agents/:id/apply|sync       push pending changes / re-pull files from the agent
 *   /api/agents/:id/status           agent, nginx and health info
 *   /api/agents/:id/sites            visual-builder site CRUD, preview, import
 *   /api/agents/:id/certs            certificate registry, upload (staged), scan
 *  Socket.IO (session-authenticated)  live operation log + apply/sync/status
 */

'use strict';

require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const bcrypt       = require('bcryptjs');
const http         = require('http');
const crypto       = require('crypto');
const { Server }   = require('socket.io');
const multer       = require('multer');
const path         = require('path');
const { randomUUID: uuidv4 } = require('crypto');

const store = require('./lib/store');
const { ensureTls } = require('./lib/tls');
const { ManagementPlane } = require('./lib/mpi');
const { siteToNginxConf, parseNginxConf } = require('./lib/nginxconf');
const proxyfile = require('./lib/proxyfile');
const { unifiedDiff } = require('./lib/linediff');
const { VipMonitor } = require('./lib/vip');
const { CertManager } = require('./lib/certmanager');
const issuers = require('./lib/issuers');
const fwdproxy = require('./lib/fwdproxy');
const branding = require('./lib/branding');
const logrx = require('./lib/logrx');
const streams = require('./lib/streams');
const { UsageStore } = require('./lib/usage');
const { CveScanner } = require('./lib/cve');
const { Users, atLeast } = require('./lib/users');
const { AuditLog } = require('./lib/audit');
const { History, changesBetween } = require('./lib/history');
const groupsync = require('./lib/groupsync');
const health = require('./lib/health');
const { Alerts } = require('./lib/alerts');
const defaultServer = require('./lib/defaultserver');
const { ExternalAuth } = require('./lib/extauth');
const fs = require('fs');
const dgram = require('dgram');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT           = process.env.PORT || 3000;
const GRPC_PORT      = parseInt(process.env.GRPC_PORT || '8443', 10);
// UDP syslog receiver for the Log tab (nginx request log + keepalived); "off" disables it
const LOG_PORT       = process.env.LOG_RECEIVER_PORT === 'off' ? null : parseInt(process.env.LOG_RECEIVER_PORT || String(logrx.DEFAULT_PORT), 10);
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_PASS     = process.env.ADMIN_PASSWORD;

for (const [name, value] of [['ADMIN_PASSWORD', ADMIN_PASS], ['SESSION_SECRET', SESSION_SECRET]]) {
  if (!value || value.startsWith('change-me')) {
    console.error(`[nginx-manager] ERROR: ${name} is not set in .env`);
    console.error('[nginx-manager] Run install.sh, or see .env.example for how to set it.');
    process.exit(1);
  }
}

// v1 (SSH-based) server entries stored SSH passwords in agents.json — strip them.
// Those servers need a token (Agent Setup → New Token) before their agent can connect.
(function migrateV1Agents() {
  const agents = store.readAgents();
  let changed = 0;
  for (const a of agents) {
    if ('sshPass' in a || 'sshKeyPath' in a || 'sshUser' in a || 'sshPort' in a) {
      if (a.host && !a.description) a.description = `was ${a.host}`;
      delete a.sshPass; delete a.sshKeyPath; delete a.sshUser; delete a.sshPort; delete a.host;
      changed++;
    }
  }
  if (changed) {
    store.writeAgents(agents);
    console.log(`[nginx-manager] Removed stored SSH credentials from ${changed} server(s); issue each an agent token via Agent Setup.`);
  }
})();

// Imported-site snapshots are no longer used — server blocks are read live from the
// config files the agent reports.
(function dropImportedSiteSnapshots() {
  let n = 0;
  for (const a of store.readAgents()) {
    for (const s of store.readSites(a.id)) if (s.importedFrom && store.deleteSite(a.id, s.id)) n++;
  }
  if (n) console.log(`[nginx-manager] Removed ${n} imported site snapshot(s); sites now come live from the agent.`);
})();

const tls = ensureTls(path.join(store.DATA_DIR, 'tls'));
const mp  = new ManagementPlane({ tls, port: GRPC_PORT });
const certManager = new CertManager({ mp });

// Syslog packets are attributed by source address (the address each agent connects from)
let addrCache = { at: 0, map: new Map() };
function agentIdByAddress(address) {
  if (Date.now() - addrCache.at > 5000) {
    addrCache = { at: Date.now(), map: new Map(store.readAgents().filter(a => a.address).map(a => [a.address, a.id])) };
  }
  return addrCache.map.get(address) || null;
}
const logReceiver = new logrx.LogReceiver({
  port: LOG_PORT || 0,
  resolveAgent: agentIdByAddress,
  persistDir: path.join(store.DATA_DIR, 'logs'),
});
const usage = new UsageStore({ dir: path.join(store.DATA_DIR, 'usage') });
logReceiver.on('entries', ({ agentId, kind, entries }) => {
  if (kind === 'access') for (const e of entries) usage.record(agentId, e);
});
const cve = new CveScanner({ cacheFile: path.join(store.DATA_DIR, 'cve-cache.json') });
const users = new Users({ file: path.join(store.DATA_DIR, 'users.json'), adminPassword: ADMIN_PASS });
const audit = new AuditLog({ file: path.join(store.DATA_DIR, 'audit.log') });
const extAuth = new ExternalAuth({ file: path.join(store.DATA_DIR, 'auth.json') });
const history = new History({ dir: path.join(store.DATA_DIR, 'history') });
const HEALTH_SETTINGS = path.join(store.DATA_DIR, 'health-settings.json');
let healthSettings = health.loadSettings(HEALTH_SETTINGS);
const healthState = new health.HealthState({ getSettings: () => healthSettings });
const alerts = new Alerts({ file: path.join(store.DATA_DIR, 'alerts.json'), historyFile: path.join(store.DATA_DIR, 'alert-history.json'), stateFile: path.join(store.DATA_DIR, 'alert-state.json') });
const HELPER_SOURCE = fs.readFileSync(path.join(__dirname, 'helper', 'nm-helper.py'), 'utf8');
logReceiver.on('health', (agentId, msg) => healthState.receive(agentId, msg));
healthState.on('status', (agentId, sample) => usage.recordConnections(agentId, sample.active));

// Every apply goes through here (UI, REST, certificate deployments, group sync, rollback):
// it refreshes the helper's target list, records history and the audit entry, and alerts on failure.
const rawConfigApply = mp.configApply.bind(mp);
mp.configApply = async (agentId, opts = {}) => {
  const user = opts.user || 'system';
  if (!opts.files) {
    try { await refreshHelperConfig(agentId); } catch (err) { console.warn('[nginx-manager] helper config:', err.message); }
    try { refreshDefaultServer(agentId); } catch (err) { console.warn('[nginx-manager] default server:', err.message); }
  }
  const result = await rawConfigApply(agentId, opts);
  const agent = store.findAgent(agentId);
  const label = opts.label || (opts.files ? 'Certificate deployment' : 'Apply');
  if (result.success && !result.unchanged) {
    history.record(agentId, store.currentFiles(store.readState(agentId)), { cause: 'apply', user, label, result: 'ok' });
  }
  if (!result.unchanged) {
    audit.record({ user, action: opts.files ? 'certificate.deploy' : 'config.apply', agent: agent && agent.name, result: result.success ? 'ok' : 'failed', detail: opts.label || result.output || '' });
  }
  if (!result.success && agent) {
    alerts.notify({ event: 'apply_failed', key: `apply_failed:${agentId}`, server: agent.name, group: agent.group || null,
      title: `Config apply failed on ${agent.name}`, message: `${label} by ${user} failed — the server keeps its previous config.\n${result.output || ''}` }).catch(() => {});
  }
  return result;
};

// Multer — cert file uploads (PEM/CRT/KEY, max 1 MB each), kept in memory
const certUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1 * 1024 * 1024 } });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function publicAgent(a) {
  const { tokenHash, ...rest } = a;
  const st = store.readState(a.id);
  return {
    ...rest,
    online: mp.isOnline(a.id),
    pendingChanges: Object.keys(st.draft).length,
    health: mp.health.get(a.id) || [],
  };
}

function requireAgent(req, res) {
  const agent = store.findAgent(req.params.id);
  if (!agent) res.status(404).json({ error: 'Server not found' });
  return agent;
}

// The nginx main config dir for an agent, e.g. /etc/nginx
function nginxDir(agent) {
  const st = store.readState(agent.id);
  if (st.configPath) return path.dirname(st.configPath);
  return agent.nginxConfigPath || '/etc/nginx';
}

function confDir(agent) { return path.posix.join(nginxDir(agent), 'conf.d'); }

function siteConfPath(agent, site) {
  return path.posix.join(confDir(agent), `site_${site.name.replace(/[^a-zA-Z0-9_-]/g, '_')}.conf`);
}

// Absolute, normalized, no traversal — the agent additionally enforces allowed_directories.
function cleanRemotePath(p) {
  if (typeof p !== 'string' || !p.startsWith('/')) return null;
  const norm = path.posix.normalize(p);
  if (norm !== p || norm.endsWith('/') || norm.includes('\0')) return null;
  return norm;
}

function fileStatus(st, name) {
  const d = st.draft[name];
  if (!d) return 'live';
  if (d.deleted) return 'deleted';
  return store.currentFile(st, name) ? 'modified' : 'added';
}

// private keys and htpasswd files: never shown in diffs, and only to admins in the editor
function isSecret(name, content) {
  return /PRIVATE KEY-----/.test(content || '') || /\.htpasswd$|privkey|\.key$/i.test(name);
}

function readFileContent(st, name) {
  const d = st.draft[name];
  const entry = d && !d.deleted ? d : store.currentFile(st, name);
  if (!entry) return null;
  const buf = store.getBlob(entry.hash);
  return buf ? buf.toString('utf8') : undefined;
}

function setupInfo(agent, req, token) {
  const host = process.env.AGENT_CONNECT_HOST || req.hostname;
  const allowed = ['/etc/nginx', '/usr/local/etc/nginx', '/usr/share/nginx/modules',
    '/var/run/nginx', '/var/log/nginx', '/etc/letsencrypt', '/etc/ssl/nginx'];
  const agentConf = [
    'log:',
    '  level: info',
    '  path: /var/log/nginx-agent/',
    '',
    'allowed_directories:',
    ...allowed.map(d => `  - ${d}`),
    '',
    'features:',
    '  - configuration',
    '  - certificates',
    '  - file-watcher',
    '',
    'command:',
    '  server:',
    `    host: ${host}`,
    `    port: ${GRPC_PORT}`,
    '    type: grpc',
    '  auth:',
    '    tokenpath: /etc/nginx-agent/manager.token',
    '  tls:',
    '    ca: /etc/nginx-agent/manager-ca.pem',
    '    skip_verify: false',
  ].join('\n') + '\n';

  // Without a token (only its hash is stored) the script refuses to run rather than
  // installing a placeholder the manager will reject.
  const tokenLines = token
    ? [`TOKEN='${token}'`]
    : ['# No token in this copy of the script — click "New Token" in nginx-manager, or run with TOKEN=<token> set',
       'TOKEN="${TOKEN:-}"',
       '[ -n "$TOKEN" ] || { echo "ERROR: no agent token. In nginx-manager click New Token and use that script." >&2; exit 1; }'];

  const script = [
    '#!/bin/bash',
    '# Run as root on the nginx server',
    'set -euo pipefail',
    ...tokenLines,
    '',
    '# 1. Install NGINX Agent v3 from the nginx.org repo (uses the existing nginx.org signing key)',
    'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://packages.nginx.org/nginx-agent/debian $(. /etc/os-release && echo $VERSION_CODENAME) agent" \\',
    '  > /etc/apt/sources.list.d/nginx-agent.list',
    'apt-get update && apt-get install -y nginx-agent',
    '',
    '# 2. Token + manager CA',
    `install -m 600 /dev/null /etc/nginx-agent/manager.token && printf '%s' "$TOKEN" > /etc/nginx-agent/manager.token`,
    "cat > /etc/nginx-agent/manager-ca.pem <<'EOF'",
    tls.ca.trim(),
    'EOF',
    '',
    '# 3. Agent config',
    "cat > /etc/nginx-agent/nginx-agent.conf <<'EOF'",
    agentConf.trimEnd(),
    'EOF',
    '',
    'systemctl enable --now nginx-agent && systemctl restart nginx-agent',
  ].join('\n') + '\n';

  return { host, port: GRPC_PORT, ca: tls.ca, agentConf, script, tokenIncluded: !!token };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app    = express();
const server = http.createServer(app);
const io     = new Server(server);

if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY);

const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 24 * 60 * 60 * 1000,
  },
});

app.use(express.json({ limit: '10mb' }));
app.use(sessionMiddleware);
app.use(roleGate);
app.use(auditTrail);
app.use(express.static(path.join(__dirname, 'public')));

// Re-checks the user on every request, so removing or demoting someone takes effect at once.
function sessionUser(req) {
  const s = req.session;
  if (!s || !s.authenticated || !s.user) return null;
  if (s.user.source) {
    // directory user: role fixed at sign-in; disabling the provider (or a same-named local account) ends the session
    const cfg = extAuth.settings[s.user.source];
    if (!cfg || !cfg.enabled || users.exists(s.user.username)) return null;
    return { username: s.user.username, role: s.user.role, source: s.user.source };
  }
  return users.lookup(s.user.username);
}

function requireAuth(req, res, next) {
  const u = sessionUser(req);
  if (u) { req.user = u; return next(); }
  if (req.session && req.session.authenticated) req.session.destroy(() => {});
  res.status(401).json({ error: 'Unauthorised' });
}

// Role needed per request: viewers read, operators change config, admins manage the manager itself.
const ADMIN_ONLY = [
  [/^\/api\/users/, 'ALL'], [/^\/api\/alerts/, 'ALL'], [/^\/api\/audit/, 'ALL'], [/^\/api\/auth-settings/, 'ALL'],
  [/^\/api\/branding/, 'WRITE'], [/^\/api\/agents\/?$/, 'WRITE'], [/^\/api\/agents\/[^/]+\/?$/, 'DELETE'],
  [/^\/api\/agents\/[^/]+\/token$/, 'WRITE'], [/^\/api\/agents\/[^/]+\/setup$/, 'ALL'],
  [/^\/api\/health\/settings/, 'WRITE'],
];
const SELF_SERVICE = new Set(['/api/login', '/api/logout', '/api/me/password']);

function requiredRole(req) {
  const p = req.path, m = req.method;
  const write = !['GET', 'HEAD', 'OPTIONS'].includes(m);
  for (const [re, when] of ADMIN_ONLY) {
    if (re.test(p) && (when === 'ALL' || (when === 'WRITE' && write) || when === m)) return 'admin';
  }
  return write ? 'operator' : 'viewer';
}

function roleGate(req, res, next) {
  if (!req.path.startsWith('/api/') || SELF_SERVICE.has(req.path)) return next();
  const u = sessionUser(req);
  if (!u) return next();                                   // routes without requireAuth are public; the rest 401
  const need = requiredRole(req);
  if (!atLeast(u.role, need)) return res.status(403).json({ error: `Your role (${u.role}) can't do this — needs ${need}` });
  next();
}

// Audit every change made through the API (bodies are never logged — they can carry secrets).
function auditTrail(req, res, next) {
  if (!req.path.startsWith('/api/') || ['GET', 'HEAD', 'OPTIONS'].includes(req.method) || SELF_SERVICE.has(req.path)) return next();
  res.on('finish', () => {
    const u = sessionUser(req);
    if (!u) return;
    const route = req.route ? req.baseUrl + req.route.path : req.path;
    const agent = req.params && req.params.id ? store.findAgent(req.params.id) : null;
    audit.record({
      user: u.username, ip: req.ip, action: `${req.method} ${route}`,
      agent: agent ? agent.name : undefined,
      target: req.params && (req.params.name || req.params.siteId || req.params.snap || req.params.username) || undefined,
      result: res.statusCode < 400 ? 'ok' : `HTTP ${res.statusCode}`,
    });
  });
  next();
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
const loginFailures = new Map();   // ip -> { count, until }
const MAX_FAILURES = 10, LOCKOUT_MS = 15 * 60 * 1000;

app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  const f = loginFailures.get(ip);
  if (f && f.count >= MAX_FAILURES && f.until > Date.now()) {
    return res.status(429).json({ error: 'Too many attempts — try again later' });
  }
  const username = String((req.body && req.body.username) || 'admin').trim().toLowerCase();
  const password = req.body && req.body.password;
  let user = await users.verify(username, password);
  let ext = null;
  // directory sign-in only for names that aren't local accounts (no ambiguity, no fallback on a wrong local password)
  if (!user && !users.exists(username) && extAuth.enabled()) {
    ext = await extAuth.authenticate(username, password).catch(e => ({ ok: false, reason: e.message }));
    if (ext.ok) {
      const canonical = ext.username || username;
      if (users.exists(canonical)) ext = { ok: false, reason: `a local account named ${canonical} exists — sign in with it` };
      else {
        user = { username: canonical, role: ext.role, source: ext.source };
        users.recordExternal({ username: canonical, role: ext.role, source: ext.source, displayName: ext.displayName });
      }
    }
  }
  if (!user) {
    const cur = f && f.until > Date.now() ? f : { count: 0 };
    loginFailures.set(ip, { count: cur.count + 1, until: Date.now() + LOCKOUT_MS });
    audit.record({ user: username.slice(0, 64), ip, action: 'login', result: 'failed', detail: ext && ext.reason ? `${(ext.tried || []).map(t => t.source).join('/') || 'directory'}: ${ext.reason}` : undefined });
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  loginFailures.delete(ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.authenticated = true;
    req.session.user = user.source ? { username: user.username, role: user.role, source: user.source } : { username: user.username };
    audit.record({ user: user.username, ip, action: 'login', result: 'ok', detail: user.source ? `via ${user.source} as ${user.role}` : undefined });
    res.json({ ok: true, user });
  });
});
app.post('/api/logout', (req, res) => {
  const u = sessionUser(req);
  if (u) audit.record({ user: u.username, ip: req.ip, action: 'logout', result: 'ok' });
  req.session.destroy(() => res.json({ ok: true }));
});

app.post('/api/me/password', requireAuth, async (req, res) => {
  const { current, password } = req.body || {};
  if (req.user.builtin) return res.status(400).json({ error: 'The built-in admin password is set with ADMIN_PASSWORD in .env' });
  if (req.user.source) return res.status(400).json({ error: `Your password is managed by the ${req.user.source.toUpperCase()} directory` });
  if (!(await users.verify(req.user.username, current))) return res.status(403).json({ error: 'Current password is wrong' });
  try { users.update(req.user.username, { password }); } catch (err) { return sendError(res, err); }
  audit.record({ user: req.user.username, ip: req.ip, action: 'user.password', target: req.user.username, result: 'ok' });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Users (admin)
// ---------------------------------------------------------------------------
app.get('/api/users', requireAuth, (req, res) => res.json(users.list()));
app.post('/api/users', requireAuth, (req, res) => {
  try { res.json(users.create(req.body || {})); } catch (err) { sendError(res, err); }
});
app.put('/api/users/:username', requireAuth, (req, res) => {
  const { role, password } = req.body || {};
  if (req.params.username === req.user.username && role && role !== req.user.role) return res.status(400).json({ error: "You can't change your own role" });
  try { res.json(users.update(req.params.username, { role, password: password || undefined })); } catch (err) { sendError(res, err); }
});
app.delete('/api/users/:username', requireAuth, (req, res) => {
  if (req.params.username === req.user.username) return res.status(400).json({ error: "You can't remove yourself" });
  try { users.remove(req.params.username); res.json({ ok: true }); } catch (err) { sendError(res, err); }
});
// Directory sign-in (admin): LDAP / AD and RADIUS
app.get('/api/auth-settings', requireAuth, (req, res) => res.json(extAuth.view()));
app.put('/api/auth-settings', requireAuth, (req, res) => {
  try { res.json(extAuth.update(req.body || {})); } catch (err) { sendError(res, err); }
});
// try a sign-in without creating a session — shows each step so misconfiguration is easy to spot
app.post('/api/auth-settings/test', requireAuth, async (req, res) => {
  const { username, password, source } = req.body || {};
  const r = await extAuth.authenticate(String(username || '').trim().toLowerCase(), password, { only: source || undefined }).catch(e => ({ ok: false, reason: e.message }));
  audit.record({ user: req.user.username, ip: req.ip, action: 'auth.test', target: String(username || '').slice(0, 64), result: r.ok ? 'ok' : 'failed', detail: r.ok ? `${r.source} → ${r.role}` : r.reason });
  res.json({ ok: r.ok, role: r.role || null, source: r.source || null, reason: r.reason || null,
    tried: (r.tried || []).map(t => ({ source: t.source, ok: t.ok, role: t.role, reason: t.reason, dn: t.dn, groups: t.groups, trace: t.trace })) });
});

app.get('/api/audit', requireAuth, (req, res) => {
  res.json(audit.query({ limit: Math.min(parseInt(req.query.limit, 10) || 200, 2000), user: req.query.user, agent: req.query.agent, action: req.query.action, q: req.query.q }));
});
// ---------------------------------------------------------------------------
// Branding — app name, login text, logo (public read: the login screen needs it)
// ---------------------------------------------------------------------------
const logoUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: branding.MAX_LOGO_BYTES + 1 } });

app.get('/api/branding', (req, res) => res.json(branding.publicView()));

app.get('/branding/logo', (req, res) => {
  const f = branding.logoFile();
  if (!f) return res.status(404).end();
  res.set({
    'Content-Type': f.mime,
    'Cache-Control': 'public, max-age=86400',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'",
  });
  res.sendFile(f.path);
});

app.put('/api/branding', requireAuth, (req, res) => {
  try {
    const out = branding.updateText(req.body || {});
    io.emit('branding');
    res.json(out);
  } catch (err) { res.status(err.status || 400).json({ error: err.message }); }
});

app.post('/api/branding/logo', requireAuth, (req, res) => {
  logoUpload.single('logo')(req, res, err => {
    if (err) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Logo must be 512 KB or smaller' : err.message });
    try {
      const out = branding.setLogo(req.file && req.file.buffer);
      io.emit('branding');
      res.json(out);
    } catch (e) { res.status(e.status || 400).json({ error: e.message }); }
  });
});

app.delete('/api/branding/logo', requireAuth, (req, res) => {
  const out = branding.clearLogo();
  io.emit('branding');
  res.json(out);
});

app.post('/api/branding/reset', requireAuth, (req, res) => {
  const out = branding.reset();
  io.emit('branding');
  res.json(out);
});

app.get('/api/me', (req, res) => {
  const u = sessionUser(req);
  res.json({ authenticated: !!u, user: u });
});

// ---------------------------------------------------------------------------
// Servers (manual add only — agents with unknown tokens are rejected)
// ---------------------------------------------------------------------------
const EDITABLE_AGENT_FIELDS = ['name', 'group', 'description', 'nginxConfigPath'];

function pickAgentFields(body) {
  const out = {};
  for (const k of EDITABLE_AGENT_FIELDS) {
    if (body[k] !== undefined) out[k] = String(body[k]).trim();
  }
  if (out.nginxConfigPath !== undefined && !cleanRemotePath(out.nginxConfigPath)) delete out.nginxConfigPath;
  return out;
}

app.get('/api/agents', requireAuth, (req, res) => {
  res.json(store.readAgents().map(publicAgent));
});

app.post('/api/agents', requireAuth, (req, res) => {
  const fields = pickAgentFields(req.body || {});
  if (!fields.name) return res.status(400).json({ error: 'name required' });
  const token = store.newToken();
  const agent = {
    id: uuidv4(),
    name: fields.name,
    group: fields.group || '',
    description: fields.description || '',
    nginxConfigPath: fields.nginxConfigPath || '/etc/nginx',
    tokenHash: store.hashToken(token),
    createdAt: new Date().toISOString(),
  };
  const agents = store.readAgents();
  agents.push(agent);
  store.writeAgents(agents);
  io.emit('agents');
  res.json({ ...publicAgent(agent), token, setup: setupInfo(agent, req, token) });
});

app.put('/api/agents/:id', requireAuth, (req, res) => {
  const fields = pickAgentFields(req.body || {});
  if (fields.name === '') delete fields.name;
  const agent = store.updateAgent(req.params.id, fields);
  if (!agent) return res.status(404).json({ error: 'Not found' });
  io.emit('agents');
  res.json(publicAgent(agent));
});

app.delete('/api/agents/:id', requireAuth, (req, res) => {
  const agents = store.readAgents();
  const remaining = agents.filter(a => a.id !== req.params.id);
  if (remaining.length === agents.length) return res.status(404).json({ error: 'Not found' });
  store.writeAgents(remaining);
  store.removeAgentData(req.params.id);
  usage.forget(req.params.id);
  history.forget(req.params.id);
  healthState.forget(req.params.id);
  const call = mp.streams.get(req.params.id);
  if (call) { try { call.end(); } catch {} mp.streams.delete(req.params.id); }
  io.emit('agents');
  res.json({ ok: true });
});

app.post('/api/agents/:id/token', requireAuth, (req, res) => {
  const token = store.newToken();
  const agent = store.updateAgent(req.params.id, { tokenHash: store.hashToken(token) });
  if (!agent) return res.status(404).json({ error: 'Not found' });
  const call = mp.streams.get(agent.id);
  if (call) { try { call.end(); } catch {} mp.streams.delete(agent.id); }
  io.emit('agents');
  res.json({ token, setup: setupInfo(agent, req, token) });
});

app.get('/api/agents/:id/setup', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(setupInfo(agent, req, null));
});

app.get('/api/agents/:id/status', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const st = store.readState(agent.id);
  res.json({
    ...publicAgent(agent),
    instanceId: st.instanceId,
    configPath: st.configPath,
    fileCount: Object.keys(st.live).length,
  });
});

// ---------------------------------------------------------------------------
// Groups — optional keepalived/VRRP virtual IP per group, watched by VipMonitor
// ---------------------------------------------------------------------------
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function groupList() {
  const settings = store.readGroups();
  const names = new Set([...Object.keys(settings), ...store.readAgents().map(a => (a.group || '').trim()).filter(Boolean)]);
  return [...names].map(name => ({
    name, vip: (settings[name] || {}).vip || '', port: (settings[name] || {}).port || 443,
    drift: (driftState.get(name) || {}).count || 0,
  }));
}

const vipMonitor = new VipMonitor({
  getGroups: groupList,
  getMembers: name => store.readAgents().filter(a => (a.group || '').trim() === name)
    .map(a => ({ id: a.id, name: a.name, address: a.address || null })),
});

app.get('/api/groups', requireAuth, (req, res) => {
  res.json(groupList().map(g => ({ ...g, status: vipMonitor.status.get(g.name) || null })));
});

// Set or clear a group's VIP: { vip: "192.0.2.50" | "", port?: 443 }
app.put('/api/groups/:name', requireAuth, async (req, res) => {
  const name = String(req.params.name).trim();
  if (!name) return res.status(400).json({ error: 'group name required' });
  const vip = String((req.body && req.body.vip) || '').trim();
  const port = parseInt((req.body && req.body.port) || 443, 10);
  if (vip && !IPV4.test(vip)) return res.status(400).json({ error: 'VIP must be an IPv4 address' });
  if (!(port > 0 && port < 65536)) return res.status(400).json({ error: 'port must be 1-65535' });
  const groups = store.readGroups();
  if (vip) groups[name] = { vip, port };
  else delete groups[name];
  store.writeGroups(groups);
  if (vip) await vipMonitor.check({ name, vip, port });
  else await vipMonitor.tick();
  io.emit('groups');
  res.json({ name, vip, port, status: vipMonitor.status.get(name) || null });
});

// Rename a group: moves its members and its VIP setting
app.post('/api/groups/:name/rename', requireAuth, (req, res) => {
  const from = String(req.params.name).trim();
  const to = String((req.body && req.body.name) || '').trim();
  if (!from || !to) return res.status(400).json({ error: 'name required' });
  const agents = store.readAgents();
  for (const a of agents) if ((a.group || '').trim() === from) a.group = to;
  store.writeAgents(agents);
  const groups = store.readGroups();
  if (groups[from]) { groups[to] = groups[from]; delete groups[from]; }
  store.writeGroups(groups);
  const st = vipMonitor.status.get(from);
  if (st) { vipMonitor.status.delete(from); vipMonitor.status.set(to, st); }
  io.emit('agents');
  io.emit('groups');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Config files (live from the agent + staged draft)
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/files', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const st = store.readState(agent.id);
  const names = new Set([...Object.keys(st.live), ...Object.keys(st.pinned), ...Object.keys(st.draft)]);
  const files = [...names].sort().map(name => {
    const d = st.draft[name];
    const e = d && !d.deleted ? d : store.currentFile(st, name);
    return {
      name,
      size: e ? e.size : 0,
      modified: e ? e.modifiedTime : null,
      status: fileStatus(st, name),
      isCert: !!(e && e.certificateMeta),
      isKey: !!(e && e.pin && !st.live[name]) && /key|priv/i.test(name),
      pinned: !!st.pinned[name] && !st.live[name],
      synced: !!(e && store.hasBlob(e.hash)),
    };
  });
  res.json({ instanceId: st.instanceId, configPath: st.configPath, confDir: confDir(agent), files });
});

app.get('/api/agents/:id/file', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const name = cleanRemotePath(req.query.path);
  if (!name) return res.status(400).json({ error: 'absolute path required' });
  const st = store.readState(agent.id);
  const content = readFileContent(st, name);
  if (content === null) return res.status(404).json({ error: 'File not found' });
  if (content === undefined) return res.status(409).json({ error: 'Contents not synced from the agent yet — run Sync' });
  if (isSecret(name, content) && req.user.role !== 'admin') return res.status(403).json({ error: 'Private keys and password files are visible to admins only' });
  res.json({ name, content, status: fileStatus(st, name) });
});

app.put('/api/agents/:id/file', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const name = cleanRemotePath(req.query.path);
  if (!name) return res.status(400).json({ error: 'absolute path required' });
  const { content } = req.body || {};
  if (typeof content !== 'string') return res.status(400).json({ error: 'content required' });
  const st = store.stageFile(agent.id, name, content);
  io.emit('files', { agentId: agent.id });
  res.json({ ok: true, name, status: fileStatus(st, name) });
});

app.delete('/api/agents/:id/file', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const name = cleanRemotePath(req.query.path);
  if (!name) return res.status(400).json({ error: 'absolute path required' });
  store.stageDelete(agent.id, name);
  io.emit('files', { agentId: agent.id });
  res.json({ ok: true });
});

app.post('/api/agents/:id/discard', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const st = store.readState(agent.id);
  const only = req.body && req.body.path ? cleanRemotePath(req.body.path) : null;
  if (only) delete st.draft[only];
  else st.draft = {};
  store.writeState(agent.id, st);
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

app.post('/api/agents/:id/apply', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(await mp.configApply(agent.id, { user: req.user.username, label: req.body && req.body.label }));
});

app.post('/api/agents/:id/sync', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(await mp.configUpload(agent.id));
});

// ---------------------------------------------------------------------------
// Live views derived from what the agent reports (no scanning / importing)
// ---------------------------------------------------------------------------
// Parse every nginx .conf file in the desired file set (live + pending edits).
// Returns [{ path, status, sites: [parsed server blocks] }] — re-derived on each call,
// so the Builder and Certificates tabs always reflect the agent's latest overview.
function parsedConfFiles(agentId) {
  const st = store.readState(agentId);
  const desired = store.desiredFiles(st);
  const agent = store.findAgent(agentId);
  const streamPrefix = streams.streamDir(agent ? nginxDir(agent) : '/etc/nginx') + '/';   // stream {} servers aren't http sites
  const out = [];
  for (const name of Object.keys(desired).sort()) {
    if (!name.endsWith('.conf') || desired[name].certificateMeta || name.startsWith(streamPrefix)) continue;
    const content = readFileContent(st, name);
    if (typeof content !== 'string') continue;
    let sites = [];
    try { sites = parseNginxConf(path.basename(name), content); } catch {}
    out.push({ path: name, status: fileStatus(st, name), sites });
  }
  return { st, desired, files: out };
}

function builderSites(agentId) {
  return store.readSites(agentId).filter(s => !s.importedFrom);
}

// Every certificate nginx config references (ssl_certificate / ssl_certificate_key),
// plus uploads staged through the UI that nothing references yet.
function deriveCerts(agentId) {
  const { st, desired, files } = parsedConfFiles(agentId);
  const byPath = new Map();
  const entry = certPath => {
    if (!byPath.has(certPath)) {
      byPath.set(certPath, { id: certPath, certPath, keyPaths: new Set(), sites: new Set(), files: new Set() });
    }
    return byPath.get(certPath);
  };
  for (const f of files) {
    for (const s of f.sites) {
      if (!s.certFile) continue;
      const e = entry(s.certFile);
      if (s.keyFile) e.keyPaths.add(s.keyFile);
      e.sites.add(s.serverName ? s.serverName.split(/\s+/)[0] : s.name);
      e.files.add(f.path);
    }
  }
  for (const m of certManager.list().filter(c => c.targets.includes(agentId))) {
    const e = entry(m.certPath);
    e.keyPaths.add(m.keyPath);
    e.managed = { id: m.id, name: m.name, source: m.source };
  }
  const uploads = store.readCerts(agentId).filter(c => c.uploaded);
  for (const u of uploads) {
    const e = entry(u.remoteCertPath);
    e.keyPaths.add(u.remoteKeyPath);
    e.uploadLabel = u.label;
    e.chainPath = u.remoteChainPath || null;
  }
  return [...byPath.values()].map(e => {
    const meta = desired[e.certPath] ? desired[e.certPath].certificateMeta || null : null;
    const keyPath = [...e.keyPaths][0] || null;
    const dirName = path.basename(path.dirname(e.certPath));
    return {
      id: e.id,
      label: e.uploadLabel || (e.managed && e.managed.name) || (meta && meta.subject) || (dirName !== 'ssl' && dirName !== 'certs' ? dirName : path.basename(e.certPath)),
      managed: e.managed || null,
      remoteCertPath: e.certPath,
      remoteKeyPath: keyPath,
      remoteChainPath: e.chainPath || null,
      certificateMeta: meta,
      usedBy: [...e.sites].sort(),
      referencedIn: [...e.files].sort(),
      inUse: e.sites.size > 0,
      uploaded: !!e.uploadLabel,
      onServer: !!store.currentFile(st, e.certPath),
      pending: [e.certPath, keyPath, e.chainPath].some(p => p && st.draft[p]),
    };
  }).sort((a, b) => a.label.localeCompare(b.label));
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/certs', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(deriveCerts(agent.id));
});

// Upload a cert+key pair — staged as files at the remote paths, pushed with Apply
app.post('/api/agents/:id/certs', requireAuth,
  certUpload.fields([
    { name: 'certFile', maxCount: 1 },
    { name: 'keyFile',  maxCount: 1 },
    { name: 'chainFile', maxCount: 1 },
  ]),
  (req, res) => {
    const agent = requireAgent(req, res); if (!agent) return;
    const { label } = req.body;
    const remoteCertPath  = cleanRemotePath(req.body.remoteCertPath);
    const remoteKeyPath   = cleanRemotePath(req.body.remoteKeyPath);
    const remoteChainPath = req.body.remoteChainPath ? cleanRemotePath(req.body.remoteChainPath) : null;
    const file = n => req.files && req.files[n] && req.files[n][0];

    if (!label) return res.status(400).json({ error: 'label required' });
    if (!remoteCertPath || !remoteKeyPath) return res.status(400).json({ error: 'absolute remote cert and key paths required' });
    if (!file('certFile') || !file('keyFile')) return res.status(400).json({ error: 'certificate and key files required' });
    if (req.body.remoteChainPath && !remoteChainPath) return res.status(400).json({ error: 'chain path must be absolute' });

    // pinned: the agent never reports keys (or certs nothing references yet) back
    store.stageFile(agent.id, remoteCertPath, file('certFile').buffer, '0644', { pin: true });
    store.stageFile(agent.id, remoteKeyPath,  file('keyFile').buffer,  '0600', { pin: true });
    if (file('chainFile') && remoteChainPath) store.stageFile(agent.id, remoteChainPath, file('chainFile').buffer, '0644', { pin: true });

    // Remember uploads so they're listed (and selectable in the Builder) before any
    // config references them.
    const certs = store.readCerts(agent.id).filter(c => c.remoteCertPath !== remoteCertPath);
    certs.push({
      id: remoteCertPath, label,
      remoteCertPath, remoteKeyPath,
      remoteChainPath: file('chainFile') ? remoteChainPath : null,
      uploaded: true,
      createdAt: new Date().toISOString(),
    });
    store.writeCerts(agent.id, certs);
    io.emit('files', { agentId: agent.id });
    io.emit('agents');
    res.json(deriveCerts(agent.id).find(c => c.id === remoteCertPath));
  }
);

// Forget an uploaded cert that no config uses. If its files were never applied the
// staged upload is dropped; if they are on the server they are left in place.
app.delete('/api/agents/:id/certs', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const certPath = cleanRemotePath(req.query.path);
  const cert = certPath && deriveCerts(agent.id).find(c => c.id === certPath);
  if (!cert || !cert.uploaded) return res.status(404).json({ error: 'Uploaded cert not found' });
  if (cert.inUse) return res.status(409).json({ error: `In use by ${cert.usedBy.join(', ')} — remove it from those configs first` });
  const st = store.readState(agent.id);
  for (const p of [cert.remoteCertPath, cert.remoteKeyPath, cert.remoteChainPath]) {
    if (p && st.draft[p] && !store.currentFile(st, p)) delete st.draft[p];
  }
  store.writeState(agent.id, st);
  store.writeCerts(agent.id, store.readCerts(agent.id).filter(c => c.remoteCertPath !== certPath));
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Remote logs — request log streamed by nginx (syslog), keepalived via a forwarder unit
// ---------------------------------------------------------------------------
// The manager address an agent should send syslog to: LOG_RECEIVER_HOST, else the local
// address the kernel would use to reach that agent (no packet is sent).
function receiverAddressFor(agent) {
  if (process.env.LOG_RECEIVER_HOST) return Promise.resolve(process.env.LOG_RECEIVER_HOST);
  if (!agent.address) return Promise.resolve(process.env.AGENT_CONNECT_HOST || null);
  return new Promise(resolve => {
    const sock = dgram.createSocket(agent.address.includes(':') ? 'udp6' : 'udp4');
    const done = v => { try { sock.close(); } catch {} resolve(v); };
    sock.on('error', () => done(process.env.AGENT_CONNECT_HOST || null));
    sock.connect(9, agent.address, () => done(sock.address().address));
  });
}

function mainConfPath(agent) {
  const st = store.readState(agent.id);
  return st.configPath || path.posix.join(nginxDir(agent), 'nginx.conf');
}

// nginx.conf has the stream {} block nginx-manager added (which includes the stream session log)
function streamLogWired(st, agent) {
  const main = readFileContent(st, mainConfPath(agent));
  return typeof main === 'string' && main.includes('nginx-manager/remote-stream-log');
}

function remoteLogWant(st, agent, receiver) {
  return logrx.remoteLogFiles(nginxDir(agent), receiver, LOG_PORT, { stream: streamLogWired(st, agent) });
}

async function remoteLogStatus(agent) {
  const st = store.readState(agent.id);
  const desired = store.desiredFiles(st);
  const paths = logrx.remoteLogPaths(nginxDir(agent));
  const receiver = await receiverAddressFor(agent);
  const want = receiver && LOG_PORT ? remoteLogWant(st, agent, receiver) : null;
  const enabled = !!desired[paths.conf];
  const statuses = [paths.conf, paths.inc, paths.streamInc].map(p => (desired[p] ? fileStatus(st, p) : (st.draft[p] && st.draft[p].deleted ? 'deleted' : null)));
  return {
    available: !!LOG_PORT,
    port: LOG_PORT,
    receiver,
    enabled,
    pending: statuses.some(x => x && x !== 'live'),
    upToDate: !enabled || !want || Object.entries(want).every(([p, text]) => readFileContent(st, p) === text),
    files: paths,
    keepalivedScript: receiver && LOG_PORT ? logrx.keepalivedForwarderScript(receiver, LOG_PORT) : null,
    stats: logReceiver.stats(agent.id),
  };
}

app.get('/api/agents/:id/remote-logs', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(await remoteLogStatus(agent));
});

// Stages (or removes) the nginx logging files; the UI then applies them like any other edit.
app.post('/api/agents/:id/remote-logs', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  if (!LOG_PORT) return res.status(409).json({ error: 'The log receiver is disabled (LOG_RECEIVER_PORT=off)' });
  const dir = nginxDir(agent);
  const paths = logrx.remoteLogPaths(dir);
  const st = store.readState(agent.id);
  if (req.body && req.body.enabled) {
    const receiver = await receiverAddressFor(agent);
    if (!receiver) return res.status(409).json({ error: "Can't work out the manager's address for this server — set LOG_RECEIVER_HOST" });
    for (const [p, text] of Object.entries(remoteLogWant(st, agent, receiver))) {
      if (readFileContent(st, p) !== text) store.stageFile(agent.id, p, text);
    }
  } else {
    for (const p of [paths.conf, paths.inc, paths.streamInc]) {
      if (store.currentFile(st, p)) store.stageDelete(agent.id, p);
      else if (st.draft[p]) { const s2 = store.readState(agent.id); delete s2.draft[p]; store.writeState(agent.id, s2); }
    }
  }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json(await remoteLogStatus(agent));
});

app.get('/api/agents/:id/logs', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const kind = req.query.kind === 'keepalived' ? 'keepalived' : 'access';
  const limit = Math.min(parseInt(req.query.limit, 10) || 1000, 5000);
  res.json({ kind, entries: logReceiver.entries(agent.id, kind, limit), stats: logReceiver.stats(agent.id) });
});

app.delete('/api/agents/:id/logs', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  logReceiver.clear(agent.id, req.query.kind === 'keepalived' ? 'keepalived' : 'access');
  res.json({ ok: true });
});


// ---------------------------------------------------------------------------
// Config history & rollback (lib/history)
// ---------------------------------------------------------------------------
function blobText(hash) { const b = hash && store.getBlob(hash); return b ? b.toString('utf8') : null; }

// unified diffs between two file maps; secrets are never shown
function fileDiffs(a, b, names) {
  return names.map(name => {
    const x = a[name], y = b[name];
    const tx = x ? blobText(x.hash) : '', ty = y ? blobText(y.hash) : '';
    if (isSecret(name, tx) || isSecret(name, ty)) return { name, secret: true, changed: !x || !y || x.hash !== y.hash };
    if (tx === null || ty === null) return { name, missing: true };
    return { name, diff: unifiedDiff(tx, ty) };
  });
}

// Snapshot the current file set whenever the agent reports a change (edits made on the server
// itself show up here too). Waits until the contents are synced and no apply is running.
const historyTimers = new Map();
function scheduleHistory(agentId, delay = 5000) {
  clearTimeout(historyTimers.get(agentId));
  historyTimers.set(agentId, setTimeout(() => {
    historyTimers.delete(agentId);
    if (mp.busy && mp.busy.has(agentId)) return scheduleHistory(agentId, 10000);
    const st = store.readState(agentId);
    const files = store.currentFiles(st);
    if (!Object.keys(files).length) return;
    if (Object.values(files).some(f => !f.unmanaged && !store.hasBlob(f.hash))) return scheduleHistory(agentId, 15000);
    const snap = history.record(agentId, files, { cause: history.list(agentId).length ? 'server' : 'baseline' });
    if (snap && snap.cause === 'server') {
      const agent = store.findAgent(agentId);
      audit.record({ user: 'server', action: 'config.changed-on-server', agent: agent && agent.name, detail: snap.changes.map(c => `${c.change} ${c.name}`).join(', ').slice(0, 500) });
    }
    if (snap) io.emit('history', { agentId });
  }, delay));
}
mp.on('files', agentId => scheduleHistory(agentId));
for (const a of store.readAgents()) scheduleHistory(a.id, 15000);

app.get('/api/agents/:id/history', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(history.summaries(agent.id));
});

// ?against=previous (default) | current
app.get('/api/agents/:id/history/:snap', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const snap = history.get(agent.id, req.params.snap);
  if (!snap) return res.status(404).json({ error: 'Snapshot not found' });
  let base, label;
  if (req.query.against === 'current') {
    const cur = store.currentFiles(store.readState(agent.id));
    base = Object.fromEntries(Object.entries(cur).filter(([, f]) => !f.unmanaged).map(([n, f]) => [n, { hash: f.hash, permissions: f.permissions }]));
    label = 'current';
  } else {
    const prev = history.previous(agent.id, snap.id);
    base = prev ? prev.files : {};
    label = prev ? prev.at : 'empty';
  }
  const changes = changesBetween(base, snap.files);
  const { files, fp, ...meta } = snap;
  res.json({ ...meta, against: label, fileCount: Object.keys(files).length, changes, diffs: fileDiffs(base, snap.files, changes.map(c => c.name)) });
});

// Stage the snapshot's file set (the user reviews and applies it like any other edit)
app.post('/api/agents/:id/history/:snap/restore', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const snap = history.get(agent.id, req.params.snap);
  if (!snap) return res.status(404).json({ error: 'Snapshot not found' });
  const missing = Object.entries(snap.files).filter(([, f]) => !store.hasBlob(f.hash)).map(([n]) => n);
  if (missing.length) return res.status(409).json({ error: `Contents missing for ${missing.join(', ')}` });
  const st = store.readState(agent.id);
  st.draft = {};
  store.writeState(agent.id, st);
  const cur = store.currentFiles(st);
  let staged = 0, removed = 0;
  for (const [name, f] of Object.entries(snap.files)) {
    const c = cur[name];
    if (!c || c.hash !== f.hash || (c.permissions || '0644') !== f.permissions) { store.stageBlob(agent.id, name, f); staged++; }
  }
  for (const [name, f] of Object.entries(cur)) {
    if (!snap.files[name] && !f.unmanaged) { store.stageDelete(agent.id, name); removed++; }
  }
  audit.record({ user: req.user.username, ip: req.ip, action: 'config.rollback.staged', agent: agent.name, target: snap.id, detail: `to ${snap.at}: ${staged} file(s) restored, ${removed} removed` });
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true, staged, removed, label: `Rollback to ${snap.at.slice(0, 16).replace('T', ' ')} UTC` });
});

// ---------------------------------------------------------------------------
// Group sync & drift (lib/groupsync)
// ---------------------------------------------------------------------------
function groupMembers(name) {
  return store.readAgents().filter(a => (a.group || '').trim() === name);
}

function memberFiles(a) {
  const files = store.currentFiles(store.readState(a.id));
  return { id: a.id, name: a.name, files };
}

function groupIgnore(name) { return ((store.readGroups()[name] || {}).ignore) || []; }

function groupDrift(name) {
  const members = groupMembers(name);
  if (members.length < 2) return { members: members.map(m => ({ id: m.id, name: m.name })), drift: [], inSync: true };
  return groupsync.compare(members.map(memberFiles), { ignore: groupIgnore(name) });
}

app.get('/api/groups/:name/drift', requireAuth, (req, res) => {
  const d = groupDrift(req.params.name);
  const pending = Object.fromEntries(groupMembers(req.params.name).map(a => [a.id, Object.keys(store.readState(a.id).draft).length]));
  res.json({ ...d, ignore: groupIgnore(req.params.name), pending });
});

app.put('/api/groups/:name/sync-settings', requireAuth, (req, res) => {
  const ignore = (Array.isArray(req.body && req.body.ignore) ? req.body.ignore : String((req.body && req.body.ignore) || '').split('\n'))
    .map(x => String(x).trim()).filter(Boolean);
  if (ignore.some(p => !p.startsWith('/') || p.length > 300)) return res.status(400).json({ error: 'Ignore patterns are absolute paths, * and ** allowed' });
  const groups = store.readGroups();
  groups[req.params.name] = { ...(groups[req.params.name] || {}), ignore };
  store.writeGroups(groups);
  runDriftCheck();
  res.json({ ok: true, ignore });
});

// diff of one file between two members
app.get('/api/groups/:name/diff', requireAuth, (req, res) => {
  const name = cleanRemotePath(req.query.file);
  const a = store.findAgent(req.query.a), b = store.findAgent(req.query.b);
  if (!name || !a || !b) return res.status(400).json({ error: 'file, a and b required' });
  const fa = store.currentFile(store.readState(a.id), name), fb = store.currentFile(store.readState(b.id), name);
  const [d] = fileDiffs(fa ? { [name]: fa } : {}, fb ? { [name]: fb } : {}, [name]);
  res.json(d);
});

async function applyMembers(ids, user, label, logTo) {
  const results = [];
  for (const id of ids) {
    const a = store.findAgent(id);
    if (!Object.keys(store.readState(id).draft).length) { results.push({ id, name: a.name, success: true, output: 'nothing to apply' }); continue; }
    if (logTo && logTo !== id) mp.log(logTo, `🔁 ${label}: applying on ${a.name}…`);
    const r = await mp.configApply(id, { user, label });
    results.push({ id, name: a.name, success: r.success, output: r.output });
    if (logTo && logTo !== id) mp.log(logTo, `${r.success ? '✅' : '❌'} ${a.name}: ${r.output || ''}`);
    if (!r.success) break;              // stop: leave the rest of the group on the known-good config
  }
  return results;
}

function stagePlans(plans) {
  for (const p of plans) {
    for (const f of p.stage) store.stageBlob(p.agentId, f.name, f);
    for (const n of p.remove) store.stageDelete(p.agentId, n);
    io.emit('files', { agentId: p.agentId });
  }
  io.emit('agents');
}

// Make the other members match a source member: { source, files?: [names], apply?: bool }
app.post('/api/groups/:name/sync', requireAuth, async (req, res) => {
  const members = groupMembers(req.params.name);
  const src = members.find(m => m.id === (req.body && req.body.source));
  if (!src) return res.status(400).json({ error: 'source must be a member of the group' });
  const targets = members.filter(m => m.id !== src.id);
  const files = Array.isArray(req.body.files) ? req.body.files.map(cleanRemotePath).filter(Boolean) : null;
  let plans;
  try { plans = groupsync.planSync(memberFiles(src), targets.map(memberFiles), { files, ignore: groupIgnore(req.params.name) }); stagePlans(plans); }
  catch (err) { return sendError(res, err); }
  audit.record({ user: req.user.username, ip: req.ip, action: 'group.sync.staged', target: req.params.name, detail: `from ${src.name}: ${plans.map(p => `${store.findAgent(p.agentId).name} +${p.stage.length}/-${p.remove.length}`).join(', ')}` });
  const out = { ok: true, plans: plans.map(p => ({ id: p.agentId, staged: p.stage.length, removed: p.remove.length })) };
  if (req.body.apply) out.results = await applyMembers(targets.map(t => t.id), req.user.username, `Group sync from ${src.name}`);
  runDriftCheck();
  res.json(out);
});

// Apply this server's pending edits here AND on the rest of its group
app.post('/api/agents/:id/apply-group', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const group = (agent.group || '').trim();
  const members = group ? groupMembers(group) : [agent];
  const others = members.filter(m => m.id !== agent.id);
  const st = store.readState(agent.id);
  if (!Object.keys(st.draft).length) return res.status(400).json({ error: 'No pending changes on this server' });
  const { plans, conflicts } = groupsync.planPropagate(
    { current: store.currentFiles(st), draft: st.draft }, others.map(memberFiles),
    { force: !!(req.body && req.body.force), ignore: groupIgnore(group) });
  if (conflicts.length) {
    return res.status(409).json({ error: 'Some files differ on other members', conflicts: conflicts.map(c => ({ ...c, server: store.findAgent(c.agentId).name })) });
  }
  try { stagePlans(plans); } catch (err) { return sendError(res, err); }
  const label = (req.body && req.body.label) || `Group apply from ${agent.name}`;
  mp.log(agent.id, `🔁 Applying to ${members.length} server(s) in ${group || 'this server'}: ${members.map(m => m.name).join(', ')}`);
  const results = await applyMembers([agent.id, ...others.map(o => o.id)], req.user.username, label, agent.id);
  runDriftCheck();
  res.json({ ok: results.every(r => r.success), results });
});

// ---------------------------------------------------------------------------
// Usage dashboard — aggregated from the streamed request log (lib/usage)
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/usage', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const group = (agent.group || '').trim();
  const members = req.query.scope === 'group' && group
    ? store.readAgents().filter(a => (a.group || '').trim() === group) : [agent];
  const st = id => store.desiredFiles(store.readState(id));
  const logging = members.map(a => ({
    id: a.id, name: a.name,
    enabled: !!st(a.id)[logrx.remoteLogPaths(nginxDir(a)).conf],
  }));
  res.json({ scope: members.length > 1 || req.query.scope === 'group' ? 'group' : 'server', group: group || null,
    servers: logging, ...usage.query(members.map(a => a.id), String(req.query.range || '24h')) });
});


// ---------------------------------------------------------------------------
// Backend health checks (run by the helper on each server — lib/health)
// ---------------------------------------------------------------------------
function agentConfTexts(agentId) {
  const st = store.readState(agentId);
  const desired = store.desiredFiles(st);
  const out = {};
  for (const n of Object.keys(desired)) {
    if (!n.endsWith('.conf') || desired[n].certificateMeta) continue;
    const t = readFileContent(st, n);
    if (typeof t === 'string') out[n] = t;
  }
  return out;
}

function healthEnabled(agent) {
  return !!store.desiredFiles(store.readState(agent.id))[health.helperPaths(nginxDir(agent)).config];
}

async function wantedHelperFiles(agent) {
  const receiver = await receiverAddressFor(agent);
  if (!receiver || !LOG_PORT) throw Object.assign(new Error("Can't work out the manager's address for this server — set LOG_RECEIVER_HOST"), { status: 409 });
  const paths = health.helperPaths(nginxDir(agent));
  return {
    [paths.config]: health.helperConfig(health.deriveTargets(agentConfTexts(agent.id)), healthSettings, { receiver, port: LOG_PORT }),
    [paths.status]: health.statusConf(),
  };
}

// Keep helper.json in step with the config being applied (targets come from the upstreams)
async function refreshHelperConfig(agentId) {
  const agent = store.findAgent(agentId);
  if (!agent || !healthEnabled(agent)) return;
  const want = await wantedHelperFiles(agent);
  const st = store.readState(agentId);
  const paths = health.helperPaths(nginxDir(agent));
  if (readFileContent(st, paths.config) !== want[paths.config]) store.stageFile(agentId, paths.config, want[paths.config], '0644', { pin: true });
}

app.get('/api/agents/:id/health', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const st = store.readState(agent.id);
  const paths = health.helperPaths(nginxDir(agent));
  const desired = store.desiredFiles(st);
  const enabled = !!desired[paths.config];
  const pending = [paths.config, paths.status].some(p => st.draft[p]);
  const targets = health.deriveTargets(agentConfTexts(agent.id));
  const view = healthState.view(agent.id);
  // the same backends as seen from the other members of the group
  const group = (agent.group || '').trim();
  const peers = group ? groupMembers(group).filter(m => m.id !== agent.id).map(m => ({ id: m.id, name: m.name, targets: healthState.view(m.id).targets })) : [];
  res.json({
    enabled, pending,
    upToDate: !enabled || readFileContent(st, paths.config) === (await wantedHelperFiles(agent).catch(() => ({})))[paths.config],
    helperVersion: health.HELPER_VERSION,
    report: view.report, status: view.status,
    defaults: healthSettings.defaults,
    targets: targets.map(t => ({ ...t, settings: healthSettings.targets[t.key] || {}, state: view.targets[t.key] || null,
      peers: peers.map(p => ({ id: p.id, name: p.name, state: p.targets[t.key] || null })) })),
    installScript: req.user.role === 'admin' ? health.helperInstallScript(HELPER_SOURCE) : null,
    files: paths,
  });
});

app.post('/api/agents/:id/health', requireAuth, async (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const paths = health.helperPaths(nginxDir(agent));
  const st = store.readState(agent.id);
  try {
    if (req.body && req.body.enabled) {
      const want = await wantedHelperFiles(agent);
      // the status listener must not collide with another server block
      const used = streams.listenPorts(Object.entries(agentConfTexts(agent.id)).filter(([n]) => n !== paths.status).map(([, t]) => t));
      if (used.includes(health.STATUS_PORT)) throw Object.assign(new Error(`Port ${health.STATUS_PORT} is already used on this server`), { status: 409 });
      store.stageFile(agent.id, paths.config, want[paths.config], '0644', { pin: true });
      if (readFileContent(st, paths.status) !== want[paths.status]) store.stageFile(agent.id, paths.status, want[paths.status]);
    } else {
      for (const p of [paths.config, paths.status]) {
        if (store.currentFile(st, p)) store.stageDelete(agent.id, p);
        else { const s2 = store.readState(agent.id); delete s2.draft[p]; store.writeState(agent.id, s2); }
      }
    }
  } catch (err) { return sendError(res, err); }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

function saveHealthSettings() {
  fs.writeFileSync(HEALTH_SETTINGS, JSON.stringify(healthSettings, null, 2), { mode: 0o600 });
}

// after a settings change, stage the new helper.json on every server that has health checks on
async function restageHelpers() {
  const changed = [];
  for (const a of store.readAgents()) {
    if (!healthEnabled(a)) continue;
    const before = Object.keys(store.readState(a.id).draft).length;
    await refreshHelperConfig(a.id).catch(() => {});
    if (Object.keys(store.readState(a.id).draft).length !== before) { changed.push(a.name); io.emit('files', { agentId: a.id }); }
  }
  io.emit('agents');
  return changed;
}

app.put('/api/health/settings', requireAuth, async (req, res) => {
  try { healthSettings = { ...healthSettings, defaults: health.validateDefaults({ ...healthSettings.defaults, ...(req.body || {}) }) }; }
  catch (err) { return sendError(res, err); }
  saveHealthSettings();
  res.json({ ok: true, defaults: healthSettings.defaults, staged: await restageHelpers() });
});

// per-backend check: { type: tcp|http, path, expect, hostHeader, tls, disabled }
app.put('/api/health/targets', requireAuth, async (req, res) => {
  const key = String((req.body && req.body.key) || '');
  if (!key || key.length > 300) return res.status(400).json({ error: 'key required' });
  try {
    const v = health.validateTargetSettings(req.body.settings || {});
    healthSettings.targets[key] = v;
    if (!Object.keys(v).length || (v.type === 'tcp' && !v.disabled)) delete healthSettings.targets[key];
  } catch (err) { return sendError(res, err); }
  saveHealthSettings();
  res.json({ ok: true, staged: await restageHelpers() });
});

healthState.on('transition', ({ agentId, key, from, to, error }) => {
  io.emit('health', { agentId });
  const agent = store.findAgent(agentId);
  if (!agent) return;
  if (to === 'down') {
    mp.log(agentId, `💔 Backend ${key} is DOWN (${error || 'failed'}) — seen from ${agent.name}`);
    alerts.notify({ event: 'backend_down', key: `backend:${agentId}:${key}`, server: agent.name, group: agent.group || null,
      title: `Backend ${key} is down (from ${agent.name})`, message: `${agent.name} can't reach ${key}: ${error || 'check failed'}.` }).catch(() => {});
  } else if (to === 'up' && from === 'down') {
    mp.log(agentId, `💚 Backend ${key} is back up`);
    alerts.notify({ event: 'backend_down', key: `backend:${agentId}:${key}`, recovery: true, server: agent.name, group: agent.group || null,
      title: `Backend ${key} recovered (from ${agent.name})`, message: `${agent.name} can reach ${key} again.` }).catch(() => {});
  }
});
let healthEmitTimer = null;
logReceiver.on('health', agentId => {     // live refresh of the Health tab, at most every 5 s
  if (healthEmitTimer) return;
  healthEmitTimer = setTimeout(() => { healthEmitTimer = null; io.emit('health', { agentId }); }, 5000);
});

// ---------------------------------------------------------------------------
// Alerts (lib/alerts) — settings, test, history; triggers are wired below
// ---------------------------------------------------------------------------
app.get('/api/alerts', requireAuth, (req, res) => res.json(alerts.view()));
app.put('/api/alerts', requireAuth, (req, res) => {
  try { res.json(alerts.update(req.body || {})); } catch (err) { sendError(res, err); }
});
app.post('/api/alerts/test', requireAuth, async (req, res) => {
  const r = await alerts.notify({ event: 'test', key: `test:${Date.now()}`, title: 'Test alert from nginx-manager',
    message: `Sent by ${req.user.username}. If you can read this, alerts are working.` });
  res.json(r);
});
app.get('/api/alerts/history', requireAuth, (req, res) => res.json(alerts.history(200)));

// --- triggers ---------------------------------------------------------------
const driftState = new Map();     // group -> { count, since, fp }
function runDriftCheck() {
  let changed = false;
  for (const g of new Set(store.readAgents().map(a => (a.group || '').trim()).filter(Boolean))) {
    if (groupMembers(g).length < 2) { if (driftState.delete(g)) changed = true; continue; }
    const d = groupDrift(g);
    const fp = d.drift.map(f => f.name).join('|');
    const prev = driftState.get(g);
    if (!d.drift.length) {
      if (prev) {
        driftState.delete(g); changed = true;
        if (prev.alerted) alerts.notify({ event: 'drift', key: `drift:${g}`, recovery: true, group: g, title: `Group ${g} is back in sync`, message: 'All members have identical config again.' }).catch(() => {});
      }
      continue;
    }
    const cur = prev && prev.fp === fp ? prev : { count: d.drift.length, since: Date.now(), fp, alerted: prev && prev.alerted };
    cur.count = d.drift.length;
    if (!prev || prev.count !== cur.count) changed = true;
    if (!cur.alerted && Date.now() - cur.since >= alerts.settings.thresholds.driftMin * 60e3) {
      cur.alerted = true;
      alerts.notify({ event: 'drift', key: `drift:${g}`, remindMin: 24 * 60, group: g, title: `Config drift in group ${g}`,
        message: `${d.drift.length} file(s) differ between ${d.members.map(m => m.name).join(' and ')}:\n${d.drift.slice(0, 20).map(f => `  ${f.name}`).join('\n')}` }).catch(() => {});
    }
    driftState.set(g, cur);
  }
  if (changed) io.emit('groups');
}

const offlineSince = new Map();
function checkOffline() {
  const mins = alerts.settings.thresholds.offlineMin;
  for (const a of store.readAgents()) {
    if (mp.isOnline(a.id)) {
      if (offlineSince.has(a.id)) {
        offlineSince.delete(a.id);
        alerts.notify({ event: 'agent_offline', key: `offline:${a.id}`, recovery: true, server: a.name, group: a.group || null,
          title: `${a.name} is back online`, message: `NGINX Agent on ${a.name} reconnected.` }).catch(() => {});
      }
      continue;
    }
    if (!a.lastSeen) continue;                               // never enrolled
    if (!offlineSince.has(a.id)) offlineSince.set(a.id, Date.now());
    if (Date.now() - offlineSince.get(a.id) >= mins * 60e3) {
      alerts.notify({ event: 'agent_offline', key: `offline:${a.id}`, remindMin: 24 * 60, server: a.name, group: a.group || null,
        title: `${a.name} is offline`, message: `NGINX Agent on ${a.name} has not been connected for ${mins}+ minutes (last seen ${a.lastSeen}). The server itself may still be serving traffic.` }).catch(() => {});
    }
  }
}

const spikeState = new Map();      // `${kind}:${agentId}` -> true while alerted
function checkSpikes() {
  const t = alerts.settings.thresholds;
  for (const a of store.readAgents()) {
    const q = usage.query([a.id], '1h');
    const recent = q.series.slice(-t.windowMin);
    const n = recent.reduce((x, p) => x + p.n, 0);
    for (const [kind, field, pct, event] of [['5xx', 'server_error', t.errorPct, 'error_spike'], ['denied', 'denied', t.deniedPct, 'denied_spike']]) {
      const k = `${kind}:${a.id}`;
      const bad = recent.reduce((x, p) => x + p[field], 0);
      const ratio = n ? (100 * bad) / n : 0;
      if (n >= t.minRequests && ratio >= pct && !spikeState.get(k)) {
        spikeState.set(k, true);
        alerts.notify({ event, key: `${event}:${a.id}`, server: a.name, group: a.group || null,
          title: `${ratio.toFixed(0)}% ${kind === '5xx' ? '5xx errors' : 'denied requests'} on ${a.name}`,
          message: `${bad} of ${n} requests in the last ${t.windowMin} minutes were ${kind === '5xx' ? 'server errors' : 'denied (401/403/407/429/444)'} (threshold ${pct}%).` }).catch(() => {});
      } else if (spikeState.get(k) && (n < t.minRequests || ratio < pct / 2)) {
        spikeState.delete(k);
        alerts.notify({ event, key: `${event}:${a.id}`, recovery: true, server: a.name, group: a.group || null,
          title: `${kind === '5xx' ? '5xx errors' : 'Denied requests'} back to normal on ${a.name}`, message: `${ratio.toFixed(1)}% over the last ${t.windowMin} minutes.` }).catch(() => {});
      }
    }
  }
}

function checkCertificates() {
  const days = alerts.settings.thresholds.certDays;
  for (const c of certManager.list()) {
    const st = c.status || {};
    if (st.state === 'error' || st.state === 'warning') {
      alerts.notify({ event: 'cert_failed', key: `certfail:${c.id}`, remindMin: 12 * 60, title: `Certificate ${c.name || c.id}: ${st.message || 'renewal failed'}`,
        message: `${st.lastError || st.message || ''}\nThe certificate manager retries automatically; the current certificate stays in place until it expires.` }).catch(() => {});
    }
  }
  for (const a of store.readAgents()) {
    const st = store.readState(a.id);
    for (const [name, f] of Object.entries(store.currentFiles(st))) {
      const na = f.certificateMeta && f.certificateMeta.notAfter;
      if (!na) continue;
      const left = (Date.parse(na) - Date.now()) / 86400e3;
      if (left <= days) {
        alerts.notify({ event: 'cert_expiring', key: `certexp:${a.id}:${name}`, remindMin: 24 * 60, server: a.name, group: a.group || null,
          title: `Certificate on ${a.name} ${left < 0 ? 'has expired' : `expires in ${Math.max(0, Math.floor(left))} day(s)`}`,
          message: `${name}\nExpires ${na}.` }).catch(() => {});
      }
    }
  }
}

function checkCves() {
  for (const a of store.readAgents()) {
    const r = cve.assess(a, agentConfigText(a.id));
    const affected = [...((r.nginx && r.nginx.findings) || []), ...((r.agent && r.agent.findings) || [])].filter(f => f.status === 'affected');
    for (const f of affected) {
      alerts.notify({ event: 'cve_new', key: `cve:${a.id}:${f.id}`, remindMin: 7 * 24 * 60, server: a.name, group: a.group || null,
        title: `${f.cves[0] || f.id} affects ${a.name} (${f.severity})`,
        message: `${f.title}\n${r.nginx ? `nginx ${r.nginx.version}` : ''}${f.fixedIn ? ` — fixed in ${f.fixedIn}` : ''}\n${f.advisory || ''}` }).catch(() => {});
    }
  }
}

setInterval(() => { try { runDriftCheck(); } catch (e) { console.warn('[nginx-manager] drift check:', e.message); } }, 60e3).unref();
setInterval(() => { try { checkOffline(); checkSpikes(); } catch (e) { console.warn('[nginx-manager] alert checks:', e.message); } }, 30e3).unref();
setInterval(() => { try { checkCertificates(); checkCves(); } catch (e) { console.warn('[nginx-manager] alert checks:', e.message); } }, 30 * 60e3).unref();
setTimeout(() => { try { runDriftCheck(); checkCertificates(); } catch {} }, 30e3).unref();
cve.on('change', () => { try { checkCves(); } catch {} });

// ---------------------------------------------------------------------------
// CVE detection (lib/cve) — nginx.org advisories + OSV for nginx-agent
// ---------------------------------------------------------------------------
function agentConfigText(agentId) {
  const st = store.readState(agentId);
  const desired = store.desiredFiles(st);
  return Object.keys(desired).filter(n => n.endsWith('.conf') && !desired[n].certificateMeta)
    .map(n => readFileContent(st, n)).filter(t => typeof t === 'string').join('\n');
}

function cveReport() {
  return {
    sources: cve.sources(),
    servers: store.readAgents().map(a => ({
      ...cve.assess(a, agentConfigText(a.id)), group: (a.group || '').trim() || null, online: mp.isOnline(a.id),
    })),
  };
}

function refreshCves(force = false) {
  return cve.refresh({ force, agentVersions: store.readAgents().map(a => a.agentVersion) });
}

app.get('/api/cve', requireAuth, (req, res) => res.json(cveReport()));
app.post('/api/cve/refresh', requireAuth, async (req, res) => {
  await refreshCves(true);
  res.json(cveReport());
});


// ---------------------------------------------------------------------------
// Unknown hosts — managed default_server catch-all (lib/defaultserver)
// ---------------------------------------------------------------------------
function defaultServerPath(agent) { return path.posix.join(confDir(agent), defaultServer.FILE); }

function planDefaultServer(agent, settings) {
  const own = defaultServerPath(agent);
  const st = store.readState(agent.id);
  const before = readFileContent(st, own);
  const texts = agentConfTexts(agent.id);
  const scan = defaultServer.scan(texts, own);
  const after = settings ? defaultServer.generate(settings, scan.listeners) : null;
  return { path: own, before: typeof before === 'string' ? before : null, after, scan };
}

// keep the catch-all covering every listener when sites/ports change
function refreshDefaultServer(agentId) {
  const agent = store.findAgent(agentId);
  if (!agent) return;
  const own = defaultServerPath(agent);
  const cur = readFileContent(store.readState(agentId), own);
  const settings = defaultServer.parseOwn(cur);
  if (!settings) return;
  const p = planDefaultServer(agent, settings);
  if (p.after !== cur) store.stageFile(agentId, own, p.after);
}

app.get('/api/agents/:id/default-server', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const p = planDefaultServer(agent, null);
  const st = store.readState(agent.id);
  res.json({ path: p.path, settings: defaultServer.parseOwn(p.before), fileStatus: p.before === null ? null : fileStatus(st, p.path), ...p.scan });
});

function defaultServerChange(agent, body) {
  const enabled = !!(body && body.enabled);
  const p = planDefaultServer(agent, enabled ? (body.settings || {}) : null);
  if (enabled && !p.scan.listeners.length) throw Object.assign(new Error('No listeners to cover — no name-based sites found'), { status: 409 });
  return p;
}

app.post('/api/agents/:id/default-server/preview', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const p = defaultServerChange(agent, req.body);
    res.json({ path: p.path, diff: unifiedDiff(p.before || '', p.after || ''), ...p.scan });
  } catch (err) { sendError(res, err); }
});

app.put('/api/agents/:id/default-server', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const p = defaultServerChange(agent, req.body);
    if (p.after) store.stageFile(agent.id, p.path, p.after);
    else if (store.currentFile(store.readState(agent.id), p.path)) store.stageDelete(agent.id, p.path);
    else { const s2 = store.readState(agent.id); delete s2.draft[p.path]; store.writeState(agent.id, s2); }
  } catch (err) { return sendError(res, err); }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// RTSP streams — TCP proxies in the stream {} context (stream.d/rtsp-streams.conf)
// ---------------------------------------------------------------------------
function discoveredStreams(agent) {
  const st = store.readState(agent.id);
  const dir = streams.streamDir(nginxDir(agent)) + '/';
  const out = [];
  for (const name of Object.keys(store.desiredFiles(st)).filter(n => n.startsWith(dir) && n.endsWith('.conf')).sort()) {
    const text = readFileContent(st, name);
    if (typeof text !== 'string') continue;
    let found;
    try { found = streams.findStreams(text); } catch { continue; }
    for (const p of found) out.push({ ...streams.publicStream(p), confPath: name, fileStatus: fileStatus(st, name) });
  }
  return out;
}

function streamsInfo(agent) {
  const st = store.readState(agent.id);
  const main = readFileContent(st, mainConfPath(agent));
  return {
    file: streams.streamsFile(nginxDir(agent)),
    mainConf: mainConfPath(agent),
    streamBlock: typeof main === 'string' && streams.streamBlockState(main, nginxDir(agent)).includes,
    streams: discoveredStreams(agent),
  };
}

function planStream(agent, body) {
  const st = store.readState(agent.id);
  const dir = nginxDir(agent);
  const confPath = body.key ? cleanRemotePath(body.confPath) : streams.streamsFile(dir);
  if (!confPath || !confPath.startsWith(streams.streamDir(dir) + '/')) throw Object.assign(new Error('confPath must be in stream.d'), { status: 400 });
  const before = readFileContent(st, confPath);
  if (before === undefined) throw Object.assign(new Error('File not synced from the agent yet'), { status: 409 });
  const mainPath = mainConfPath(agent);
  const mainBefore = readFileContent(st, mainPath);
  if (typeof mainBefore !== 'string') throw Object.assign(new Error(`${mainPath} not synced from the agent yet`), { status: 409 });
  // ports used by every other config file (http servers, forward proxies, other stream files)
  const desired = store.desiredFiles(st);
  const others = Object.keys(desired).filter(n => n.endsWith('.conf') && n !== confPath && !desired[n].certificateMeta)
    .map(n => readFileContent(st, n)).filter(t => typeof t === 'string');
  const p = streams.plan(before || '', { key: body.key || null, fields: body.fields || {}, usedPorts: streams.listenPorts(others) });
  const mainAfter = streams.ensureStreamBlock(mainBefore, dir);
  return { ...p, confPath, before: before || '', created: before === null, mainPath, mainBefore, mainAfter };
}

app.get('/api/agents/:id/streams', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(streamsInfo(agent));
});

app.post('/api/agents/:id/streams/preview', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const p = planStream(agent, req.body || {});
    res.json({
      path: p.confPath, created: p.created, diff: unifiedDiff(p.before, p.conf),
      mainPath: p.mainPath, mainDiff: p.mainAfter !== p.mainBefore ? unifiedDiff(p.mainBefore, p.mainAfter) : null,
    });
  } catch (err) { sendError(res, err); }
});

async function saveStream(req, res) {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const p = planStream(agent, req.body || {});
    if (p.mainAfter !== p.mainBefore) store.stageFile(agent.id, p.mainPath, p.mainAfter);
    if (p.conf !== p.before) store.stageFile(agent.id, p.confPath, p.conf);
    // request logging already on → also log stream sessions, now that the stream block includes it
    const st = store.readState(agent.id);
    const paths = logrx.remoteLogPaths(nginxDir(agent));
    if (LOG_PORT && store.desiredFiles(st)[paths.conf] && !store.desiredFiles(st)[paths.streamInc] && streamLogWired(st, agent)) {
      const receiver = await receiverAddressFor(agent);
      const want = receiver && remoteLogWant(st, agent, receiver);
      if (want && want[paths.streamInc]) store.stageFile(agent.id, paths.streamInc, want[paths.streamInc]);
    }
    io.emit('files', { agentId: agent.id });
    io.emit('agents');
    res.json({ ok: true, key: p.key, path: p.confPath, created: p.created, mainChanged: p.mainAfter !== p.mainBefore });
  } catch (err) { sendError(res, err); }
}
app.post('/api/agents/:id/streams', requireAuth, saveStream);
app.put('/api/agents/:id/streams', requireAuth, (req, res) => {
  if (!req.body || !req.body.key) return res.status(400).json({ error: 'key required' });
  saveStream(req, res);
});

app.delete('/api/agents/:id/streams', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const confPath = cleanRemotePath(req.query.path);
  if (!confPath || !req.query.key || !confPath.startsWith(streams.streamDir(nginxDir(agent)) + '/')) {
    return res.status(400).json({ error: 'path (in stream.d) and key required' });
  }
  const st = store.readState(agent.id);
  const before = readFileContent(st, confPath);
  if (typeof before !== 'string') return res.status(409).json({ error: 'File not synced from the agent yet' });
  try {
    const r = streams.remove(before, String(req.query.key));
    if (!r.empty) store.stageFile(agent.id, confPath, r.conf);
    else if (store.currentFile(st, confPath)) store.stageDelete(agent.id, confPath);
    else { const s2 = store.readState(agent.id); delete s2.draft[confPath]; store.writeState(agent.id, s2); }
  } catch (err) { return sendError(res, err); }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Forward proxies (CONNECT tunnels, ngx_http_tunnel_module) — nginx 1.31.0+
// ---------------------------------------------------------------------------
function forwardProxiesPath(agent) { return path.posix.join(confDir(agent), 'forward-proxies.conf'); }

function forwardSupport(agent) {
  const a = store.findAgent(agent.id) || agent;
  return {
    minVersion: fwdproxy.MIN_VERSION,
    version: a.nginxVersion || null,
    supported: fwdproxy.versionAtLeast(a.nginxVersion),
  };
}

function requireForwardSupport(agent, res) {
  const s = forwardSupport(agent);
  if (s.supported) return true;
  res.status(409).json({
    error: `Forward proxies need nginx ${s.minVersion} or newer (ngx_http_tunnel_module) — ` +
      (s.version ? `${agent.name} runs nginx ${s.version}` : `${agent.name} hasn't reported its nginx version yet`),
  });
  return false;
}

function discoveredForwardProxies(agent) {
  const st = store.readState(agent.id);
  const out = [];
  for (const name of Object.keys(store.desiredFiles(st)).filter(n => n.endsWith('.conf')).sort()) {
    const text = readFileContent(st, name);
    if (typeof text !== 'string' || !text.includes('tunnel_pass')) continue;
    let found;
    try { found = fwdproxy.findForwardProxies(text); } catch { continue; }
    for (const p of found) {
      const ht = p.authFile ? readFileContent(st, p.authFile) : null;
      out.push({
        ...fwdproxy.publicProxy(p),
        users: typeof ht === 'string' ? fwdproxy.parseHtpasswd(ht).map(u => u.username) : [],
        confPath: name,
        fileStatus: fileStatus(st, name),
      });
    }
  }
  return out;
}

function planForwardProxy(agent, body) {
  const st = store.readState(agent.id);
  const confPath = body.key ? cleanRemotePath(body.confPath) : forwardProxiesPath(agent);
  if (!confPath) throw Object.assign(new Error('confPath required'), { status: 400 });
  const before = readFileContent(st, confPath);
  if (before === undefined) throw Object.assign(new Error('File not synced from the agent yet'), { status: 409 });
  let existingHtpasswd = '';
  if (body.key) {
    const cur = fwdproxy.findForwardProxies(before || '').find(p => p.key === body.key);
    if (cur && cur.authFile) existingHtpasswd = readFileContent(st, cur.authFile) || '';
  }
  // the listen port must not already be used by another (non-proxy) server on this host
  const plan = fwdproxy.plan(before || '', {
    key: body.key || null, fields: body.fields || {}, nginxDir: nginxDir(agent), existingHtpasswd,
  });
  return { ...plan, confPath, before: before || '', created: before === null };
}

app.get('/api/agents/:id/forward-proxies', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json({ ...forwardSupport(agent), file: forwardProxiesPath(agent), proxies: discoveredForwardProxies(agent) });
});

app.post('/api/agents/:id/forward-proxies/preview', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const p = planForwardProxy(agent, req.body || {});
    res.json({ path: p.confPath, created: p.created, diff: unifiedDiff(p.before, p.conf), users: p.users, authFile: p.htpasswd ? p.authFile : null });
  } catch (err) { sendError(res, err); }
});

function saveForwardProxy(req, res) {
  const agent = requireAgent(req, res); if (!agent) return;
  if (!requireForwardSupport(agent, res)) return;
  try {
    const p = planForwardProxy(agent, req.body || {});
    if (p.conf !== p.before) store.stageFile(agent.id, p.confPath, p.conf);
    const st = store.readState(agent.id);
    if (p.htpasswd) {
      // the agent never reports auth_basic_user_file back — pin it so later applies keep it.
      // 0640: the agent writes as root:nginx-agent and the nginx user is in nginx-agent
      // (set up by the nginx-agent package), so workers can read it but other users can't.
      store.stageFile(agent.id, p.authFile, p.htpasswd, '0640', { pin: true });
    } else if (store.currentFile(st, p.authFile)) {
      store.stageDelete(agent.id, p.authFile);
    }
    io.emit('files', { agentId: agent.id });
    io.emit('agents');
    res.json({ ok: true, key: p.key, path: p.confPath, created: p.created, users: p.users });
  } catch (err) { sendError(res, err); }
}
app.post('/api/agents/:id/forward-proxies', requireAuth, saveForwardProxy);
app.put('/api/agents/:id/forward-proxies', requireAuth, (req, res) => {
  if (!req.body || !req.body.key) return res.status(400).json({ error: 'key required' });
  saveForwardProxy(req, res);
});

app.delete('/api/agents/:id/forward-proxies', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const confPath = cleanRemotePath(req.query.path);
  if (!confPath || !req.query.key) return res.status(400).json({ error: 'path and key required' });
  const st = store.readState(agent.id);
  const before = readFileContent(st, confPath);
  if (typeof before !== 'string') return res.status(409).json({ error: 'File not synced from the agent yet' });
  try {
    const r = fwdproxy.remove(before, String(req.query.key));
    if (r.conf.trim()) store.stageFile(agent.id, confPath, r.conf);
    else store.stageDelete(agent.id, confPath);
    if (r.authFile && store.currentFile(st, r.authFile)) store.stageDelete(agent.id, r.authFile);
    else if (r.authFile) { const s2 = store.readState(agent.id); delete s2.draft[r.authFile]; store.writeState(agent.id, s2); }
  } catch (err) { return sendError(res, err); }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Managed certificates — issued on the manager (certbot / AWS ACM), deployed by agents
// ---------------------------------------------------------------------------
function certSecretsFromBody(b) {
  const s = (b && b.secrets) || {};
  return {
    eabHmac: typeof s.eabHmac === 'string' ? s.eabHmac.trim() : undefined,
    dns: s.dns && typeof s.dns === 'object' ? Object.fromEntries(Object.entries(s.dns).map(([k, v]) => [k, String(v || '').trim()])) : undefined,
    aws: s.aws && typeof s.aws === 'object' ? { secretAccessKey: String(s.aws.secretAccessKey || '').trim() } : undefined,
  };
}

function runInBackground(id, opts) {
  certManager.process(id, opts).catch(err => certManager.log(id, `❌ ${err.message}`));
}

app.get('/api/managed-certs', requireAuth, (req, res) => {
  res.json({ catalog: issuers.catalog(), certs: certManager.list().map(c => certManager.view(c)) });
});

app.post('/api/managed-certs', requireAuth, (req, res) => {
  try {
    const cert = certManager.create(req.body || {}, certSecretsFromBody(req.body));
    runInBackground(cert.id, {});
    res.json(certManager.view(certManager.get(cert.id)));
  } catch (err) { sendError(res, err); }
});

app.put('/api/managed-certs/:id', requireAuth, (req, res) => {
  try {
    const before = certManager.get(req.params.id);
    const cert = certManager.update(req.params.id, req.body || {}, certSecretsFromBody(req.body));
    const targetsChanged = JSON.stringify(before.targets) !== JSON.stringify(cert.targets) ||
      before.certPath !== cert.certPath || before.keyPath !== cert.keyPath;
    if (cert.status.needsReissue || targetsChanged) runInBackground(cert.id, {});
    res.json(certManager.view(certManager.get(cert.id)));
  } catch (err) { sendError(res, err); }
});

// Stops managing the certificate; files already on servers are left in place.
app.delete('/api/managed-certs/:id', requireAuth, (req, res) => {
  if (!certManager.get(req.params.id)) return res.status(404).json({ error: 'not found' });
  certManager.remove(req.params.id);
  res.json({ ok: true });
});

app.post('/api/managed-certs/:id/renew', requireAuth, (req, res) => {
  if (!certManager.get(req.params.id)) return res.status(404).json({ error: 'not found' });
  runInBackground(req.params.id, { force: true });
  res.json({ ok: true });
});

app.post('/api/managed-certs/:id/deploy', requireAuth, (req, res) => {
  if (!certManager.get(req.params.id)) return res.status(404).json({ error: 'not found' });
  runInBackground(req.params.id, {});
  res.json({ ok: true });
});

// Point a server's sites at this managed certificate: every ssl_certificate /
// ssl_certificate_key that currently uses fromCert / fromKey is rewritten. Staged only.
app.post('/api/managed-certs/:id/switch-sites', requireAuth, (req, res) => {
  const cert = certManager.get(req.params.id);
  if (!cert) return res.status(404).json({ error: 'not found' });
  const agent = store.findAgent(req.body && req.body.agentId);
  if (!agent || !cert.targets.includes(agent.id)) return res.status(400).json({ error: 'server is not a target of this certificate' });
  const dep = (cert.status.deployments || {})[agent.id];
  if (!dep || dep.state !== 'ok') return res.status(409).json({ error: 'Deploy the certificate to this server first — nginx -t would fail without the files' });
  const fromCert = cleanRemotePath(req.body.fromCert);
  const fromKey = cleanRemotePath(req.body.fromKey);
  if (!fromCert || !fromKey) return res.status(400).json({ error: 'fromCert and fromKey (absolute paths) required' });

  const st = store.readState(agent.id);
  let files = 0, directives = 0;
  for (const name of Object.keys(store.desiredFiles(st)).filter(n => n.endsWith('.conf'))) {
    const before = readFileContent(st, name);
    if (typeof before !== 'string') continue;
    let out;
    try { out = proxyfile.replaceCertPaths(before, { [fromCert]: cert.certPath, [fromKey]: cert.keyPath }); }
    catch { continue; }
    if (out.count) { store.stageFile(agent.id, name, out.text); files++; directives += out.count; }
  }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true, files, directives });
});

// ---------------------------------------------------------------------------
// Visual-builder Sites
//   Builder sites: created here; their whole .conf file is generated from the form.
//   Discovered sites: server blocks in any other .conf the agent reported. Shown
//   read-only (edit the file) — regenerating them would drop unsupported directives.
// ---------------------------------------------------------------------------
function resolveCertPaths(agentId, site) {
  if (site.ssl && site.certId) {
    const cert = deriveCerts(agentId).find(c => c.id === site.certId);
    if (cert) {
      site.certFile = cert.remoteCertPath || site.certFile;
      site.keyFile  = cert.remoteKeyPath  || site.keyFile;
    }
  }
  return site;
}

// Reverse proxies live in one hand-maintainable file; new ones are appended to it.
function reverseProxiesPath(agent) { return path.posix.join(confDir(agent), 'reverse-proxies.conf'); }

// Does any config define `map $http_upgrade $connection_upgrade`? New WebSocket proxies
// then use it (keeps upstream keepalive working) instead of a hardcoded "upgrade".
function hasConnectionUpgradeMap(agentId) {
  const { files } = parsedConfFiles(agentId);
  const st = store.readState(agentId);
  return files.some(f => /map\s+\$http_upgrade\s+\$connection_upgrade/.test(readFileContent(st, f.path) || ''));
}

function siteId(confPath, key) { return `file:${confPath}#${key}`; }

function splitSiteId(id) {
  const m = /^file:(\/[^#]+)#(.+)$/.exec(id);
  if (!m) return null;
  const confPath = cleanRemotePath(m[1]);
  return confPath ? { confPath, key: m[2] } : null;
}

// Server blocks from every .conf file, grouped into sites by server_name.
function discoveredSites(agent) {
  const { st, files } = parsedConfFiles(agent.id);
  const managedPaths = new Set(builderSites(agent.id).map(s => s.confPath || siteConfPath(agent, s)));
  const zones = proxyfile.parseLimitZones(readFileContent(st, limitsPath(agent)) || '');
  const out = [];
  for (const f of files) {
    // files nginx-manager generates (catch-all, status page, limits, logging) have their own UI
    if (managedPaths.has(f.path) || /\/00-nginx-manager-[^/]*\.conf$/.test(f.path)) continue;
    const content = readFileContent(st, f.path);
    let sites;
    try { sites = proxyfile.findSites(content).map(proxyfile.publicSite); }
    catch { sites = null; }
    if (!sites) {
      // unparseable file — fall back to the lightweight parser, read-only
      f.sites.forEach((x, i) => out.push({ ...x, id: siteId(f.path, `#${i}`), confPath: f.path, discovered: true,
        editable: false, readOnlyReason: 'Could not parse this file — edit it in Raw Configs', fileStatus: f.status }));
      continue;
    }
    for (const x of sites) {
      if (x.rateLimit) x.rateLimit.rate = zones.get(x.rateLimit.zone) || null;
      out.push({
        ...x,
        id: siteId(f.path, x.key),
        name: x.label,
        upstream: x.backends,
        confPath: f.path,
        discovered: true,
        fileStatus: f.status,
      });
    }
  }
  return out;
}

function allServerNames(agent) {
  return new Set(discoveredSites(agent).flatMap(s => (s.serverName || '').split(/\s+/)).filter(Boolean)
    .concat(builderSites(agent.id).flatMap(s => (s.serverName || '').split(/\s+/)).filter(Boolean)));
}

// Fields accepted from the reverse-proxy popup
function proxyFields(b) {
  const f = {};
  for (const k of ['name', 'serverName', 'backendScheme', 'backendPath', 'lbMethod', 'certFile', 'keyFile', 'clientMaxBodySize']) {
    if (b[k] !== undefined) f[k] = String(b[k]).trim();
  }
  if (Array.isArray(b.backends)) f.backends = b.backends.map(String);
  for (const k of ['ssl', 'hsts', 'websockets', 'httpRedirect']) if (b[k] !== undefined) f[k] = !!b[k];
  if (b.proxyReadTimeout !== undefined) f.proxyReadTimeout = b.proxyReadTimeout === '' || b.proxyReadTimeout === null ? '' : String(b.proxyReadTimeout);
  if (b.listenPort !== undefined) f.listenPort = parseInt(b.listenPort, 10);
  if (b.rateLimit !== undefined) f.rateLimit = b.rateLimit ? { rate: String(b.rateLimit.rate || '').trim(), burst: parseInt(b.rateLimit.burst, 10) || 0 } : null;
  if (b.connLimit !== undefined) f.connLimit = b.connLimit === null || b.connLimit === '' ? null : parseInt(b.connLimit, 10);
  if (b.sso !== undefined) f.sso = b.sso ? { authUrl: String(b.sso.authUrl || '').trim(), signinUrl: String(b.sso.signinUrl || '').trim() } : null;
  if (b.certId) {
    const cert = deriveCerts(b._agentId).find(c => c.id === b.certId);
    if (cert) { f.certFile = cert.remoteCertPath; f.keyFile = cert.remoteKeyPath || f.keyFile; }
  }
  return f;
}

// Compute the new contents of the target file for a create/edit, without saving.
function limitsPath(agent) { return path.posix.join(confDir(agent), '00-nginx-manager-limits.conf'); }

// The site edit plus the http-level zones file it may need (created/updated/removed)
function planProxyChange(agent, siteIdOrNull, body) {
  const plan = planProxySite(agent, siteIdOrNull, body);
  const f = plan.fields;
  const st = store.readState(agent.id);
  const lp = limitsPath(agent);
  const limitsBefore = readFileContent(st, lp);
  const zones = proxyfile.parseLimitZones(limitsBefore || '');
  if (f.rateLimit) zones.set(plan.rateZone, f.rateLimit.rate);
  const texts = Object.entries(agentConfTexts(agent.id)).filter(([n]) => n !== plan.path && n !== lp).map(([, t]) => t);
  const limitsAfter = proxyfile.limitsFileText([...texts, plan.after], zones);
  if ((limitsBefore || null) !== limitsAfter) plan.extra = { path: lp, before: limitsBefore || '', after: limitsAfter };
  return plan;
}

function stageProxyPlan(agent, plan) {
  if (plan.after !== plan.before) store.stageFile(agent.id, plan.path, plan.after);
  if (plan.extra) {
    if (plan.extra.after) store.stageFile(agent.id, plan.extra.path, plan.extra.after);
    else if (store.currentFile(store.readState(agent.id), plan.extra.path)) store.stageDelete(agent.id, plan.extra.path);
    else { const s2 = store.readState(agent.id); delete s2.draft[plan.extra.path]; store.writeState(agent.id, s2); }
  }
}

function planProxySite(agent, siteIdOrNull, body) {
  const f = proxyFields({ ...body, _agentId: agent.id });
  const ctx = { connectionUpgradeMap: hasConnectionUpgradeMap(agent.id) };
  const st = store.readState(agent.id);
  if (siteIdOrNull) {
    const ref = splitSiteId(siteIdOrNull);
    if (!ref) throw Object.assign(new Error('bad site id'), { status: 400 });
    const before = readFileContent(st, ref.confPath);
    if (typeof before !== 'string') throw Object.assign(new Error('File not synced from the agent yet'), { status: 409 });
    if (f.serverName !== undefined) {
      const current = proxyfile.findSites(before).find(x => x.key === ref.key);
      const mine = new Set(((current && current.serverName) || '').split(/\s+/));
      const taken = allServerNames(agent);
      const clash = f.serverName.split(/\s+/).find(n => taken.has(n) && !mine.has(n));
      if (clash) throw Object.assign(new Error(`${clash} is already used by another site`), { status: 409 });
    }
    const current = proxyfile.findSites(before).find(x => x.key === ref.key);
    ctx.rateZone = (current && current.rateLimit && /^nm_rl_/.test(current.rateLimit.zone)) ? current.rateLimit.zone
      : proxyfile.rateZoneName((f.serverName || (current && current.serverName) || ''));
    const after = proxyfile.editSite(before, ref.key, f, ctx);
    return { path: ref.confPath, before, after, fields: f, rateZone: ctx.rateZone };
  }
  const target = reverseProxiesPath(agent);
  const existing = readFileContent(st, target);
  if (existing === undefined) throw Object.assign(new Error('reverse-proxies.conf not synced from the agent yet'), { status: 409 });
  const before = existing || '';
  const taken = allServerNames(agent);
  const clash = (f.serverName || '').split(/\s+/).find(n => n && taken.has(n));
  if (clash) throw Object.assign(new Error(`${clash} is already used by another site`), { status: 409 });
  ctx.rateZone = proxyfile.rateZoneName(f.serverName || '');
  const after = proxyfile.addSite(before, f, ctx);
  return { path: target, before, after, created: existing === null, fields: f, rateZone: ctx.rateZone };
}

function sendError(res, err) {
  res.status(err.status || 400).json({ error: err.message });
}

app.get('/api/agents/:id/sites', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const { st } = parsedConfFiles(agent.id);
  const managed = builderSites(agent.id).map(s => {
    const p = s.confPath || siteConfPath(agent, s);
    return { ...s, confPath: p, managed: true, fileStatus: fileStatus(st, p) };
  });
  res.json([...managed, ...discoveredSites(agent)]);
});

// Preview a reverse-proxy create/edit as a diff of the target file
app.post('/api/agents/:id/proxies/preview', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const plan = planProxyChange(agent, req.body && req.body.siteId, req.body || {});
    res.json({ path: plan.path, created: !!plan.created, diff: unifiedDiff(plan.before, plan.after),
      extra: plan.extra ? { path: plan.extra.path, diff: unifiedDiff(plan.extra.before, plan.extra.after || '') } : null });
  } catch (err) { sendError(res, err); }
});

// New reverse proxy → appended to conf.d/reverse-proxies.conf (created if missing)
app.post('/api/agents/:id/proxies', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const plan = planProxyChange(agent, null, req.body || {});
    stageProxyPlan(agent, plan);
    io.emit('files', { agentId: agent.id });
    io.emit('agents');
    res.json({ ok: true, path: plan.path, created: !!plan.created });
  } catch (err) { sendError(res, err); }
});

// Edit a reverse proxy in place (only the directives the popup owns are rewritten)
app.put('/api/agents/:id/proxies', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const plan = planProxyChange(agent, req.body && req.body.siteId, req.body || {});
    stageProxyPlan(agent, plan);
    io.emit('files', { agentId: agent.id });
    io.emit('agents');
    res.json({ ok: true, path: plan.path, changed: plan.after !== plan.before });
  } catch (err) { sendError(res, err); }
});

// Builder sites (static / redirect) — whole generated file
app.post('/api/agents/:id/sites', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const b = req.body || {};
  const site = resolveCertPaths(agent.id, {
    id:              uuidv4(),
    name:            b.name            || 'New Site',
    type:            b.type === 'redirect' ? 'redirect' : 'static',
    serverName:      b.serverName      || '',
    listenPort:      b.listenPort      || 80,
    upstream:        [],
    lbMethod:        'round_robin',
    staticRoot:      b.staticRoot      || '/var/www/html',
    redirectTo:      b.redirectTo      || '',
    ssl:             b.ssl             || false,
    certId:          b.certId          || null,         // cert path from the Certificates tab
    certFile:        b.certFile        || '',           // remote path
    keyFile:         b.keyFile         || '',           // remote path
    hsts:            b.hsts            || false,
    proxyTimeout:    60,
    proxyBuffering:  true,
    extraDirectives: b.extraDirectives || '',
    enabled:         b.enabled         !== false,
    createdAt:       new Date().toISOString(),
    updatedAt:       new Date().toISOString(),
  });
  site.confPath = siteConfPath(agent, site);
  const desired = store.desiredFiles(store.readState(agent.id));
  if (desired[site.confPath] && !builderSites(agent.id).some(s => s.confPath === site.confPath)) {
    return res.status(409).json({ error: `${site.confPath} already exists — choose another site name` });
  }
  store.writeSite(agent.id, site);
  store.stageFile(agent.id, site.confPath, siteToNginxConf(site));
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json(site);
});

app.put('/api/agents/:id/sites/:siteId', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const existing = store.readSite(agent.id, req.params.siteId);
  if (!existing || existing.importedFrom) return res.status(404).json({ error: 'Site not found' });

  const site = resolveCertPaths(agent.id, {
    ...existing, ...req.body,
    id: existing.id, createdAt: existing.createdAt, updatedAt: new Date().toISOString(),
  });
  const oldConf = existing.confPath || siteConfPath(agent, existing);
  site.confPath = siteConfPath(agent, site);
  if (oldConf !== site.confPath) store.stageDelete(agent.id, oldConf);
  store.writeSite(agent.id, site);
  store.stageFile(agent.id, site.confPath, siteToNginxConf(site));
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json(site);
});

// Builder site: forget it and delete its generated file.
// Discovered site ("file:<path>#<key>"): remove just that site's blocks from the file.
app.delete('/api/agents/:id/sites/:siteId', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const id = req.params.siteId;
  if (id.startsWith('file:')) {
    const ref = splitSiteId(id);
    if (!ref) return res.status(400).json({ error: 'bad site id' });
    const st = store.readState(agent.id);
    const before = readFileContent(st, ref.confPath);
    if (typeof before !== 'string') return res.status(409).json({ error: 'File not synced from the agent yet' });
    let after;
    try { after = proxyfile.removeSite(before, ref.key); }
    catch (err) { return sendError(res, err); }
    if (after.trim()) store.stageFile(agent.id, ref.confPath, after);
    else store.stageDelete(agent.id, ref.confPath);
  } else {
    const site = store.readSite(agent.id, id);
    if (!site) return res.status(404).json({ error: 'Site not found' });
    store.deleteSite(agent.id, site.id);
    store.stageDelete(agent.id, site.confPath || siteConfPath(agent, site));
  }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

// Preview generated config for a builder (static/redirect) site without saving
app.post('/api/agents/:id/sites/preview', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const site = resolveCertPaths(agent.id, { ...req.body });
    res.json({ conf: siteToNginxConf(site), path: siteConfPath(agent, site) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Socket.IO — session-authenticated live log + operations
// ---------------------------------------------------------------------------
io.engine.use(sessionMiddleware);
io.use((socket, next) => {
  if (sessionUser(socket.request)) return next();
  next(new Error('unauthorised'));
});

mp.on('log', (agentId, text) => io.emit('log', { agentId, text }));
mp.on('agents', () => io.emit('agents'));
mp.on('files', agentId => io.emit('files', { agentId }));
vipMonitor.on('change', () => io.emit('groups'));
logReceiver.on('entries', ({ agentId, kind, entries }) => io.emit('remotelog', { agentId, kind, entries }));
cve.on('change', () => io.emit('cve'));
certManager.on('change', id => io.emit('managedcerts', { id }));
certManager.on('log', (id, line) => io.emit('certlog', { id, line }));
vipMonitor.on('failover', ({ group, from, to, at }) => {
  console.log(`[nginx-manager] VIP failover in ${group}: ${from} -> ${to}`);
  alerts.notify({ event: 'vip_failover', key: `vip:${group}:${to}`, group, title: `VIP for ${group} moved to ${to}`,
    message: `The keepalived VIP for group ${group} moved from ${from} to ${to} at ${at}.` }).catch(() => {});
  for (const a of store.readAgents().filter(x => (x.group || '').trim() === group)) {
    io.emit('log', { agentId: a.id, text: `🔀 VIP for ${group} moved from ${from} to ${to} at ${at}\n` });
  }
});

io.on('connection', (socket) => {
  const op = (name, fn, role = 'viewer') => socket.on(name, async ({ agentId, label } = {}) => {
    const u = sessionUser(socket.request);
    if (!u) { socket.emit('done', { op: name, agentId, success: false, output: 'Not authenticated' }); return; }
    if (!atLeast(u.role, role)) { socket.emit('done', { op: name, agentId, success: false, output: `Your role (${u.role}) can't do this` }); return; }
    const agent = store.findAgent(agentId);
    if (!agent) { socket.emit('done', { op: name, agentId, success: false, output: 'Server not found' }); return; }
    const result = await fn(agent, u, { label });
    socket.emit('done', { op: name, agentId, ...result });
  });

  op('apply', (agent, u, o) => mp.configApply(agent.id, { user: u.username, label: o.label }), 'operator');
  op('sync',  (agent, u) => { audit.record({ user: u.username, action: 'config.sync', agent: agent.name }); return mp.configUpload(agent.id); }, 'operator');
  op('status', async agent => {
    if (!mp.isOnline(agent.id)) return { success: false, output: 'Agent is not connected' };
    mp.requestHealth(agent.id);
    await new Promise(r => setTimeout(r, 2000));
    const a = store.findAgent(agent.id);
    const health = mp.health.get(agent.id) || [];
    const lines = [
      `Host:          ${a.hostname || '—'} ${a.os ? `(${a.os})` : ''}`,
      `NGINX Agent:   ${a.agentVersion || '—'}`,
      `nginx:         ${a.nginxVersion || '—'}  ${a.configPath || ''}`,
      `Last seen:     ${a.lastSeen || '—'}`,
      ...health.map(h => `Health:        ${h.status}${h.description ? ` — ${h.description}` : ''}`),
    ];
    const healthy = health.length > 0 && health.every(h => h.status === 'healthy');
    return { success: healthy, output: lines.join('\n') + '\n', healthy };
  });
});

// ---------------------------------------------------------------------------
// SPA catch-all
// ---------------------------------------------------------------------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

vipMonitor.start();
certManager.start();
usage.start();
// CVE sources: first check shortly after start (agents report versions on connect), then every 6 h
setTimeout(() => refreshCves().catch(() => {}), 20e3).unref();
setInterval(() => refreshCves().catch(() => {}), 6 * 3600e3).unref();
for (const sig of ['SIGTERM', 'SIGINT']) process.once(sig, () => { usage.save(); process.exit(0); });
if (LOG_PORT) {
  logReceiver.start()
    .then(p => console.log(`[nginx-manager] log receiver listening on udp/${p}`))
    .catch(err => console.error(`[nginx-manager] log receiver failed to start on udp/${LOG_PORT}: ${err.message}`));
}

mp.start().catch(err => {
  console.error('[nginx-manager] Failed to start agent gRPC listener:', err.message);
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`nginx-manager listening on http://0.0.0.0:${PORT}`);
});

module.exports = { app, server, mp };
