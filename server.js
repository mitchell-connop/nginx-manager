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

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT           = process.env.PORT || 3000;
const GRPC_PORT      = parseInt(process.env.GRPC_PORT || '8443', 10);
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
  return st.live[name] ? 'modified' : 'added';
}

function readFileContent(st, name) {
  const d = st.draft[name];
  const entry = d && !d.deleted ? d : st.live[name];
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
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorised' });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
const loginFailures = new Map();   // ip -> { count, until }
const MAX_FAILURES = 10, LOCKOUT_MS = 15 * 60 * 1000;

async function checkPassword(password) {
  if (typeof password !== 'string') return false;
  if (/^\$2[aby]\$/.test(ADMIN_PASS)) return bcrypt.compare(password, ADMIN_PASS);
  const a = crypto.createHash('sha256').update(password).digest();
  const b = crypto.createHash('sha256').update(ADMIN_PASS).digest();
  return crypto.timingSafeEqual(a, b);
}

app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  const f = loginFailures.get(ip);
  if (f && f.count >= MAX_FAILURES && f.until > Date.now()) {
    return res.status(429).json({ error: 'Too many attempts — try again later' });
  }
  if (!(await checkPassword(req.body && req.body.password))) {
    const cur = f && f.until > Date.now() ? f : { count: 0 };
    loginFailures.set(ip, { count: cur.count + 1, until: Date.now() + LOCKOUT_MS });
    return res.status(401).json({ error: 'Invalid password' });
  }
  loginFailures.delete(ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.authenticated = true;
    res.json({ ok: true });
  });
});
app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/me', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
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
// Config files (live from the agent + staged draft)
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/files', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const st = store.readState(agent.id);
  const names = new Set([...Object.keys(st.live), ...Object.keys(st.draft)]);
  const files = [...names].sort().map(name => {
    const d = st.draft[name];
    const e = d && !d.deleted ? d : st.live[name];
    return {
      name,
      size: e ? e.size : 0,
      modified: e ? e.modifiedTime : null,
      status: fileStatus(st, name),
      isCert: !!(e && e.certificateMeta),
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
  res.json(await mp.configApply(agent.id));
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
  const out = [];
  for (const name of Object.keys(desired).sort()) {
    if (!name.endsWith('.conf') || desired[name].certificateMeta) continue;
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
      label: e.uploadLabel || (meta && meta.subject) || (dirName !== 'ssl' && dirName !== 'certs' ? dirName : path.basename(e.certPath)),
      remoteCertPath: e.certPath,
      remoteKeyPath: keyPath,
      remoteChainPath: e.chainPath || null,
      certificateMeta: meta,
      usedBy: [...e.sites].sort(),
      referencedIn: [...e.files].sort(),
      inUse: e.sites.size > 0,
      uploaded: !!e.uploadLabel,
      onServer: !!st.live[e.certPath],
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

    store.stageFile(agent.id, remoteCertPath, file('certFile').buffer, '0644');
    store.stageFile(agent.id, remoteKeyPath,  file('keyFile').buffer,  '0600');
    if (file('chainFile') && remoteChainPath) store.stageFile(agent.id, remoteChainPath, file('chainFile').buffer, '0644');

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
    if (p && st.draft[p] && !st.live[p]) delete st.draft[p];
  }
  store.writeState(agent.id, st);
  store.writeCerts(agent.id, store.readCerts(agent.id).filter(c => c.remoteCertPath !== certPath));
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
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
  const out = [];
  for (const f of files) {
    if (managedPaths.has(f.path)) continue;
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
  if (b.certId) {
    const cert = deriveCerts(b._agentId).find(c => c.id === b.certId);
    if (cert) { f.certFile = cert.remoteCertPath; f.keyFile = cert.remoteKeyPath || f.keyFile; }
  }
  return f;
}

// Compute the new contents of the target file for a create/edit, without saving.
function planProxyChange(agent, siteIdOrNull, body) {
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
    const after = proxyfile.editSite(before, ref.key, f, ctx);
    return { path: ref.confPath, before, after };
  }
  const target = reverseProxiesPath(agent);
  const existing = readFileContent(st, target);
  if (existing === undefined) throw Object.assign(new Error('reverse-proxies.conf not synced from the agent yet'), { status: 409 });
  const before = existing || '';
  const taken = allServerNames(agent);
  const clash = (f.serverName || '').split(/\s+/).find(n => n && taken.has(n));
  if (clash) throw Object.assign(new Error(`${clash} is already used by another site`), { status: 409 });
  const after = proxyfile.addSite(before, f, ctx);
  return { path: target, before, after, created: existing === null };
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
    res.json({ path: plan.path, created: !!plan.created, diff: unifiedDiff(plan.before, plan.after) });
  } catch (err) { sendError(res, err); }
});

// New reverse proxy → appended to conf.d/reverse-proxies.conf (created if missing)
app.post('/api/agents/:id/proxies', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const plan = planProxyChange(agent, null, req.body || {});
    store.stageFile(agent.id, plan.path, plan.after);
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
    if (plan.after !== plan.before) store.stageFile(agent.id, plan.path, plan.after);
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
  const s = socket.request.session;
  if (s && s.authenticated) return next();
  next(new Error('unauthorised'));
});

mp.on('log', (agentId, text) => io.emit('log', { agentId, text }));
mp.on('agents', () => io.emit('agents'));
mp.on('files', agentId => io.emit('files', { agentId }));

io.on('connection', (socket) => {
  const authed = () => socket.request.session && socket.request.session.authenticated;
  const op = (name, fn) => socket.on(name, async ({ agentId } = {}) => {
    if (!authed()) { socket.emit('done', { op: name, agentId, success: false, output: 'Not authenticated' }); return; }
    const agent = store.findAgent(agentId);
    if (!agent) { socket.emit('done', { op: name, agentId, success: false, output: 'Server not found' }); return; }
    const result = await fn(agent);
    socket.emit('done', { op: name, agentId, ...result });
  });

  op('apply', agent => mp.configApply(agent.id));
  op('sync',  agent => mp.configUpload(agent.id));
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

mp.start().catch(err => {
  console.error('[nginx-manager] Failed to start agent gRPC listener:', err.message);
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`nginx-manager listening on http://0.0.0.0:${PORT}`);
});

module.exports = { app, server, mp };
