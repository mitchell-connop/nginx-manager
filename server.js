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
  const tokenValue = token || '<paste the token shown when the server was added>';
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

  const script = [
    '# Run as root on the nginx server',
    '# 1. Install NGINX Agent v3 from the nginx.org repo (uses the existing nginx.org signing key)',
    'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://packages.nginx.org/nginx-agent/debian $(. /etc/os-release && echo $VERSION_CODENAME) agent" \\',
    '  > /etc/apt/sources.list.d/nginx-agent.list',
    'apt-get update && apt-get install -y nginx-agent',
    '',
    '# 2. Token + manager CA',
    `install -m 600 /dev/null /etc/nginx-agent/manager.token && printf '%s' '${tokenValue}' > /etc/nginx-agent/manager.token`,
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
// Certificates
// ---------------------------------------------------------------------------
function certWithMeta(agentId, cert) {
  const st = store.readState(agentId);
  const desired = store.desiredFiles(st);
  const f = desired[cert.remoteCertPath];
  return {
    ...cert,
    certificateMeta: f ? f.certificateMeta || null : null,
    onServer: !!st.live[cert.remoteCertPath],
    pending: [cert.remoteCertPath, cert.remoteKeyPath, cert.remoteChainPath].some(p => p && st.draft[p]),
  };
}

app.get('/api/agents/:id/certs', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(store.readCerts(agent.id).map(c => certWithMeta(agent.id, c)));
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

    const certs = store.readCerts(agent.id);
    const entry = {
      id: uuidv4(), label,
      remoteCertPath, remoteKeyPath,
      remoteChainPath: file('chainFile') ? remoteChainPath : null,
      uploaded: true,
      createdAt: new Date().toISOString(),
    };
    certs.push(entry);
    store.writeCerts(agent.id, certs);
    io.emit('files', { agentId: agent.id });
    io.emit('agents');
    res.json(certWithMeta(agent.id, entry));
  }
);

// Register a cert that already exists on the server (no upload)
app.post('/api/agents/:id/certs/remote', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const { label } = req.body || {};
  const remoteCertPath = cleanRemotePath(req.body && req.body.remoteCertPath);
  const remoteKeyPath  = cleanRemotePath(req.body && req.body.remoteKeyPath);
  if (!label || !remoteCertPath || !remoteKeyPath)
    return res.status(400).json({ error: 'label and absolute remoteCertPath, remoteKeyPath required' });
  const certs = store.readCerts(agent.id);
  const cert = {
    id: uuidv4(), label, remoteCertPath, remoteKeyPath, remoteChainPath: null,
    remoteOnly: true, createdAt: new Date().toISOString(),
  };
  certs.push(cert);
  store.writeCerts(agent.id, certs);
  res.json(certWithMeta(agent.id, cert));
});

// "Scan" the certificate files the agent reported (those referenced by nginx config
// in its allowed directories) and auto-register cert/key pairs.
app.post('/api/agents/:id/certs/scan', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const st = store.readState(agent.id);
  const files = Object.keys(st.live).filter(f => /\.(pem|crt|cer|key)$/i.test(f) || st.live[f].certificateMeta).sort();

  // A file is a "cert" if the agent parsed certificate metadata from it, or by name;
  // a file is a "key" if its basename contains privkey / private / key.
  const isKey = f => {
    const b = path.basename(f).toLowerCase();
    return b.includes('privkey') || b.includes('private') || b.endsWith('.key') ||
      (b.includes('key') && b.endsWith('.pem'));
  };
  const isCert = f => !isKey(f) && (!!st.live[f].certificateMeta || /\.(pem|crt|cer)$/i.test(f));

  const byDir = {};
  for (const f of files) (byDir[path.dirname(f)] = byDir[path.dirname(f)] || []).push(f);

  const suggestions = Object.entries(byDir).map(([dir, dirFiles]) => {
    const certs = dirFiles.filter(isCert);
    const keys  = dirFiles.filter(isKey);
    const bestCert = certs.find(f => path.basename(f) === 'fullchain.pem')
      || certs.find(f => path.basename(f).startsWith('cert'))
      || certs[0];
    const bestKey = keys.find(f => path.basename(f) === 'privkey.pem')
      || keys.find(f => path.basename(f).includes('privkey'))
      || keys[0];
    return { dir, files: dirFiles, certs, keys, bestCert, bestKey };
  }).filter(s => s.certs.length > 0 || s.keys.length > 0);

  const stored = store.readCerts(agent.id);
  const autoRegistered = [];
  for (const sg of suggestions) {
    if (!sg.bestCert || !sg.bestKey) continue;
    if (stored.some(c => c.remoteCertPath === sg.bestCert && c.remoteKeyPath === sg.bestKey)) continue;
    const dirParts = sg.dir.split('/').filter(Boolean);
    const cert = {
      id: uuidv4(),
      label: dirParts[dirParts.length - 1] || sg.dir,
      remoteCertPath: sg.bestCert,
      remoteKeyPath: sg.bestKey,
      remoteChainPath: sg.certs.find(f => path.basename(f).includes('chain') && f !== sg.bestCert) || null,
      remoteOnly: true,
      autoDiscovered: true,
      createdAt: new Date().toISOString(),
    };
    stored.push(cert);
    autoRegistered.push(cert);
  }
  if (autoRegistered.length) store.writeCerts(agent.id, stored);

  res.json({ files, suggestions, autoRegistered });
});

app.put('/api/agents/:id/certs/:certId', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const certs = store.readCerts(agent.id);
  const idx = certs.findIndex(c => c.id === req.params.certId);
  if (idx === -1) return res.status(404).json({ error: 'Cert not found' });
  const { label } = req.body || {};
  if (label) certs[idx].label = label;
  for (const k of ['remoteCertPath', 'remoteKeyPath', 'remoteChainPath']) {
    const v = req.body && req.body[k] ? cleanRemotePath(req.body[k]) : null;
    if (v) certs[idx][k] = v;
  }
  store.writeCerts(agent.id, certs);
  res.json(certWithMeta(agent.id, certs[idx]));
});

// Removes the registry entry only — files on the server are left alone.
app.delete('/api/agents/:id/certs/:certId', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const certs = store.readCerts(agent.id);
  if (!certs.some(c => c.id === req.params.certId)) return res.status(404).json({ error: 'Cert not found' });
  store.writeCerts(agent.id, certs.filter(c => c.id !== req.params.certId));
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Visual-builder Sites
// ---------------------------------------------------------------------------
function resolveCertPaths(agentId, site) {
  if (site.ssl && site.certId) {
    const cert = store.readCerts(agentId).find(c => c.id === site.certId);
    if (cert) {
      site.certFile = cert.remoteCertPath || site.certFile;
      site.keyFile  = cert.remoteKeyPath  || site.keyFile;
    }
  }
  return site;
}

app.get('/api/agents/:id/sites', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  res.json(store.readSites(agent.id));
});

app.post('/api/agents/:id/sites', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const b = req.body || {};
  const site = resolveCertPaths(agent.id, {
    id:              uuidv4(),
    name:            b.name            || 'New Site',
    type:            b.type            || 'proxy',      // proxy | static | redirect
    serverName:      b.serverName      || '',
    listenPort:      b.listenPort      || 80,
    upstream:        b.upstream        || [],           // array of host:port
    lbMethod:        b.lbMethod        || 'round_robin',
    staticRoot:      b.staticRoot      || '/var/www/html',
    redirectTo:      b.redirectTo      || '',
    ssl:             b.ssl             || false,
    certId:          b.certId          || null,         // links to certs store
    certFile:        b.certFile        || '',           // remote path
    keyFile:         b.keyFile         || '',           // remote path
    hsts:            b.hsts            || false,
    proxyTimeout:    b.proxyTimeout    || 60,
    proxyBuffering:  b.proxyBuffering  !== false,
    extraDirectives: b.extraDirectives || '',
    enabled:         b.enabled         !== false,
    createdAt:       new Date().toISOString(),
    updatedAt:       new Date().toISOString(),
  });
  site.confPath = siteConfPath(agent, site);
  store.writeSite(agent.id, site);
  store.stageFile(agent.id, site.confPath, siteToNginxConf(site));
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json(site);
});

app.put('/api/agents/:id/sites/:siteId', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const existing = store.readSite(agent.id, req.params.siteId);
  if (!existing) return res.status(404).json({ error: 'Site not found' });

  const site = resolveCertPaths(agent.id, {
    ...existing, ...req.body,
    id: existing.id, createdAt: existing.createdAt, updatedAt: new Date().toISOString(),
  });
  // Imported sites keep their original file; builder sites follow the site name.
  const oldConf = existing.confPath || siteConfPath(agent, existing);
  site.confPath = existing.importedFrom ? oldConf : siteConfPath(agent, site);
  if (oldConf !== site.confPath) store.stageDelete(agent.id, oldConf);
  store.writeSite(agent.id, site);
  store.stageFile(agent.id, site.confPath, siteToNginxConf(site));
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json(site);
});

app.delete('/api/agents/:id/sites/:siteId', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const site = store.readSite(agent.id, req.params.siteId);
  if (!site) return res.status(404).json({ error: 'Site not found' });
  store.deleteSite(agent.id, site.id);
  if (!site.importedFrom || req.query.removeFile === 'true') {
    store.stageDelete(agent.id, site.confPath || siteConfPath(agent, site));
  }
  io.emit('files', { agentId: agent.id });
  io.emit('agents');
  res.json({ ok: true });
});

// Preview generated config without saving
app.post('/api/agents/:id/sites/preview', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  try {
    const site = resolveCertPaths(agent.id, { ...req.body });
    res.json({ conf: siteToNginxConf(site), path: siteConfPath(agent, site) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Import conf.d files the agent reported into the Visual Builder
app.post('/api/agents/:id/sites/import', requireAuth, (req, res) => {
  const agent = requireAgent(req, res); if (!agent) return;
  const dir = confDir(agent);
  const st  = store.readState(agent.id);
  const desired = store.desiredFiles(st);
  const confFiles = Object.keys(desired).filter(f => path.posix.dirname(f) === dir && f.endsWith('.conf')).sort();

  if (!confFiles.length) {
    return res.json({ imported: [], skipped: [], message: `No .conf files reported in ${dir} — is the agent connected?` });
  }

  const existing = store.readSites(agent.id);
  const imported = [];
  const skipped  = [];

  for (const remotePath of confFiles) {
    const fname = path.basename(remotePath);
    if (existing.some(e => (e.confPath || '') === remotePath && !e.importedFrom)) {
      skipped.push({ file: fname, reason: 'Managed by the Visual Builder' });
      continue;
    }
    const content = readFileContent(st, remotePath);
    if (typeof content !== 'string') {
      skipped.push({ file: fname, reason: 'Contents not synced from the agent yet — run Sync' });
      continue;
    }

    let sites;
    try { sites = parseNginxConf(fname, content); }
    catch (err) {
      skipped.push({ file: fname, reason: `Parse error: ${err.message}` });
      continue;
    }
    if (!sites.length) {
      skipped.push({ file: fname, reason: 'No server blocks found (may be a redirect-only block)' });
      continue;
    }

    for (const site of sites) {
      const dup = existing.find(e => e.importedFrom === fname && e.serverName === site.serverName);
      if (dup) {
        skipped.push({ file: fname, reason: `Already imported (${site.name})` });
        continue;
      }
      site.confPath = remotePath;
      store.writeSite(agent.id, site);
      imported.push(site);
      existing.push(site);
    }
  }

  res.json({ imported, skipped });
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
