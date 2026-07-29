/**
 * nginx-manager — server.js
 *
 * Express backend:
 *  - /api/agents              CRUD for agent definitions (stored in agents.json)
 *  - /api/agents/:id/configs  per-agent raw config file CRUD
 *  - /api/agents/:id/certs    per-agent certificate management (scan remote + local store)
 *  - /api/agents/:id/sites    Visual-builder site CRUD (stored as JSON + auto-generates .conf)
 *  - /api/agents/:id/push     SSH-push a config file to an agent
 *  - /api/agents/:id/validate nginx -t via SSH
 *  - /api/agents/:id/reload   nginx -s reload via SSH
 *  - /api/agents/:id/status   nginx status check
 *  - Socket.IO                live log streaming for push/validate/reload/sync
 */

'use strict';

require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const bcrypt       = require('bcryptjs');
const { NodeSSH }  = require('node-ssh');
const http         = require('http');
const { Server }   = require('socket.io');
const multer       = require('multer');
const fs           = require('fs');
const path         = require('path');
const { v4: uuidv4 } = require('uuid');

// ---------------------------------------------------------------------------
// Config & directories
// ---------------------------------------------------------------------------
const PORT           = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';
const ADMIN_PASS     = process.env.ADMIN_PASSWORD || 'admin';
const DATA_DIR       = path.join(__dirname, 'data');
const AGENTS_FILE    = path.join(DATA_DIR, 'agents.json');
const CONFIGS_DIR    = path.join(DATA_DIR, 'configs');
const CERTS_DIR      = path.join(DATA_DIR, 'certs');   // uploaded certs stored locally
const SITES_DIR      = path.join(DATA_DIR, 'sites');   // visual-builder site JSON

[DATA_DIR, CONFIGS_DIR, CERTS_DIR, SITES_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

if (!fs.existsSync(AGENTS_FILE)) fs.writeFileSync(AGENTS_FILE, JSON.stringify([], null, 2));

// Multer — cert file uploads (PEM/CRT/KEY, max 1 MB each)
const certUpload = multer({
  dest: path.join(DATA_DIR, '_uploads'),
  limits: { fileSize: 1 * 1024 * 1024 },
});

// ---------------------------------------------------------------------------
// Helpers — agents
// ---------------------------------------------------------------------------
function readAgents() {
  try { return JSON.parse(fs.readFileSync(AGENTS_FILE, 'utf8')); }
  catch { return []; }
}

function writeAgents(agents) {
  fs.writeFileSync(AGENTS_FILE, JSON.stringify(agents, null, 2));
}

function agentConfigDir(agentId) {
  const d = path.join(CONFIGS_DIR, agentId);
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  return d;
}

function agentCertDir(agentId) {
  const d = path.join(CERTS_DIR, agentId);
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  return d;
}

function agentSitesDir(agentId) {
  const d = path.join(SITES_DIR, agentId);
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  return d;
}

function sudoPrefix(agent) {
  return agent.sshUser === 'root' ? '' : 'sudo ';
}

// ---------------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------------
function makeConnOpts(agent) {
  const o = { host: agent.host, port: agent.sshPort || 22, username: agent.sshUser };
  if (agent.sshKeyPath && fs.existsSync(agent.sshKeyPath)) {
    o.privateKeyPath = agent.sshKeyPath;
  } else {
    o.password = agent.sshPass;
  }
  return o;
}

async function sshExec(agent, command, emit) {
  const ssh = new NodeSSH();
  let output = '';
  try {
    await ssh.connect(makeConnOpts(agent));
    const result = await ssh.execCommand(command, {
      onStdout: c => { const l = c.toString(); output += l; if (emit) emit(l); },
      onStderr:  c => { const l = c.toString(); output += l; if (emit) emit(l); },
    });
    ssh.dispose();
    return { success: result.code === 0, code: result.code, output };
  } catch (err) {
    try { ssh.dispose(); } catch {}
    const msg = `SSH error: ${err.message}`;
    if (emit) emit(msg);
    return { success: false, code: -1, output: msg };
  }
}

// ---------------------------------------------------------------------------
// Visual-builder: generate nginx config from site definition
// ---------------------------------------------------------------------------
function siteToNginxConf(site, agent) {
  const lines = [];
  const ssl   = site.ssl && site.certFile;
  const sudo  = sudoPrefix(agent);

  const upstreamName = (site.id || site.name || 'backend').replace(/[^a-zA-Z0-9_]/g,'_');
  if (site.upstream && site.upstream.length > 1) {
    lines.push(`upstream ${upstreamName} {`);
    if (site.lbMethod && site.lbMethod !== 'round_robin') lines.push(`    ${site.lbMethod};`);
    for (const up of site.upstream) {
      lines.push(`    server ${up};`);
    }
    lines.push(`}`);
    lines.push(``);
  }

  const upstreamTarget = (site.upstream && site.upstream.length > 1)
    ? `http://${upstreamName}`
    : (site.upstream && site.upstream[0]) ? `http://${site.upstream[0]}` : null;

  // Main server block
  lines.push(`server {`);

  if (ssl) {
    lines.push(`    listen 443 ssl http2;`);
    lines.push(`    listen [::]:443 ssl http2;`);
  } else {
    lines.push(`    listen ${site.listenPort || 80};`);
    lines.push(`    listen [::]:${site.listenPort || 80};`);
  }

  if (site.serverName) lines.push(`    server_name ${site.serverName};`);

  if (ssl) {
    lines.push(``);
    lines.push(`    # SSL / TLS`);
    lines.push(`    ssl_certificate     ${site.certFile};`);
    lines.push(`    ssl_certificate_key ${site.keyFile};`);
    lines.push(`    ssl_protocols       TLSv1.2 TLSv1.3;`);
    lines.push(`    ssl_ciphers         HIGH:!aNULL:!MD5;`);
    lines.push(`    ssl_session_cache   shared:SSL:10m;`);
    lines.push(`    ssl_session_timeout 10m;`);
    if (site.hsts) {
      lines.push(`    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`);
    }
  }

  lines.push(``);
  lines.push(`    # Logging`);
  lines.push(`    access_log /var/log/nginx/${site.name.replace(/\s+/g,'_').toLowerCase()}_access.log;`);
  lines.push(`    error_log  /var/log/nginx/${site.name.replace(/\s+/g,'_').toLowerCase()}_error.log;`);

  if (site.type === 'proxy' && upstreamTarget) {
    lines.push(``);
    lines.push(`    location / {`);
    lines.push(`        proxy_pass         ${upstreamTarget};`);
    lines.push(`        proxy_http_version 1.1;`);
    lines.push(`        proxy_set_header   Upgrade $http_upgrade;`);
    lines.push(`        proxy_set_header   Connection "upgrade";`);
    lines.push(`        proxy_set_header   Host $host;`);
    lines.push(`        proxy_set_header   X-Real-IP $remote_addr;`);
    lines.push(`        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;`);
    lines.push(`        proxy_set_header   X-Forwarded-Proto $scheme;`);
    lines.push(`        proxy_read_timeout ${site.proxyTimeout || 60}s;`);
    if (site.proxyBuffering === false) {
      lines.push(`        proxy_buffering    off;`);
    }
    lines.push(`    }`);
  } else if (site.type === 'static') {
    lines.push(``);
    lines.push(`    root  ${site.staticRoot || '/var/www/html'};`);
    lines.push(`    index index.html index.htm;`);
    lines.push(``);
    lines.push(`    location / {`);
    lines.push(`        try_files $uri $uri/ =404;`);
    lines.push(`    }`);
    lines.push(``);
    lines.push(`    location ~* \\.(?:ico|css|js|gif|jpe?g|png|woff2?)$ {`);
    lines.push(`        expires 1y;`);
    lines.push(`        add_header Cache-Control "public, immutable";`);
    lines.push(`    }`);
  } else if (site.type === 'redirect') {
    lines.push(``);
    lines.push(`    return 301 ${site.redirectTo || 'https://$host$request_uri'};`);
  }

  if (site.extraDirectives) {
    lines.push(``);
    lines.push(`    # Custom directives`);
    for (const d of site.extraDirectives.split('\n').filter(l => l.trim())) {
      lines.push(`    ${d}`);
    }
  }

  lines.push(`}`);

  // HTTP → HTTPS redirect block
  if (ssl) {
    lines.push(``);
    lines.push(`server {`);
    lines.push(`    listen 80;`);
    lines.push(`    listen [::]:80;`);
    if (site.serverName) lines.push(`    server_name ${site.serverName};`);
    lines.push(`    return 301 https://$host$request_uri;`);
    lines.push(`}`);
  }

  return lines.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorised' });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { password } = req.body;
  let ok = false;
  if (ADMIN_PASS.startsWith('$2')) {
    ok = await bcrypt.compare(password, ADMIN_PASS);
  } else {
    ok = password === ADMIN_PASS;
  }
  if (!ok) return res.status(401).json({ error: 'Invalid password' });
  req.session.authenticated = true;
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

// ---------------------------------------------------------------------------
// Agent CRUD
// ---------------------------------------------------------------------------
app.get('/api/agents', requireAuth, (req, res) => {
  res.json(readAgents().map(a => ({ ...a, sshPass: a.sshPass ? '***' : undefined })));
});

app.post('/api/agents', requireAuth, (req, res) => {
  const { name, host, sshPort, sshUser, sshPass, sshKeyPath, nginxConfigPath, description } = req.body;
  if (!name || !host || !sshUser) return res.status(400).json({ error: 'name, host, sshUser required' });
  const agents = readAgents();
  const agent = {
    id: uuidv4(), name, host,
    sshPort: sshPort || 22, sshUser,
    sshPass: sshPass || '', sshKeyPath: sshKeyPath || '',
    nginxConfigPath: nginxConfigPath || '/etc/nginx',
    description: description || '',
    createdAt: new Date().toISOString(),
  };
  agents.push(agent);
  writeAgents(agents);
  res.json({ ...agent, sshPass: '***' });
});

app.put('/api/agents/:id', requireAuth, (req, res) => {
  const agents = readAgents();
  const idx = agents.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const updates = req.body;
  if (!updates.sshPass || updates.sshPass === '***') delete updates.sshPass;
  agents[idx] = { ...agents[idx], ...updates, id: agents[idx].id };
  writeAgents(agents);
  res.json({ ...agents[idx], sshPass: '***' });
});

app.delete('/api/agents/:id', requireAuth, (req, res) => {
  const agents = readAgents();
  const newAgents = agents.filter(a => a.id !== req.params.id);
  if (newAgents.length === agents.length) return res.status(404).json({ error: 'Not found' });
  writeAgents(newAgents);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Config file CRUD
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/configs', requireAuth, (req, res) => {
  if (!readAgents().find(a => a.id === req.params.id)) return res.status(404).json({ error: 'Agent not found' });
  const dir = agentConfigDir(req.params.id);
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.conf') || f.endsWith('.nginx'));
  res.json(files.map(f => {
    const stat = fs.statSync(path.join(dir, f));
    return { name: f, size: stat.size, modified: stat.mtime.toISOString() };
  }));
});

app.get('/api/agents/:id/configs/:filename', requireAuth, (req, res) => {
  const filePath = path.join(agentConfigDir(req.params.id), path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  res.json({ name: req.params.filename, content: fs.readFileSync(filePath, 'utf8') });
});

app.put('/api/agents/:id/configs/:filename', requireAuth, (req, res) => {
  const { content } = req.body;
  if (content === undefined) return res.status(400).json({ error: 'content required' });
  const filePath = path.join(agentConfigDir(req.params.id), path.basename(req.params.filename));
  fs.writeFileSync(filePath, content, 'utf8');
  res.json({ ok: true, name: req.params.filename });
});

app.delete('/api/agents/:id/configs/:filename', requireAuth, (req, res) => {
  const filePath = path.join(agentConfigDir(req.params.id), path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  fs.unlinkSync(filePath);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Certificate management
// ---------------------------------------------------------------------------

// List certs stored locally for this agent
app.get('/api/agents/:id/certs', requireAuth, (req, res) => {
  if (!readAgents().find(a => a.id === req.params.id)) return res.status(404).json({ error: 'Agent not found' });
  const dir = agentCertDir(req.params.id);
  const metaFile = path.join(dir, 'certs.json');
  let certs = [];
  try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
  res.json(certs);
});

// Upload a cert+key pair
app.post('/api/agents/:id/certs', requireAuth,
  certUpload.fields([
    { name: 'certFile', maxCount: 1 },
    { name: 'keyFile',  maxCount: 1 },
    { name: 'chainFile', maxCount: 1 },
  ]),
  (req, res) => {
    const agent = readAgents().find(a => a.id === req.params.id);
    if (!agent) return res.status(404).json({ error: 'Agent not found' });

    const { label, remoteCertPath, remoteKeyPath } = req.body;
    if (!label) return res.status(400).json({ error: 'label required' });

    const dir    = agentCertDir(req.params.id);
    const certId = uuidv4();
    const certEntry = {
      id: certId,
      label,
      createdAt: new Date().toISOString(),
      // remote paths (where nginx expects the cert on the server)
      remoteCertPath: remoteCertPath || '',
      remoteKeyPath:  remoteKeyPath  || '',
      // local stored filenames
      localCert:  null,
      localKey:   null,
      localChain: null,
    };

    const move = (fieldName, suffix) => {
      if (req.files && req.files[fieldName] && req.files[fieldName][0]) {
        const tmp = req.files[fieldName][0].path;
        const dest = path.join(dir, `${certId}_${suffix}`);
        fs.renameSync(tmp, dest);
        return dest;
      }
      return null;
    };

    certEntry.localCert  = move('certFile',  'cert.pem');
    certEntry.localKey   = move('keyFile',   'key.pem');
    certEntry.localChain = move('chainFile', 'chain.pem');

    // Load existing and append
    const metaFile = path.join(dir, 'certs.json');
    let certs = [];
    try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
    certs.push(certEntry);
    fs.writeFileSync(metaFile, JSON.stringify(certs, null, 2));

    res.json(certEntry);
  }
);

// Manually register a cert that already exists on the remote server (no upload)
app.post('/api/agents/:id/certs/remote', requireAuth, (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const { label, remoteCertPath, remoteKeyPath } = req.body;
  if (!label || !remoteCertPath || !remoteKeyPath)
    return res.status(400).json({ error: 'label, remoteCertPath, remoteKeyPath required' });

  const dir      = agentCertDir(req.params.id);
  const metaFile = path.join(dir, 'certs.json');
  let certs = [];
  try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}

  const cert = {
    id: uuidv4(), label,
    remoteCertPath, remoteKeyPath,
    localCert: null, localKey: null, localChain: null,
    createdAt: new Date().toISOString(),
    remoteOnly: true,
  };
  certs.push(cert);
  fs.writeFileSync(metaFile, JSON.stringify(certs, null, 2));
  res.json(cert);
});

// Scan the remote server for existing certs (looks in common paths)
app.post('/api/agents/:id/certs/scan', requireAuth, async (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const sudo = sudoPrefix(agent);

  // Restricted to /etc/ssl/nginx and /etc/letsencrypt (all subdirectories)
  const scanCmd = `${sudo}find /etc/ssl/nginx /etc/letsencrypt ` +
    `\\( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.key" \\) ` +
    `2>/dev/null | sort`;

  const result = await sshExec(agent, scanCmd);
  const files  = result.output.trim().split('\n').filter(f => f.trim());

  // ── Heuristics to match cert+key pairs ──────────────────────────────────
  // A file is a "cert" if its basename contains: fullchain, cert, crt, certificate
  // or the extension is .crt/.cer, and it does NOT look like a key.
  // A file is a "key" if its basename contains: privkey, key, private.
  const isCert = f => {
    const b = path.basename(f).toLowerCase();
    return !b.includes('key') && !b.includes('private') &&
      (b.includes('fullchain') || b.includes('cert') || b.includes('crt') ||
       b.includes('certificate') || b.endsWith('.crt') || b.endsWith('.cer') ||
       (b.endsWith('.pem') && !b.includes('chain') === false) ||
       b.endsWith('.pem'));
  };
  const isKey = f => {
    const b = path.basename(f).toLowerCase();
    return b.includes('privkey') || b.includes('private') || b.includes('.key') ||
      (b.includes('key') && b.endsWith('.pem'));
  };

  // Group by directory
  const byDir = {};
  for (const f of files) {
    const d = path.dirname(f);
    if (!byDir[d]) byDir[d] = [];
    byDir[d].push(f);
  }

  // Build suggestions — prefer fullchain.pem + privkey.pem (Let's Encrypt layout)
  const suggestions = Object.entries(byDir).map(([dir, dirFiles]) => {
    const certs = dirFiles.filter(isCert);
    const keys  = dirFiles.filter(isKey);

    // Best cert: prefer fullchain.pem, then cert.pem, then first cert found
    const bestCert = certs.find(f => path.basename(f) === 'fullchain.pem')
      || certs.find(f => path.basename(f).startsWith('cert'))
      || certs[0];

    // Best key: prefer privkey.pem, then first key found
    const bestKey = keys.find(f => path.basename(f) === 'privkey.pem')
      || keys.find(f => path.basename(f).includes('privkey'))
      || keys[0];

    return { dir, files: dirFiles, certs, keys, bestCert, bestKey };
  }).filter(s => s.certs.length > 0 || s.keys.length > 0);

  // ── Auto-register valid pairs that aren't already stored ────────────────
  const autoRegistered = [];
  if (suggestions.length > 0) {
    const certDir  = agentCertDir(req.params.id);
    const metaFile = path.join(certDir, 'certs.json');
    let stored = [];
    try { stored = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}

    for (const sg of suggestions) {
      if (!sg.bestCert || !sg.bestKey) continue;

      // Skip if this cert path is already registered
      const alreadyExists = stored.some(c =>
        c.remoteCertPath === sg.bestCert && c.remoteKeyPath === sg.bestKey
      );
      if (alreadyExists) continue;

      // Derive a readable label from the directory name
      //  /etc/letsencrypt/live/example.com → "example.com"
      //  /etc/ssl/nginx/mysite             → "mysite"
      const dirParts = sg.dir.split('/').filter(Boolean);
      const label    = dirParts[dirParts.length - 1] || sg.dir;

      const newCert = {
        id:             uuidv4(),
        label,
        remoteCertPath: sg.bestCert,
        remoteKeyPath:  sg.bestKey,
        remoteChainPath: sg.certs.find(f => path.basename(f).includes('chain') && f !== sg.bestCert) || null,
        localCert:      null,
        localKey:       null,
        localChain:     null,
        createdAt:      new Date().toISOString(),
        remoteOnly:     true,
        autoDiscovered: true,
      };
      stored.push(newCert);
      autoRegistered.push(newCert);
    }

    if (autoRegistered.length > 0) {
      fs.writeFileSync(metaFile, JSON.stringify(stored, null, 2));
    }
  }

  res.json({ files, suggestions, autoRegistered });
});

// Push a locally-stored cert to the remote server
app.post('/api/agents/:id/certs/:certId/push', requireAuth, async (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const dir      = agentCertDir(req.params.id);
  const metaFile = path.join(dir, 'certs.json');
  let certs = [];
  try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
  const cert = certs.find(c => c.id === req.params.certId);
  if (!cert) return res.status(404).json({ error: 'Cert not found' });
  if (!cert.localCert || !cert.localKey)
    return res.status(400).json({ error: 'No local cert/key files uploaded for this cert' });
  if (!cert.remoteCertPath || !cert.remoteKeyPath)
    return res.status(400).json({ error: 'remoteCertPath and remoteKeyPath must be set' });

  const sudo = sudoPrefix(agent);
  const ssh  = new NodeSSH();
  const log  = [];
  try {
    await ssh.connect(makeConnOpts(agent));

    // Ensure remote directories exist
    const certDir = path.dirname(cert.remoteCertPath);
    const keyDir  = path.dirname(cert.remoteKeyPath);
    await ssh.execCommand(`${sudo}mkdir -p ${certDir} ${keyDir}`);

    // Upload cert
    const certContent = fs.readFileSync(cert.localCert, 'utf8');
    const r1 = await ssh.execCommand(
      `${sudo}tee ${cert.remoteCertPath} > /dev/null << 'PEMEOF'\n${certContent}\nPEMEOF`
    );
    log.push(`cert: ${r1.code === 0 ? 'uploaded' : r1.stderr}`);

    // Upload key
    const keyContent = fs.readFileSync(cert.localKey, 'utf8');
    const r2 = await ssh.execCommand(
      `${sudo}tee ${cert.remoteKeyPath} > /dev/null << 'PEMEOF'\n${keyContent}\nPEMEOF`
    );
    log.push(`key: ${r2.code === 0 ? 'uploaded' : r2.stderr}`);

    // Set correct permissions on key
    await ssh.execCommand(`${sudo}chmod 600 ${cert.remoteKeyPath}`);

    // Upload chain if present
    if (cert.localChain && cert.remoteChainPath) {
      const chain = fs.readFileSync(cert.localChain, 'utf8');
      const r3 = await ssh.execCommand(
        `${sudo}tee ${cert.remoteChainPath} > /dev/null << 'PEMEOF'\n${chain}\nPEMEOF`
      );
      log.push(`chain: ${r3.code === 0 ? 'uploaded' : r3.stderr}`);
    }

    ssh.dispose();
    res.json({ ok: true, log });
  } catch (err) {
    try { ssh.dispose(); } catch {}
    res.status(500).json({ error: err.message, log });
  }
});

// Delete a locally-stored cert entry
app.delete('/api/agents/:id/certs/:certId', requireAuth, (req, res) => {
  const dir      = agentCertDir(req.params.id);
  const metaFile = path.join(dir, 'certs.json');
  let certs = [];
  try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
  const cert = certs.find(c => c.id === req.params.certId);
  if (!cert) return res.status(404).json({ error: 'Cert not found' });

  // Remove local files
  [cert.localCert, cert.localKey, cert.localChain].filter(Boolean).forEach(f => {
    try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch {}
  });

  fs.writeFileSync(metaFile, JSON.stringify(certs.filter(c => c.id !== req.params.certId), null, 2));
  res.json({ ok: true });
});

// Update a cert entry (label, remote paths)
app.put('/api/agents/:id/certs/:certId', requireAuth, (req, res) => {
  const dir      = agentCertDir(req.params.id);
  const metaFile = path.join(dir, 'certs.json');
  let certs = [];
  try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
  const idx = certs.findIndex(c => c.id === req.params.certId);
  if (idx === -1) return res.status(404).json({ error: 'Cert not found' });
  const { label, remoteCertPath, remoteKeyPath, remoteChainPath } = req.body;
  if (label)           certs[idx].label           = label;
  if (remoteCertPath)  certs[idx].remoteCertPath  = remoteCertPath;
  if (remoteKeyPath)   certs[idx].remoteKeyPath   = remoteKeyPath;
  if (remoteChainPath) certs[idx].remoteChainPath = remoteChainPath;
  fs.writeFileSync(metaFile, JSON.stringify(certs, null, 2));
  res.json(certs[idx]);
});

// ---------------------------------------------------------------------------
// Visual-builder Sites CRUD
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/sites', requireAuth, (req, res) => {
  if (!readAgents().find(a => a.id === req.params.id)) return res.status(404).json({ error: 'Agent not found' });
  const dir = agentSitesDir(req.params.id);
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  const sites = files.map(f => {
    try { return JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); }
    catch { return null; }
  }).filter(Boolean);
  res.json(sites);
});

app.post('/api/agents/:id/sites', requireAuth, (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const site = {
    id:              uuidv4(),
    name:            req.body.name            || 'New Site',
    type:            req.body.type            || 'proxy',      // proxy | static | redirect
    serverName:      req.body.serverName      || '',
    listenPort:      req.body.listenPort      || 80,
    upstream:        req.body.upstream        || [],           // array of host:port
    lbMethod:        req.body.lbMethod        || 'round_robin',
    staticRoot:      req.body.staticRoot      || '/var/www/html',
    redirectTo:      req.body.redirectTo      || '',
    ssl:             req.body.ssl             || false,
    certId:          req.body.certId          || null,         // links to certs store
    certFile:        req.body.certFile        || '',           // remote path
    keyFile:         req.body.keyFile         || '',           // remote path
    hsts:            req.body.hsts            || false,
    proxyTimeout:    req.body.proxyTimeout    || 60,
    proxyBuffering:  req.body.proxyBuffering  !== false,
    extraDirectives: req.body.extraDirectives || '',
    enabled:         req.body.enabled         !== false,
    createdAt:       new Date().toISOString(),
    updatedAt:       new Date().toISOString(),
  };

  const dir      = agentSitesDir(req.params.id);
  const siteFile = path.join(dir, `${site.id}.json`);
  fs.writeFileSync(siteFile, JSON.stringify(site, null, 2));

  // Also write generated config
  const confDir  = agentConfigDir(req.params.id);
  const confFile = path.join(confDir, `site_${site.name.replace(/[^a-zA-Z0-9_-]/g,'_')}.conf`);
  fs.writeFileSync(confFile, siteToNginxConf(site, agent));

  res.json(site);
});

app.put('/api/agents/:id/sites/:siteId', requireAuth, (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const dir      = agentSitesDir(req.params.id);
  const siteFile = path.join(dir, `${req.params.siteId}.json`);
  if (!fs.existsSync(siteFile)) return res.status(404).json({ error: 'Site not found' });

  const existing = JSON.parse(fs.readFileSync(siteFile, 'utf8'));
  const site = { ...existing, ...req.body, id: existing.id, createdAt: existing.createdAt, updatedAt: new Date().toISOString() };

  // If SSL enabled and certId provided, resolve cert paths
  if (site.ssl && site.certId) {
    const certDir  = agentCertDir(req.params.id);
    const metaFile = path.join(certDir, 'certs.json');
    let certs = [];
    try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
    const cert = certs.find(c => c.id === site.certId);
    if (cert) {
      site.certFile = cert.remoteCertPath || site.certFile;
      site.keyFile  = cert.remoteKeyPath  || site.keyFile;
    }
  }

  fs.writeFileSync(siteFile, JSON.stringify(site, null, 2));

  // Regenerate the config file (delete old name if it changed)
  const confDir    = agentConfigDir(req.params.id);
  const oldConf    = path.join(confDir, `site_${existing.name.replace(/[^a-zA-Z0-9_-]/g,'_')}.conf`);
  const newConf    = path.join(confDir, `site_${site.name.replace(/[^a-zA-Z0-9_-]/g,'_')}.conf`);
  if (oldConf !== newConf && fs.existsSync(oldConf)) fs.unlinkSync(oldConf);
  fs.writeFileSync(newConf, siteToNginxConf(site, agent));

  res.json(site);
});

app.delete('/api/agents/:id/sites/:siteId', requireAuth, (req, res) => {
  const dir      = agentSitesDir(req.params.id);
  const siteFile = path.join(dir, `${req.params.siteId}.json`);
  if (!fs.existsSync(siteFile)) return res.status(404).json({ error: 'Site not found' });

  const site = JSON.parse(fs.readFileSync(siteFile, 'utf8'));
  fs.unlinkSync(siteFile);

  // Remove generated config
  const confFile = path.join(agentConfigDir(req.params.id), `site_${site.name.replace(/[^a-zA-Z0-9_-]/g,'_')}.conf`);
  try { if (fs.existsSync(confFile)) fs.unlinkSync(confFile); } catch {}

  res.json({ ok: true });
});

// Preview generated config without saving
app.post('/api/agents/:id/sites/preview', requireAuth, (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  try {
    const conf = siteToNginxConf(req.body, agent);
    res.json({ conf });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Import conf.d files from the remote server into the Visual Builder
// ---------------------------------------------------------------------------
// Lightweight nginx conf parser — extracts the key fields we care about.
function parseNginxConf(filename, raw) {
  const text  = raw.replace(/#[^\n]*/g, '');   // strip comments
  const lines = text.replace(/\r/g, '').split('\n').map(l => l.trim()).filter(Boolean);

  // Helper: grab first match of a directive inside a block string
  const directive = (block, name) => {
    const m = block.match(new RegExp(`(?:^|\\n)\\s*${name}\\s+([^;{\\n]+);`));
    return m ? m[1].trim() : null;
  };

  // Split into top-level upstream{} blocks and server{} blocks
  const upstreamBlocks = [];
  const serverBlocks   = [];

  let depth = 0, blockStart = -1, blockType = null;
  const joined = lines.join('\n');

  for (let i = 0; i < joined.length; i++) {
    const ch = joined[i];
    if (ch === '{') {
      if (depth === 0) {
        // Grab the keyword before this {
        const before = joined.slice(Math.max(0, i - 80), i).trim();
        const typeMatch = before.match(/(upstream|server)\s*\S*\s*$/i);
        blockType  = typeMatch ? typeMatch[1].toLowerCase() : 'unknown';
        blockStart = i + 1;
      }
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && blockStart >= 0) {
        const block = joined.slice(blockStart, i).trim();
        if (blockType === 'upstream') upstreamBlocks.push(block);
        else if (blockType === 'server') serverBlocks.push(block);
        blockStart = -1; blockType = null;
      }
    }
  }

  const sites = [];

  for (const sb of serverBlocks) {
    // Listen port
    const listenMatch = sb.match(/listen\s+([\d.]*:?(\d+))\s*([^;]*)?;/i);
    const listenRaw   = listenMatch ? listenMatch[1] : '80';
    const isSSL       = sb.includes('ssl') || /listen\s+[^;]*ssl/.test(sb);
    const listenPort  = parseInt(listenRaw.replace(/.*:/, '')) || (isSSL ? 443 : 80);

    // Skip pure HTTP→HTTPS redirects (return 301 https)
    if (/return\s+301\s+https/.test(sb) && !isSSL) continue;

    const serverName = directive(sb, 'server_name') || '';

    // Detect type
    let type       = 'proxy';
    let upstream   = [];
    let staticRoot = '';
    let redirectTo = '';

    const proxyPass  = directive(sb, 'proxy_pass');
    const root       = directive(sb, 'root');
    const returnDir  = directive(sb, 'return');

    if (returnDir && /https?:\/\//.test(returnDir)) {
      type = 'redirect';
      redirectTo = returnDir.replace(/^3\d\d\s+/, '').trim();
    } else if (proxyPass) {
      type = 'proxy';
      // proxyPass may be http://upstream_name or http://host:port
      const dest = proxyPass.replace(/^https?:\/\//, '');
      // Check if it references an upstream block
      const upBlock = upstreamBlocks.find(ub => {
        const nm = joined.slice(0, joined.indexOf(ub) - 1)
          .split('\n').reverse().find(l => l.trim().startsWith('upstream'));
        return nm && nm.includes(dest.split('/')[0]);
      });
      if (upBlock) {
        upstream = [...upBlock.matchAll(/server\s+([^;]+);/g)].map(m => m[1].trim());
      } else {
        upstream = [dest.split('/')[0]];
      }
    } else if (root) {
      type = 'static';
      staticRoot = root;
    }

    // SSL cert paths
    const certFile = directive(sb, 'ssl_certificate(?!_key)') ||
                     (sb.match(/ssl_certificate\s+(?!_key)([^;]+);/) || [])[1]?.trim() || '';
    const keyFile  = directive(sb, 'ssl_certificate_key') || '';
    const hsts     = /Strict-Transport-Security/.test(sb);

    // Load balance method
    let lbMethod = 'round_robin';
    const lbBlock = upstreamBlocks[0] || '';
    if (/least_conn/.test(lbBlock))  lbMethod = 'least_conn';
    if (/ip_hash/.test(lbBlock))     lbMethod = 'ip_hash';

    // Proxy timeout
    const timeoutMatch = sb.match(/proxy_read_timeout\s+(\d+)/);
    const proxyTimeout = timeoutMatch ? parseInt(timeoutMatch[1]) : 60;

    const siteName = serverName
      ? serverName.split(/\s+/)[0].replace(/[^a-zA-Z0-9._-]/g, '')
      : filename.replace(/\.conf$/, '');

    sites.push({
      id:             uuidv4(),
      name:           siteName || filename.replace(/\.conf$/, ''),
      type,
      serverName,
      listenPort,
      upstream,
      lbMethod,
      staticRoot,
      redirectTo,
      ssl:            isSSL && !!(certFile || keyFile),
      certId:         null,
      certFile:       certFile.trim(),
      keyFile:        keyFile.trim(),
      hsts,
      proxyTimeout,
      proxyBuffering: true,
      extraDirectives: '',
      enabled:        true,
      createdAt:      new Date().toISOString(),
      updatedAt:      new Date().toISOString(),
      importedFrom:   filename,
    });
  }

  return sites;
}

app.post('/api/agents/:id/sites/import', requireAuth, async (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  const sudo       = sudoPrefix(agent);
  const confDir    = `${agent.nginxConfigPath}/conf.d`;

  // List all .conf files in conf.d
  const listResult = await sshExec(agent, `ls ${confDir}/*.conf 2>/dev/null`);
  const confFiles  = listResult.output.trim().split('\n')
    .map(f => f.trim()).filter(f => f.endsWith('.conf'));

  if (!confFiles.length) {
    return res.json({ imported: [], skipped: [], message: `No .conf files found in ${confDir}` });
  }

  // Load existing sites so we can skip duplicates
  const sitesDir = agentSitesDir(req.params.id);
  const existing = fs.readdirSync(sitesDir)
    .filter(f => f.endsWith('.json'))
    .flatMap(f => {
      try { return [JSON.parse(fs.readFileSync(path.join(sitesDir, f), 'utf8'))]; }
      catch { return []; }
    });

  const imported = [];
  const skipped  = [];

  for (const remotePath of confFiles) {
    const fname = path.basename(remotePath);

    // Read the conf file content via SSH
    const catResult = await sshExec(agent, `${sudo}cat ${remotePath}`);
    if (catResult.code !== 0) {
      skipped.push({ file: fname, reason: `Could not read: ${catResult.output.trim()}` });
      continue;
    }

    // Parse the conf into site definition(s)
    let sites;
    try { sites = parseNginxConf(fname, catResult.output); }
    catch (err) {
      skipped.push({ file: fname, reason: `Parse error: ${err.message}` });
      continue;
    }

    if (!sites.length) {
      skipped.push({ file: fname, reason: 'No server blocks found (may be a redirect-only block)' });
      continue;
    }

    for (const site of sites) {
      // Skip if a site with the same name + importedFrom is already stored
      const dup = existing.find(e =>
        e.importedFrom === fname && e.serverName === site.serverName
      );
      if (dup) {
        skipped.push({ file: fname, reason: `Already imported (${site.name})` });
        continue;
      }

      // Write site JSON
      const siteFile = path.join(sitesDir, `${site.id}.json`);
      fs.writeFileSync(siteFile, JSON.stringify(site, null, 2));

      // Also store a local copy of the raw conf (don't overwrite if it already exists)
      const localConf = path.join(agentConfigDir(req.params.id), fname);
      if (!fs.existsSync(localConf)) {
        fs.writeFileSync(localConf, catResult.output, 'utf8');
      }

      imported.push(site);
      existing.push(site);   // prevent double-import within the same request
    }
  }

  res.json({ imported, skipped });
});

// ---------------------------------------------------------------------------
// SSH operations — Socket.IO
// ---------------------------------------------------------------------------
io.on('connection', (socket) => {

  socket.on('push', async ({ agentId, filename, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agents = readAgents();
    const agent  = agents.find(a => a.id === agentId);
    if (!agent)  { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    const localPath = path.join(agentConfigDir(agentId), path.basename(filename));
    if (!fs.existsSync(localPath)) { socket.emit('done', { success: false, output: 'Local config not found' }); return; }

    const content    = fs.readFileSync(localPath, 'utf8');
    const remotePath = `${agent.nginxConfigPath}/conf.d/${filename}`;
    socket.emit('log', `📤 Pushing ${filename} → ${agent.host}:${remotePath}\n`);

    const ssh = new NodeSSH();
    try {
      await ssh.connect(makeConnOpts(agent));
      socket.emit('log', `✅ SSH connected to ${agent.host}\n`);

      const sudo    = sudoPrefix(agent);
      const escaped = content.replace(/\\/g, '\\\\').replace(/'/g, "'\\''");
      const wRes    = await ssh.execCommand(`printf '%s' '${escaped}' | ${sudo}tee ${remotePath} > /dev/null && echo "Written OK"`);
      if (wRes.code !== 0) {
        socket.emit('log', `❌ Write failed: ${wRes.stderr}\n`);
        ssh.dispose();
        socket.emit('done', { success: false, output: wRes.stderr });
        return;
      }
      socket.emit('log', `✅ File written to ${remotePath}\n`);

      socket.emit('log', `🔍 Running nginx -t...\n`);
      const tRes = await ssh.execCommand(`${sudo}nginx -t 2>&1`);
      const tOut = tRes.stdout + tRes.stderr;
      socket.emit('log', tOut + '\n');

      if (tRes.code !== 0) {
        socket.emit('log', `❌ nginx config test failed — NOT reloading\n`);
        ssh.dispose();
        socket.emit('done', { success: false, output: tOut });
        return;
      }

      socket.emit('log', `🔄 Reloading nginx...\n`);
      const rRes = await ssh.execCommand(`${sudo}nginx -s reload 2>&1`);
      socket.emit('log', (rRes.stdout + rRes.stderr) + '\n');

      if (rRes.code === 0) {
        socket.emit('log', `✅ nginx reloaded successfully!\n`);
        socket.emit('done', { success: true, output: tOut });
      } else {
        socket.emit('log', `❌ Reload failed\n`);
        socket.emit('done', { success: false, output: rRes.stdout + rRes.stderr });
      }
      ssh.dispose();
    } catch (err) {
      socket.emit('log', `❌ Error: ${err.message}\n`);
      socket.emit('done', { success: false, output: err.message });
      try { ssh.dispose(); } catch {}
    }
  });

  socket.on('validate', async ({ agentId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agent = readAgents().find(a => a.id === agentId);
    if (!agent)  { socket.emit('done', { success: false, output: 'Agent not found' }); return; }
    socket.emit('log', `🔍 Validating nginx config on ${agent.host}...\n`);
    socket.emit('done', await sshExec(agent, `${sudoPrefix(agent)}nginx -t 2>&1`, l => socket.emit('log', l)));
  });

  socket.on('reload', async ({ agentId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agent = readAgents().find(a => a.id === agentId);
    if (!agent)  { socket.emit('done', { success: false, output: 'Agent not found' }); return; }
    socket.emit('log', `🔄 Reloading nginx on ${agent.host}...\n`);
    socket.emit('done', await sshExec(agent, `${sudoPrefix(agent)}nginx -s reload 2>&1`, l => socket.emit('log', l)));
  });

  socket.on('sync', async ({ agentId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agent = readAgents().find(a => a.id === agentId);
    if (!agent)  { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    socket.emit('log', `🔄 Syncing configs from ${agent.host}...\n`);
    const ssh = new NodeSSH();
    try {
      await ssh.connect(makeConnOpts(agent));
      socket.emit('log', `✅ SSH connected\n`);

      const sudo    = sudoPrefix(agent);
      const listRes = await ssh.execCommand(
        `ls ${agent.nginxConfigPath}/conf.d/*.conf ${agent.nginxConfigPath}/conf.d/*.nginx ${agent.nginxConfigPath}/*.conf 2>/dev/null`
      );
      const files = listRes.stdout.trim().split('\n').filter(f => f.trim() && !f.includes('No such'));

      if (!files.length) {
        socket.emit('log', `ℹ️  No .conf files found — pulling nginx.conf\n`);
        const mRes = await ssh.execCommand(`${sudo}cat ${agent.nginxConfigPath}/nginx.conf 2>/dev/null`);
        if (mRes.code === 0) {
          fs.writeFileSync(path.join(agentConfigDir(agentId), 'nginx.conf'), mRes.stdout, 'utf8');
          socket.emit('log', `✅ Synced nginx.conf\n`);
        }
      } else {
        const dir = agentConfigDir(agentId);
        for (const fp of files) {
          const fname = path.basename(fp);
          const cRes  = await ssh.execCommand(`${sudo}cat ${fp}`);
          if (cRes.code === 0) {
            fs.writeFileSync(path.join(dir, fname), cRes.stdout, 'utf8');
            socket.emit('log', `✅ Synced ${fname}\n`);
          } else {
            socket.emit('log', `⚠️  Could not read ${fname}: ${cRes.stderr}\n`);
          }
        }
      }

      ssh.dispose();
      socket.emit('done', { success: true, output: 'Sync complete' });
    } catch (err) {
      socket.emit('log', `❌ Error: ${err.message}\n`);
      socket.emit('done', { success: false, output: err.message });
      try { ssh.dispose(); } catch {}
    }
  });

  socket.on('status', async ({ agentId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agent = readAgents().find(a => a.id === agentId);
    if (!agent)  { socket.emit('done', { success: false, output: 'Agent not found' }); return; }
    const s = sudoPrefix(agent);
    socket.emit('done', await sshExec(
      agent,
      `${s}systemctl is-active nginx && ${s}nginx -v 2>&1 && ${s}systemctl status nginx --no-pager -l 2>&1 | head -20`,
      l => socket.emit('log', l)
    ));
  });

  socket.on('pushCert', async ({ agentId, certId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agent = readAgents().find(a => a.id === agentId);
    if (!agent)  { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    const dir      = agentCertDir(agentId);
    const metaFile = path.join(dir, 'certs.json');
    let certs = [];
    try { certs = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch {}
    const cert = certs.find(c => c.id === certId);
    if (!cert)             { socket.emit('done', { success: false, output: 'Cert not found' }); return; }
    if (!cert.localCert)   { socket.emit('done', { success: false, output: 'No cert file uploaded' }); return; }
    if (!cert.remoteCertPath || !cert.remoteKeyPath) {
      socket.emit('done', { success: false, output: 'Remote cert/key paths not set' });
      return;
    }

    const ssh  = new NodeSSH();
    const sudo = sudoPrefix(agent);
    try {
      await ssh.connect(makeConnOpts(agent));
      socket.emit('log', `✅ SSH connected\n`);

      const ensureDir = async p => {
        await ssh.execCommand(`${sudo}mkdir -p ${path.dirname(p)} && ${sudo}chmod 755 ${path.dirname(p)}`);
      };

      socket.emit('log', `📤 Uploading certificate...\n`);
      await ensureDir(cert.remoteCertPath);
      const certContent = fs.readFileSync(cert.localCert, 'utf8');
      const r1 = await ssh.execCommand(
        `${sudo}tee ${cert.remoteCertPath} > /dev/null << 'PEMEOF'\n${certContent}\nPEMEOF\necho written`
      );
      socket.emit('log', r1.code === 0 ? `✅ Certificate written to ${cert.remoteCertPath}\n` : `❌ ${r1.stderr}\n`);

      socket.emit('log', `📤 Uploading private key...\n`);
      await ensureDir(cert.remoteKeyPath);
      const keyContent = fs.readFileSync(cert.localKey, 'utf8');
      const r2 = await ssh.execCommand(
        `${sudo}tee ${cert.remoteKeyPath} > /dev/null << 'PEMEOF'\n${keyContent}\nPEMEOF\n${sudo}chmod 600 ${cert.remoteKeyPath} && echo written`
      );
      socket.emit('log', r2.code === 0 ? `✅ Key written to ${cert.remoteKeyPath} (chmod 600)\n` : `❌ ${r2.stderr}\n`);

      if (cert.localChain && cert.remoteChainPath) {
        socket.emit('log', `📤 Uploading chain...\n`);
        await ensureDir(cert.remoteChainPath);
        const chainContent = fs.readFileSync(cert.localChain, 'utf8');
        const r3 = await ssh.execCommand(
          `${sudo}tee ${cert.remoteChainPath} > /dev/null << 'PEMEOF'\n${chainContent}\nPEMEOF\necho written`
        );
        socket.emit('log', r3.code === 0 ? `✅ Chain written to ${cert.remoteChainPath}\n` : `❌ ${r3.stderr}\n`);
      }

      ssh.dispose();
      socket.emit('done', { success: r1.code === 0 && r2.code === 0, output: 'Cert push complete' });
    } catch (err) {
      socket.emit('log', `❌ Error: ${err.message}\n`);
      socket.emit('done', { success: false, output: err.message });
      try { ssh.dispose(); } catch {}
    }
  });
});

// ---------------------------------------------------------------------------
// REST fallbacks
// ---------------------------------------------------------------------------
app.post('/api/agents/:id/validate', requireAuth, async (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  res.json(await sshExec(agent, `${sudoPrefix(agent)}nginx -t 2>&1`));
});

app.post('/api/agents/:id/reload', requireAuth, async (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  res.json(await sshExec(agent, `${sudoPrefix(agent)}nginx -s reload 2>&1`));
});

app.get('/api/agents/:id/status', requireAuth, async (req, res) => {
  const agent = readAgents().find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  res.json(await sshExec(agent, `${sudoPrefix(agent)}systemctl is-active nginx 2>&1 && ${sudoPrefix(agent)}nginx -v 2>&1`));
});

// ---------------------------------------------------------------------------
// SPA catch-all
// ---------------------------------------------------------------------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`nginx-manager listening on http://0.0.0.0:${PORT}`);
});
