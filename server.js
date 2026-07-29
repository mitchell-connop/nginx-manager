/**
 * nginx-manager — server.js
 * 
 * Express backend:
 *  - /api/agents        CRUD for agent definitions (stored in agents.json)
 *  - /api/configs       per-agent config CRUD
 *  - /api/push          SSH-push a config file to an agent
 *  - /api/validate      nginx -t via SSH on an agent
 *  - /api/reload        nginx -s reload via SSH on an agent
 *  - /api/sync          pull live config from an agent
 *  - /api/status        nginx status check
 *  - Socket.IO          live log streaming for push/validate/reload
 */

'use strict';

require('dotenv').config();

const express   = require('express');
const session   = require('express-session');
const bcrypt    = require('bcryptjs');
const { NodeSSH } = require('node-ssh');
const http      = require('http');
const { Server } = require('socket.io');
const fs        = require('fs');
const path      = require('path');
const { v4: uuidv4 } = require('uuid');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT           = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';
const ADMIN_PASS     = process.env.ADMIN_PASSWORD || 'admin';
const DATA_DIR       = path.join(__dirname, 'data');
const AGENTS_FILE    = path.join(DATA_DIR, 'agents.json');
const CONFIGS_DIR    = path.join(DATA_DIR, 'configs');

[DATA_DIR, CONFIGS_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

if (!fs.existsSync(AGENTS_FILE)) fs.writeFileSync(AGENTS_FILE, JSON.stringify([], null, 2));

// ---------------------------------------------------------------------------
// Helpers
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

async function sshExec(agent, command, emit) {
  const ssh = new NodeSSH();
  const connOpts = {
    host: agent.host,
    port: agent.sshPort || 22,
    username: agent.sshUser,
  };
  if (agent.sshKeyPath && fs.existsSync(agent.sshKeyPath)) {
    connOpts.privateKeyPath = agent.sshKeyPath;
  } else {
    connOpts.password = agent.sshPass;
  }

  let output = '';
  try {
    await ssh.connect(connOpts);
    const result = await ssh.execCommand(command, {
      onStdout: chunk => { const l = chunk.toString(); output += l; if (emit) emit(l); },
      onStderr: chunk => { const l = chunk.toString(); output += l; if (emit) emit(l); },
    });
    ssh.dispose();
    return { success: result.code === 0, code: result.code, output };
  } catch (err) {
    if (ssh) ssh.dispose();
    const msg = `SSH error: ${err.message}`;
    if (emit) emit(msg);
    return { success: false, code: -1, output: msg };
  }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
}));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorised' });
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { password } = req.body;
  // Simple single-user auth: compare against ADMIN_PASSWORD (plain or bcrypt hash)
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

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

// ---------------------------------------------------------------------------
// Agent CRUD
// ---------------------------------------------------------------------------
app.get('/api/agents', requireAuth, (req, res) => {
  const agents = readAgents().map(a => ({
    ...a,
    sshPass: a.sshPass ? '***' : undefined,
  }));
  res.json(agents);
});

app.post('/api/agents', requireAuth, (req, res) => {
  const { name, host, sshPort, sshUser, sshPass, sshKeyPath, nginxConfigPath, description } = req.body;
  if (!name || !host || !sshUser) return res.status(400).json({ error: 'name, host, sshUser required' });
  const agents = readAgents();
  const agent = {
    id: uuidv4(),
    name,
    host,
    sshPort: sshPort || 22,
    sshUser,
    sshPass: sshPass || '',
    sshKeyPath: sshKeyPath || '',
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
  // Don't overwrite password if not provided
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
// Config file CRUD (stored locally per agent)
// ---------------------------------------------------------------------------
app.get('/api/agents/:id/configs', requireAuth, (req, res) => {
  const agents = readAgents();
  const agent = agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const dir = agentConfigDir(req.params.id);
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.conf') || f.endsWith('.nginx'));
  const configs = files.map(f => {
    const stat = fs.statSync(path.join(dir, f));
    return { name: f, size: stat.size, modified: stat.mtime.toISOString() };
  });
  res.json(configs);
});

app.get('/api/agents/:id/configs/:filename', requireAuth, (req, res) => {
  const dir = agentConfigDir(req.params.id);
  const filePath = path.join(dir, path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  res.json({ name: req.params.filename, content: fs.readFileSync(filePath, 'utf8') });
});

app.put('/api/agents/:id/configs/:filename', requireAuth, (req, res) => {
  const { content } = req.body;
  if (content === undefined) return res.status(400).json({ error: 'content required' });
  const dir = agentConfigDir(req.params.id);
  const filePath = path.join(dir, path.basename(req.params.filename));
  fs.writeFileSync(filePath, content, 'utf8');
  res.json({ ok: true, name: req.params.filename });
});

app.delete('/api/agents/:id/configs/:filename', requireAuth, (req, res) => {
  const dir = agentConfigDir(req.params.id);
  const filePath = path.join(dir, path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  fs.unlinkSync(filePath);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// SSH operations — use Socket.IO for live output
// ---------------------------------------------------------------------------
io.on('connection', (socket) => {
  socket.on('push', async ({ agentId, filename, token }) => {
    // Basic auth via session token passed from client
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    
    const agents = readAgents();
    const agent = agents.find(a => a.id === agentId);
    if (!agent) { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    const dir = agentConfigDir(agentId);
    const localPath = path.join(dir, path.basename(filename));
    if (!fs.existsSync(localPath)) { socket.emit('done', { success: false, output: 'Local config not found' }); return; }

    const content = fs.readFileSync(localPath, 'utf8');
    const remotePath = `${agent.nginxConfigPath}/conf.d/${filename}`;
    
    socket.emit('log', `📤 Pushing ${filename} → ${agent.host}:${remotePath}\n`);

    const ssh = new NodeSSH();
    const connOpts = {
      host: agent.host,
      port: agent.sshPort || 22,
      username: agent.sshUser,
    };
    if (agent.sshKeyPath && fs.existsSync(agent.sshKeyPath)) {
      connOpts.privateKeyPath = agent.sshKeyPath;
    } else {
      connOpts.password = agent.sshPass;
    }

    try {
      await ssh.connect(connOpts);
      socket.emit('log', `✅ SSH connected to ${agent.host}\n`);
      
      // Write file via tee (avoids permission issues)
      const escaped = content.replace(/'/g, "'\\''");
      const writeCmd = `echo '${escaped}' | sudo tee ${remotePath} > /dev/null && echo "Written OK"`;
      const writeResult = await ssh.execCommand(writeCmd);
      
      if (writeResult.code !== 0) {
        socket.emit('log', `❌ Write failed: ${writeResult.stderr}\n`);
        ssh.dispose();
        socket.emit('done', { success: false, output: writeResult.stderr });
        return;
      }
      socket.emit('log', `✅ File written to ${remotePath}\n`);
      
      // Test config
      socket.emit('log', `🔍 Running nginx -t...\n`);
      const testResult = await ssh.execCommand('sudo nginx -t 2>&1');
      const testOutput = testResult.stdout + testResult.stderr;
      socket.emit('log', testOutput + '\n');
      
      if (testResult.code !== 0) {
        socket.emit('log', `❌ nginx config test failed — NOT reloading\n`);
        ssh.dispose();
        socket.emit('done', { success: false, output: testOutput });
        return;
      }
      
      // Reload nginx
      socket.emit('log', `🔄 Reloading nginx...\n`);
      const reloadResult = await ssh.execCommand('sudo nginx -s reload 2>&1');
      const reloadOutput = reloadResult.stdout + reloadResult.stderr;
      socket.emit('log', reloadOutput + '\n');
      
      if (reloadResult.code === 0) {
        socket.emit('log', `✅ nginx reloaded successfully!\n`);
        socket.emit('done', { success: true, output: testOutput });
      } else {
        socket.emit('log', `❌ Reload failed\n`);
        socket.emit('done', { success: false, output: reloadOutput });
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
    const agents = readAgents();
    const agent = agents.find(a => a.id === agentId);
    if (!agent) { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    socket.emit('log', `🔍 Validating nginx config on ${agent.host}...\n`);
    const result = await sshExec(agent, 'sudo nginx -t 2>&1', l => socket.emit('log', l));
    socket.emit('done', result);
  });

  socket.on('reload', async ({ agentId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agents = readAgents();
    const agent = agents.find(a => a.id === agentId);
    if (!agent) { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    socket.emit('log', `🔄 Reloading nginx on ${agent.host}...\n`);
    const result = await sshExec(agent, 'sudo nginx -s reload 2>&1', l => socket.emit('log', l));
    socket.emit('done', result);
  });

  socket.on('sync', async ({ agentId, token }) => {
    if (!token) { socket.emit('done', { success: false, output: 'Not authenticated' }); return; }
    const agents = readAgents();
    const agent = agents.find(a => a.id === agentId);
    if (!agent) { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    socket.emit('log', `🔄 Syncing configs from ${agent.host}...\n`);
    
    const ssh = new NodeSSH();
    const connOpts = {
      host: agent.host,
      port: agent.sshPort || 22,
      username: agent.sshUser,
    };
    if (agent.sshKeyPath && fs.existsSync(agent.sshKeyPath)) {
      connOpts.privateKeyPath = agent.sshKeyPath;
    } else {
      connOpts.password = agent.sshPass;
    }

    try {
      await ssh.connect(connOpts);
      socket.emit('log', `✅ SSH connected\n`);
      
      // List conf.d files
      const listResult = await ssh.execCommand(`ls ${agent.nginxConfigPath}/conf.d/*.conf 2>/dev/null`);
      const files = listResult.stdout.trim().split('\n').filter(f => f.trim());
      
      if (!files.length) {
        socket.emit('log', `ℹ️  No .conf files found in ${agent.nginxConfigPath}/conf.d/\n`);
        
        // Fallback: try nginx.conf itself
        const mainResult = await ssh.execCommand(`cat ${agent.nginxConfigPath}/nginx.conf 2>/dev/null`);
        if (mainResult.code === 0) {
          const dir = agentConfigDir(agentId);
          fs.writeFileSync(path.join(dir, 'nginx.conf'), mainResult.stdout, 'utf8');
          socket.emit('log', `✅ Synced nginx.conf\n`);
        }
      } else {
        const dir = agentConfigDir(agentId);
        for (const filePath of files) {
          const fname = path.basename(filePath);
          const catResult = await ssh.execCommand(`sudo cat ${filePath}`);
          if (catResult.code === 0) {
            fs.writeFileSync(path.join(dir, fname), catResult.stdout, 'utf8');
            socket.emit('log', `✅ Synced ${fname}\n`);
          } else {
            socket.emit('log', `⚠️  Could not read ${fname}: ${catResult.stderr}\n`);
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
    const agents = readAgents();
    const agent = agents.find(a => a.id === agentId);
    if (!agent) { socket.emit('done', { success: false, output: 'Agent not found' }); return; }

    const result = await sshExec(
      agent,
      'sudo systemctl is-active nginx && sudo nginx -v 2>&1 && sudo systemctl status nginx --no-pager -l 2>&1 | head -20',
      l => socket.emit('log', l)
    );
    socket.emit('done', result);
  });
});

// ---------------------------------------------------------------------------
// REST fallback endpoints for non-streaming operations
// ---------------------------------------------------------------------------
app.post('/api/agents/:id/validate', requireAuth, async (req, res) => {
  const agents = readAgents();
  const agent = agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const result = await sshExec(agent, 'sudo nginx -t 2>&1');
  res.json(result);
});

app.post('/api/agents/:id/reload', requireAuth, async (req, res) => {
  const agents = readAgents();
  const agent = agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const result = await sshExec(agent, 'sudo nginx -s reload 2>&1');
  res.json(result);
});

app.get('/api/agents/:id/status', requireAuth, async (req, res) => {
  const agents = readAgents();
  const agent = agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const result = await sshExec(agent, 'sudo systemctl is-active nginx 2>&1 && sudo nginx -v 2>&1');
  res.json(result);
});

// ---------------------------------------------------------------------------
// Catch-all SPA
// ---------------------------------------------------------------------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`nginx-manager listening on http://0.0.0.0:${PORT}`);
});
