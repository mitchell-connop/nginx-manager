/**
 * nginx-manager — lib/fwdproxy.js
 *
 * Forward (CONNECT) proxies using ngx_http_tunnel_module — nginx 1.31.0+, built by
 * default (absent only with --without-http_tunnel_module). Clients tunnel HTTPS through
 * nginx; plain-HTTP requests to a tunnel server get 405.
 *
 * Layout (conf.d/forward-proxies.conf), one group per proxy:
 *
 *   # ==========================================
 *   # OFFICE PROXY
 *   # ==========================================
 *   map $request_port $fwdproxy_office_port { default 0; 443 1; }
 *   map $host $fwdproxy_office_host { hostnames; default 1; ~^[0-9.]+$ 0; }
 *   server {
 *       listen 3128;
 *       allow 10.1.1.0/24; deny all;                       # who may use the proxy
 *       auth_basic "Office proxy";                          # 407 + Proxy-Authenticate for CONNECT
 *       auth_basic_user_file /etc/nginx/forward-proxy/office.htpasswd;
 *       if ($fwdproxy_office_port != 1) { return 403; }    # where they may go
 *       if ($fwdproxy_office_host != 1) { return 403; }
 *       tunnel_pass;
 *   }
 *
 * Editing regenerates the group but keeps any directives in the server block this
 * module doesn't manage, verbatim.
 */

'use strict';

const bcrypt = require('bcryptjs');
const pf = require('./proxyfile');

const MIN_VERSION = '1.31.0';

const MANAGED = new Set([
  'listen', 'server_name', 'resolver', 'resolver_timeout', 'access_log', 'allow', 'deny',
  'auth_basic', 'auth_basic_user_file', 'tunnel_pass', 'tunnel_connect_timeout',
  'tunnel_read_timeout', 'tunnel_send_timeout',
]);

function versionAtLeast(v, min = MIN_VERSION) {
  const a = String(v || '').match(/(\d+)\.(\d+)\.(\d+)/);
  if (!a) return false;
  const b = min.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const x = Number(a[i + 1]);
    if (x !== b[i]) return x > b[i];
  }
  return true;
}

// ---------------------------------------------------------------------------
// htpasswd (bcrypt — nginx uses crypt(3); Debian/Ubuntu libxcrypt supports $2b$)
// ---------------------------------------------------------------------------
function parseHtpasswd(text) {
  return String(text || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    .map(l => { const i = l.indexOf(':'); return { username: l.slice(0, i), hash: l.slice(i + 1).split(':')[0] }; })
    .filter(u => u.username && u.hash);
}

function buildHtpasswd(entries) {
  return '# managed by nginx-manager — bcrypt hashes only\n' + entries.map(u => `${u.username}:${u.hash}`).join('\n') + '\n';
}

function hashPassword(pw) { return bcrypt.hashSync(pw, 11).replace(/^\$2a\$/, '$2b$'); }

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------
const directives = (block, name) => block.children.filter(c => c.type === 'directive' && c.name === name);
const argsText = d => d.args.map(a => a.text).join(' ');
const unquote = s => s.replace(/^(["'])(.*)\1$/, '$2');

function hasTunnelPass(node) {
  return node.children.some(c => (c.type === 'directive' && c.name === 'tunnel_pass') ||
    (c.type === 'block' && c.name !== 'map' && hasTunnelPass(c)));
}

function parseDuration(v) {
  const m = String(v || '').match(/^(\d+)(ms|s|m|h)?$/);
  if (!m) return null;
  return { ms: Math.round(m[1] / 1000), s: +m[1], m: m[1] * 60, h: m[1] * 3600 }[m[2] || 's'];
}

function lineStart(text, i) { return text.lastIndexOf('\n', i - 1) + 1; }
function lineEnd(text, i) { const e = text.indexOf('\n', i); return e === -1 ? text.length : e; }

function headerAbove(text, idx) {
  const start = lineStart(text, idx);
  let h = start;
  while (h > 0) {
    const ps = lineStart(text, h - 1);
    if (!/^\s*#/.test(text.slice(ps, h - 1))) break;
    h = ps;
  }
  if (h === start) return null;
  const label = text.slice(h, start).split('\n').map(l => l.replace(/^\s*#+\s?/, '').trim()).find(l => /[A-Za-z0-9]/.test(l)) || null;
  return { start: h, end: start, label };
}

function findForwardProxies(text) {
  const root = pf.parse(text);
  const maps = root.children.filter(c => c.type === 'block' && c.name === 'map' && c.args.length === 2);
  const mapByVar = new Map(maps.map(m => [m.args[1].text, m]));
  const out = [];

  for (const srv of root.children.filter(c => c.type === 'block' && c.name === 'server' && hasTunnelPass(c))) {
    const ifs = srv.children.filter(c => c.type === 'block' && c.name === 'if');
    const condVar = re => {
      for (const b of ifs) {
        const m = argsText(b).match(/^\(\s*(\$[A-Za-z0-9_]+)\s*!=\s*1\s*\)$/);
        if (m && re.test(m[1]) && mapByVar.has(m[1])) return m[1];
      }
      return null;
    };
    const portVar = condVar(/_port$/);
    const hostVar = condVar(/_host$/);
    const portMap = portVar && mapByVar.get(portVar);
    const hostMap = hostVar && mapByVar.get(hostVar);
    const mapEntries = m => m ? m.children.filter(c => c.type === 'directive') : [];

    const ports = mapEntries(portMap).filter(d => d.name !== 'default' && argsText(d) === '1').map(d => parseInt(d.name, 10)).filter(Boolean);
    const hostEntries = mapEntries(hostMap).filter(d => !['hostnames', 'default', 'volatile'].includes(d.name));
    const hostDefault = (mapEntries(hostMap).find(d => d.name === 'default') || { args: [{ text: '1' }] }).args[0].text;
    const allowedHosts = hostEntries.filter(d => !d.name.startsWith('~') && argsText(d) === '1').map(d => d.name);
    const blockIpLiterals = hostEntries.some(d => d.name.startsWith('~') && argsText(d) === '0');

    const allow = directives(srv, 'allow').map(argsText);
    const denyAll = directives(srv, 'deny').some(d => argsText(d) === 'all');
    const authFile = directives(srv, 'auth_basic_user_file')[0];
    const realm = directives(srv, 'auth_basic')[0];
    const resolver = directives(srv, 'resolver')[0];
    const accessLog = directives(srv, 'access_log')[0];
    const slugMatch = (portVar || hostVar || '').match(/^\$fwdproxy_(.+)_(port|host)$/);

    const nodes = [portMap, hostMap, srv].filter(Boolean).sort((a, b) => a.start - b.start);
    const header = headerAbove(text, nodes[0].start);
    const listen = directives(srv, 'listen').map(argsText)[0] || '';
    const extras = srv.children.filter(c => !(c.type === 'directive' && MANAGED.has(c.name)) &&
      !(c.type === 'block' && c.name === 'if' && ifs.includes(c) && /\$fwdproxy_/.test(argsText(c))));

    out.push({
      key: slugMatch ? slugMatch[1] : `listen-${listen.replace(/[^A-Za-z0-9]+/g, '-')}`,
      label: (header && header.label) || `Forward proxy ${listen}`,
      listen,
      allowNetworks: denyAll ? allow : [],
      openToAll: !denyAll && !allow.length,
      authRealm: realm && argsText(realm) !== 'off' ? unquote(argsText(realm)) : '',
      authFile: authFile ? unquote(argsText(authFile)) : '',
      allowedPorts: portMap ? ports : [],
      allowedHosts: hostMap && hostDefault === '0' ? allowedHosts : [],
      anyHost: !hostMap || hostDefault !== '0',
      blockIpLiterals,
      resolver: resolver ? resolver.args.filter(a => !/=/.test(a.text)).map(a => a.text).join(' ') : '',
      connectTimeout: parseDuration(argsText(directives(srv, 'tunnel_connect_timeout')[0] || { args: [] })),
      idleTimeout: parseDuration(argsText(directives(srv, 'tunnel_read_timeout')[0] || { args: [] })),
      accessLog: accessLog ? argsText(accessLog) !== 'off' : true,
      accessLogPath: accessLog && argsText(accessLog) !== 'off' ? argsText(accessLog) : '',
      managed: !!slugMatch,
      extraDirectives: extras.map(c => text.slice(c.start, c.end)),
      _nodes: nodes, _header: header,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Validation & generation
// ---------------------------------------------------------------------------
const RE = {
  label: /^[^\n\r#]{1,80}$/,
  listen: /^((\d{1,3}\.){3}\d{1,3}:|\[[0-9a-fA-F:]+\]:)?\d{1,5}$/,
  cidr: /^((\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?|[0-9a-fA-F:]+(\/\d{1,3})?)$/,
  host: /^(\*\.|\.)?([A-Za-z0-9-]+\.)*[A-Za-z0-9-]+$/,
  ip: /^((\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]+\]?)$/,
  realm: /^[^"\\\n\r]{1,80}$/,
  username: /^[A-Za-z0-9._@-]{1,64}$/,
};

function slug(s) { return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40) || 'proxy'; }

function normalize(f) {
  const list = v => (Array.isArray(v) ? v : String(v || '').split(/[\s,]+/)).map(x => String(x).trim()).filter(Boolean);
  return {
    name: String(f.name || f.label || '').trim(),
    listen: String(f.listen || '').trim(),
    allowNetworks: list(f.allowNetworks),
    allowedPorts: list(f.allowedPorts).map(Number),
    allowedHosts: list(f.allowedHosts).map(h => h.toLowerCase()),
    blockIpLiterals: f.blockIpLiterals !== false,
    resolver: list(f.resolver),
    connectTimeout: f.connectTimeout === '' || f.connectTimeout == null ? 10 : parseInt(f.connectTimeout, 10),
    idleTimeout: f.idleTimeout === '' || f.idleTimeout == null ? 300 : parseInt(f.idleTimeout, 10),
    accessLog: f.accessLog !== false,
    authRealm: String(f.authRealm || 'Proxy').trim(),
    users: (Array.isArray(f.users) ? f.users : []).map(u => ({ username: String(u.username || '').trim(), password: u.password ? String(u.password) : '' })),
  };
}

function validate(f) {
  const e = [];
  if (!RE.label.test(f.name)) e.push('Name: 1-80 characters, no #');
  if (!RE.listen.test(f.listen) || +f.listen.split(':').pop() < 1 || +f.listen.split(':').pop() > 65535) e.push('Listen: a port (3128) or address:port (192.0.2.10:3128)');
  for (const n of f.allowNetworks) if (!RE.cidr.test(n)) e.push(`Client network "${n}" — use an IP or CIDR like 10.1.1.0/24`);
  if (!f.allowedPorts.length) e.push('At least one destination port is required (usually 443)');
  for (const p of f.allowedPorts) if (!(Number.isInteger(p) && p > 0 && p < 65536)) e.push(`Destination port "${p}" is invalid`);
  for (const h of f.allowedHosts) if (!RE.host.test(h)) e.push(`Destination "${h}" — use example.com or *.example.com`);
  if (!f.resolver.length) e.push('A DNS resolver is required (nginx resolves CONNECT destinations itself)');
  for (const r of f.resolver) if (!RE.ip.test(r)) e.push(`Resolver "${r}" must be an IP address`);
  if (!(f.connectTimeout >= 1 && f.connectTimeout <= 75)) e.push('Connect timeout must be 1-75 seconds');
  if (!(f.idleTimeout >= 5 && f.idleTimeout <= 86400)) e.push('Idle timeout must be 5-86400 seconds');
  if (!RE.realm.test(f.authRealm)) e.push('Realm: up to 80 characters, no quotes');
  const seen = new Set();
  for (const u of f.users) {
    if (!RE.username.test(u.username)) e.push(`Username "${u.username}" — letters, digits, . _ @ - only`);
    if (seen.has(u.username)) e.push(`Duplicate user ${u.username}`);
    seen.add(u.username);
    if (u.password && (u.password.length < 10 || u.password.length > 256 || /[\r\n]/.test(u.password))) e.push(`Password for ${u.username} must be 10-256 characters`);
  }
  if (!f.allowNetworks.length && !f.users.length) {
    e.push('Refusing to create an open proxy: restrict client networks, require a login, or both');
  }
  return e;
}

function generate(f, key, { authFile, extraDirectives = [], accessLogPath = '' }) {
  const v = `fwdproxy_${key}`;
  const out = [
    '# ==========================================',
    `# ${f.name}`,
    '# ==========================================',
    `map $request_port $${v}_port {`,
    '    default 0;',
    ...f.allowedPorts.map(p => `    ${p} 1;`),
    '}',
    `map $host $${v}_host {`,
    '    hostnames;',
    `    default ${f.allowedHosts.length ? 0 : 1};`,
    ...f.allowedHosts.map(h => `    ${h} 1;`),
    ...(f.blockIpLiterals ? ['    ~^[0-9.]+$ 0;    # IPv4 literal destinations', '    ~^\\[ 0;          # IPv6 literal destinations'] : []),
    '}',
    'server {',
    `    listen ${f.listen};`,
    `    resolver ${f.resolver.join(' ')} valid=300s;`,
    '    resolver_timeout 5s;',
    f.accessLog ? `    access_log ${accessLogPath || `/var/log/nginx/fwdproxy_${key}.access.log`};` : '    access_log off;',
    '',
  ];
  if (f.allowNetworks.length) {
    out.push('    # who may use the proxy', ...f.allowNetworks.map(n => `    allow ${n};`), '    deny all;', '');
  }
  if (f.users.length) {
    out.push('    # proxy login (407 Proxy-Authenticate for CONNECT)', `    auth_basic "${f.authRealm}";`, `    auth_basic_user_file ${authFile};`, '');
  }
  out.push(
    '    # where they may connect to',
    `    if ($${v}_port != 1) { return 403; }`,
    `    if ($${v}_host != 1) { return 403; }`,
    '',
    `    tunnel_connect_timeout ${f.connectTimeout}s;`,
    `    tunnel_read_timeout ${f.idleTimeout}s;`,
    `    tunnel_send_timeout ${f.idleTimeout}s;`,
  );
  if (extraDirectives.length) out.push('', '    # additional directives (kept from the previous version)', ...extraDirectives.map(d => `    ${d}`));
  out.push('', '    tunnel_pass;', '}');
  return out.join('\n') + '\n';
}

function authFilePath(nginxDir, key) { return `${nginxDir}/forward-proxy/${key}.htpasswd`; }

// Returns { conf, htpasswd: string|null, key, authFile }
function plan(text, { key: editKey, fields, nginxDir, existingHtpasswd }) {
  const f = normalize(fields);
  const errors = validate(f);
  const existing = editKey ? findForwardProxies(text).find(p => p.key === editKey) : null;
  if (editKey && !existing) errors.push(`forward proxy ${editKey} not found`);

  // users: keep existing hashes unless a new password was given; new users need one
  const current = new Map(parseHtpasswd(existingHtpasswd).map(u => [u.username, u.hash]));
  const entries = [];
  for (const u of f.users) {
    if (u.password) entries.push({ username: u.username, hash: hashPassword(u.password) });
    else if (current.has(u.username)) entries.push({ username: u.username, hash: current.get(u.username) });
    else errors.push(`Set a password for new user ${u.username}`);
  }
  if (errors.length) throw Object.assign(new Error(errors.join('; ')), { status: 400 });

  let key = editKey;
  if (!key) {
    const taken = new Set(findForwardProxies(text).map(p => p.key));
    key = slug(f.name);
    for (let i = 2; taken.has(key); i++) key = `${slug(f.name)}_${i}`;
  }
  const listenTaken = findForwardProxies(text).some(p => p.key !== key && p.listen === f.listen);
  if (listenTaken) throw Object.assign(new Error(`Another forward proxy already listens on ${f.listen}`), { status: 409 });

  const authFile = (existing && existing.authFile) || authFilePath(nginxDir, key);
  const block = generate(f, key, {
    authFile,
    extraDirectives: existing ? existing.extraDirectives : [],
    accessLogPath: existing ? existing.accessLogPath : '',   // keep a customised log path
  });

  let conf;
  if (existing) {
    const start = existing._header ? existing._header.start : lineStart(text, existing._nodes[0].start);
    const last = existing._nodes[existing._nodes.length - 1];
    const end = Math.min(lineEnd(text, last.end) + 1, text.length);
    conf = text.slice(0, start) + block + text.slice(end);
  } else {
    let base = text;
    if (base.length && !base.endsWith('\n')) base += '\n';
    conf = base.trim().length ? `${base}\n${block}` : block;
  }
  return { conf, key, authFile, htpasswd: entries.length ? buildHtpasswd(entries) : null, users: entries.map(u => u.username) };
}

function remove(text, key) {
  const p = findForwardProxies(text).find(x => x.key === key);
  if (!p) throw Object.assign(new Error(`forward proxy ${key} not found`), { status: 404 });
  const start = p._header ? p._header.start : lineStart(text, p._nodes[0].start);
  const last = p._nodes[p._nodes.length - 1];
  let end = Math.min(lineEnd(text, last.end) + 1, text.length);
  const blank = text.slice(end).match(/^[ \t]*\n/);
  if (blank) end += blank[0].length;
  const out = text.slice(0, start) + text.slice(end);
  return { conf: end >= text.length ? out.replace(/\n\s*$/, '\n') : out, authFile: p.authFile };
}

function publicProxy(p) {
  const out = {};
  for (const [k, v] of Object.entries(p)) if (!k.startsWith('_')) out[k] = v;
  return out;
}

module.exports = {
  MIN_VERSION, versionAtLeast, findForwardProxies, publicProxy, plan, remove,
  parseHtpasswd, buildHtpasswd, hashPassword, normalize, validate,
};
