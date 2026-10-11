/**
 * nginx-manager — lib/streams.js
 *
 * RTSP streams: TCP proxies in nginx's stream module (ngx_stream_proxy_module).
 *
 * The stream context is separate from http, so these can't live in conf.d (included
 * inside http {}). Layout:
 *
 *   nginx.conf            stream { ... include /etc/nginx/stream.d/*.conf; }   (added once if missing)
 *   stream.d/rtsp-streams.conf, one group per stream:
 *
 *   # ==========================================
 *   # FRONT DOOR CAMERA
 *   # ==========================================
 *   upstream rtsp_front_door {
 *       server 192.0.2.20:554 max_fails=2 fail_timeout=30s;
 *       server 192.0.2.21:554 backup;                  # optional fallback (e.g. the NVR)
 *   }
 *   server {
 *       listen 8554;
 *       allow 10.1.1.0/24;                             # who may connect
 *       deny all;
 *       proxy_pass rtsp_front_door;
 *       proxy_connect_timeout 5s;
 *       proxy_timeout 300s;                            # idle timeout between reads/writes
 *       proxy_socket_keepalive on;
 *   }
 *
 * RTSP over a TCP proxy carries the RTP media interleaved on the same connection, so
 * clients must use TCP transport (e.g. ffmpeg -rtsp_transport tcp; VLC "RTP over RTSP (TCP)").
 * UDP RTP negotiates extra ports in SETUP that a proxy can't follow.
 *
 * Editing regenerates the group but keeps any directives in the server block this module
 * doesn't manage, verbatim.
 */

'use strict';

const pf = require('./proxyfile');

const DEFAULT_RTSP_PORT = 554;
const STREAM_LOG_FORMAT = "log_format stream_basic '$remote_addr [$time_local] $protocol $server_port $status " +
  "$bytes_sent $bytes_received $session_time \"$upstream_addr\"';";

const MANAGED = new Set([
  'listen', 'allow', 'deny', 'proxy_pass', 'proxy_connect_timeout', 'proxy_timeout', 'proxy_socket_keepalive',
]);

const directives = (block, name) => block.children.filter(c => c.type === 'directive' && c.name === name);
const argsText = d => d.args.map(a => a.text).join(' ');

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

function parseDuration(v) {
  const m = String(v || '').match(/^(\d+)(ms|s|m|h)?$/);
  if (!m) return null;
  return { ms: Math.round(m[1] / 1000), s: +m[1], m: m[1] * 60, h: m[1] * 3600 }[m[2] || 's'];
}

// ---------------------------------------------------------------------------
// nginx.conf: the stream {} block
// ---------------------------------------------------------------------------
function streamDir(nginxDir) { return `${nginxDir}/stream.d`; }
function streamsFile(nginxDir) { return `${streamDir(nginxDir)}/rtsp-streams.conf`; }
function streamLogInclude(nginxDir) { return `${nginxDir}/nginx-manager/remote-stream-log[.]inc`; }

// Does nginx.conf have a stream {} block that includes stream.d?
function streamBlockState(mainConf, nginxDir) {
  let root;
  try { root = pf.parse(mainConf || ''); } catch { return { block: null, includes: false }; }
  const block = root.children.find(c => c.type === 'block' && c.name === 'stream') || null;
  const want = `${streamDir(nginxDir)}/*.conf`;
  const includes = !!block && directives(block, 'include').some(d => argsText(d) === want);
  return { block, includes };
}

// Returns nginx.conf with a stream {} block including stream.d (unchanged if already there).
function ensureStreamBlock(mainConf, nginxDir) {
  const text = String(mainConf || '');
  const { block, includes } = streamBlockState(text, nginxDir);
  if (includes) return text;
  const inc = `include ${streamDir(nginxDir)}/*.conf;`;
  if (block) {
    // add the include just before the closing brace of the existing block
    const close = block.end - 1;
    const ls = lineStart(text, close);
    const before = /^\s*$/.test(text.slice(ls, close)) ? ls : close;
    return text.slice(0, before) + `    ${inc}\n` + (before === ls ? '' : '\n') + text.slice(before);
  }
  const out = text.length && !text.endsWith('\n') ? text + '\n' : text;
  return out + [
    '',
    '# Managed by nginx-manager: TCP stream proxies (RTSP cameras etc.).',
    '# The stream context is separate from http — one file per purpose in stream.d/.',
    'stream {',
    `    ${STREAM_LOG_FORMAT}`,
    `    access_log /var/log/nginx/stream-access.log stream_basic;`,
    `    include ${streamLogInclude(nginxDir)};`,
    `    ${inc}`,
    '}',
    '',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------
function findStreams(text) {
  const root = pf.parse(text || '');
  const upstreams = new Map(root.children.filter(c => c.type === 'block' && c.name === 'upstream' && c.args.length === 1)
    .map(u => [u.args[0].text, u]));
  const out = [];
  for (const srv of root.children.filter(c => c.type === 'block' && c.name === 'server')) {
    const pass = directives(srv, 'proxy_pass')[0];
    if (!pass) continue;
    const target = argsText(pass);
    const up = upstreams.get(target) || null;
    const servers = up
      ? directives(up, 'server').map(d => ({ address: d.args[0] ? d.args[0].text : '', backup: d.args.some(a => a.text === 'backup') }))
      : [{ address: target, backup: false }];
    const allow = directives(srv, 'allow').map(argsText);
    const denyAll = directives(srv, 'deny').some(d => argsText(d) === 'all');
    const nodes = [up, srv].filter(Boolean).sort((a, b) => a.start - b.start);
    const header = headerAbove(text, nodes[0].start);
    const listen = directives(srv, 'listen').map(argsText)[0] || '';
    const keyMatch = up && target.match(/^rtsp_([a-z0-9_]+)$/);
    const extras = srv.children.filter(c => !(c.type === 'directive' && MANAGED.has(c.name)));
    out.push({
      key: keyMatch ? keyMatch[1] : `listen-${listen.replace(/[^A-Za-z0-9]+/g, '-')}`,
      label: (header && header.label) || `Stream ${listen}`,
      listen,
      upstreams: servers.filter(s => !s.backup).map(s => s.address),
      backups: servers.filter(s => s.backup).map(s => s.address),
      allowNetworks: allow,
      denyAll,
      openToAll: !denyAll || allow.some(a => a === 'all' || a === '0.0.0.0/0' || a === '::/0'),
      connectTimeout: parseDuration(argsText(directives(srv, 'proxy_connect_timeout')[0] || { args: [] })),
      idleTimeout: parseDuration(argsText(directives(srv, 'proxy_timeout')[0] || { args: [] })),
      managed: !!keyMatch,
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
  upstream: /^(([A-Za-z0-9-]+\.)*[A-Za-z0-9-]+|\[[0-9a-fA-F:]+\])(:\d{1,5})?$/,
};

function slug(s) { return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40) || 'stream'; }

function withPort(a) {
  const s = String(a).trim();
  if (/^\[[^\]]+\]:\d+$/.test(s) || /^[^:\[\]]+:\d+$/.test(s)) return s;
  return `${s}:${DEFAULT_RTSP_PORT}`;
}

function normalize(f) {
  const list = v => (Array.isArray(v) ? v : String(v || '').split(/[\s,]+/)).map(x => String(x).trim()).filter(Boolean);
  const int = (v, d) => (v === '' || v == null ? d : parseInt(v, 10));
  return {
    name: String(f.name || f.label || '').trim(),
    listen: String(f.listen || '').trim(),
    upstreams: list(f.upstreams).map(withPort),
    backups: list(f.backups).map(withPort),
    allowNetworks: list(f.allowNetworks),
    connectTimeout: int(f.connectTimeout, 5),
    idleTimeout: int(f.idleTimeout, 300),
  };
}

function portOf(listen) { return parseInt(String(listen).split(':').pop(), 10); }

function validate(f) {
  const e = [];
  if (!RE.label.test(f.name)) e.push('Name: 1-80 characters, no #');
  const port = portOf(f.listen);
  if (!RE.listen.test(f.listen) || !(port >= 1 && port <= 65535)) e.push('Listen: a port (8554) or address:port (192.0.2.10:8554)');
  if (!f.upstreams.length) e.push('Camera / RTSP server address is required (host or host:port, default port 554)');
  for (const u of [...f.upstreams, ...f.backups]) {
    const p = portOf(u);
    if (!RE.upstream.test(u) || !(p >= 1 && p <= 65535)) e.push(`Server "${u}" — use 192.0.2.20 or camera.lan:554`);
  }
  if (!f.allowNetworks.length) e.push('Client networks are required — cameras should not be reachable by everyone (use 0.0.0.0/0 to allow all deliberately)');
  for (const n of f.allowNetworks) if (!RE.cidr.test(n)) e.push(`Client network "${n}" — use an IP or CIDR like 10.1.1.0/24`);
  if (!(f.connectTimeout >= 1 && f.connectTimeout <= 75)) e.push('Connect timeout must be 1-75 seconds');
  if (!(f.idleTimeout >= 10 && f.idleTimeout <= 86400)) e.push('Idle timeout must be 10-86400 seconds');
  return e;
}

function generate(f, key, { extraDirectives = [] } = {}) {
  const up = `rtsp_${key}`;
  const out = [
    '# ==========================================',
    `# ${f.name}`,
    '# ==========================================',
    `upstream ${up} {`,
    ...f.upstreams.map(u => `    server ${u} max_fails=2 fail_timeout=30s;`),
    ...f.backups.map(u => `    server ${u} backup;`),
    '}',
    'server {',
    `    listen ${f.listen};`,
    '',
    '    # who may connect',
    ...f.allowNetworks.map(n => `    allow ${n};`),
    '    deny all;',
    '',
    `    proxy_pass ${up};`,
    `    proxy_connect_timeout ${f.connectTimeout}s;`,
    `    proxy_timeout ${f.idleTimeout}s;`,
    '    proxy_socket_keepalive on;',
  ];
  if (extraDirectives.length) out.push('', '    # additional directives (kept from the previous version)', ...extraDirectives.map(d => `    ${d}`));
  out.push('}');
  return out.join('\n') + '\n';
}

// Returns { conf, key }. usedPorts: listen ports taken elsewhere on this server (http, other files).
function plan(text, { key: editKey, fields, usedPorts = [] }) {
  const f = normalize(fields);
  const errors = validate(f);
  const all = findStreams(text || '');
  const existing = editKey ? all.find(p => p.key === editKey) : null;
  if (editKey && !existing) errors.push(`stream ${editKey} not found`);
  if (errors.length) throw Object.assign(new Error(errors.join('; ')), { status: 400 });

  let key = editKey;
  if (!key) {
    const taken = new Set(all.map(p => p.key));
    key = slug(f.name);
    for (let i = 2; taken.has(key); i++) key = `${slug(f.name)}_${i}`;
  }
  const port = portOf(f.listen);
  const clash = all.find(p => p.key !== key && portOf(p.listen) === port);
  if (clash) throw Object.assign(new Error(`${clash.label} already listens on port ${port}`), { status: 409 });
  if (usedPorts.includes(port) && !(existing && portOf(existing.listen) === port)) {
    throw Object.assign(new Error(`Port ${port} is already used by another server block on this host`), { status: 409 });
  }

  const block = generate(f, key, { extraDirectives: existing ? existing.extraDirectives : [] });
  let conf;
  if (existing) {
    const start = existing._header ? existing._header.start : lineStart(text, existing._nodes[0].start);
    const last = existing._nodes[existing._nodes.length - 1];
    const end = Math.min(lineEnd(text, last.end) + 1, text.length);
    conf = text.slice(0, start) + block + text.slice(end);
  } else {
    let base = text || '';
    if (base.length && !base.endsWith('\n')) base += '\n';
    conf = base.trim().length ? `${base}\n${block}` : '# RTSP streams — managed by nginx-manager (Visual Builder → RTSP streams)\n\n' + block;
  }
  return { conf, key };
}

function remove(text, key) {
  const p = findStreams(text).find(x => x.key === key);
  if (!p) throw Object.assign(new Error(`stream ${key} not found`), { status: 404 });
  const start = p._header ? p._header.start : lineStart(text, p._nodes[0].start);
  const last = p._nodes[p._nodes.length - 1];
  let end = Math.min(lineEnd(text, last.end) + 1, text.length);
  const blank = text.slice(end).match(/^[ \t]*\n/);
  if (blank) end += blank[0].length;
  const out = text.slice(0, start) + text.slice(end);
  const conf = end >= text.length ? out.replace(/\n\s*$/, '\n') : out;
  // nothing left but comments → caller deletes the file
  const empty = !conf.split('\n').some(l => l.trim() && !l.trim().startsWith('#'));
  return { conf, empty };
}

function publicStream(p) {
  const out = {};
  for (const [k, v] of Object.entries(p)) if (!k.startsWith('_')) out[k] = v;
  return out;
}

// Listen ports used by every server block in the given config texts (http and stream).
function listenPorts(texts) {
  const ports = new Set();
  for (const t of texts) {
    for (const m of String(t || '').matchAll(/^[ \t]*listen[ \t]+([^;\s]+)[^;]*;/gm)) {
      const v = m[1];
      if (v.startsWith('unix:')) continue;
      const port = /^\d+$/.test(v) ? +v : (v.match(/:(\d+)$/) || [])[1];
      ports.add(port ? +port : 80);   // address without a port listens on 80
    }
  }
  return [...ports];
}

module.exports = {
  DEFAULT_RTSP_PORT, streamDir, streamsFile, streamLogInclude, streamBlockState, ensureStreamBlock,
  findStreams, publicStream, plan, remove, normalize, validate, listenPorts, portOf,
};
