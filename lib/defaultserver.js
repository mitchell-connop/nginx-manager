/**
 * nginx-manager — lib/defaultserver.js
 *
 * Catch-all for requests whose Host matches no site. Without one, nginx hands them to the
 * first server block on that address:port — so scanners hitting the IP, or any stray
 * hostname, land on a real site. conf.d/00-nginx-manager-default.conf holds one
 * `default_server` block per address:port that name-based sites listen on:
 *
 *   drop      HTTP: return 444 (close without a response); HTTPS: ssl_reject_handshake
 *             (refused during TLS — no certificate needed and none is revealed)
 *   status    return a fixed status code (e.g. 404)
 *   redirect  301/302 to a URL (e.g. the main site)
 *
 * For status/redirect on HTTPS a certificate is needed to answer at all; without one the
 * HTTPS listeners fall back to rejecting the handshake.
 *
 * Only listeners shared by name-based servers are covered: a port served by a single block
 * without server_name (forward proxy, loopback status page) already has no ambiguity, and a
 * port that already has a default_server elsewhere is reported as a conflict and skipped.
 */

'use strict';

const pf = require('./proxyfile');

const FILE = '00-nginx-manager-default.conf';
const ACTIONS = ['drop', 'status', 'redirect'];

const directives = (block, name) => (block.children || []).filter(c => c.type === 'directive' && c.name === name);

function parseListen(args) {
  const words = args.map(a => a.text);
  const addr = words[0] || '';
  let host = '', port;
  let m = addr.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (m) { host = `[${m[1]}]`; port = +(m[2] || 80); }
  else if (/^\d+$/.test(addr)) port = +addr;
  else if ((m = addr.match(/^([^:]+):(\d+)$/))) { host = m[1] === '*' ? '' : m[1]; port = +m[2]; }
  else if (addr.startsWith('unix:')) return null;
  else { host = addr; port = 80; }
  return {
    host, port,
    ssl: words.includes('ssl'),
    quic: words.includes('quic'),
    isDefault: words.includes('default_server') || words.includes('default'),
    key: `${host || '*'}:${port}`,
  };
}

// files: { name: text } — every http config file (not stream.d). Returns the listeners to cover.
function scan(files, ownPath) {
  const byKey = new Map();
  for (const [name, text] of Object.entries(files)) {
    if (name === ownPath || /\/stream\.d\//.test(name)) continue;
    let root;
    try { root = pf.parse(text); } catch { continue; }
    const servers = [];
    const walk = (n, ctx) => {
      for (const c of n.children || []) {
        if (c.type !== 'block') continue;
        if (c.name === 'stream' || c.name === 'mail') continue;
        if (c.name === 'server' && !ctx.includes('upstream')) servers.push(c);
        else walk(c, [...ctx, c.name]);
      }
    };
    walk(root, []);
    for (const srv of servers) {
      const names = directives(srv, 'server_name').flatMap(d => d.args.map(a => a.text)).filter(n => n && n !== '_' && n !== '""');
      const listens = directives(srv, 'listen').map(d => parseListen(d.args)).filter(Boolean);
      if (!listens.length) listens.push({ host: '', port: 80, ssl: false, quic: false, isDefault: false, key: '*:80' });
      for (const l of listens) {
        if (l.quic) continue;
        const e = byKey.get(l.key) || { host: l.host, port: l.port, ssl: false, named: 0, unnamed: 0, defaultIn: null };
        e.ssl = e.ssl || l.ssl;
        if (names.length) e.named++; else e.unnamed++;
        if (l.isDefault) e.defaultIn = name;
        byKey.set(l.key, e);
      }
    }
  }
  const listeners = [], conflicts = [], skipped = [];
  for (const [key, e] of [...byKey].sort()) {
    if (!e.named) { skipped.push({ key, reason: 'no name-based sites' }); continue; }
    if (e.defaultIn) { conflicts.push({ key, file: e.defaultIn }); continue; }
    if (/^127\.|^\[::1\]$/.test(e.host)) { skipped.push({ key, reason: 'loopback' }); continue; }
    listeners.push({ key, host: e.host, port: e.port, ssl: e.ssl });
  }
  return { listeners, conflicts, skipped };
}

// current settings, read back from our own file
function parseOwn(text) {
  if (!text) return null;
  const m = text.match(/^# nginx-manager default-server: (\{.*\})$/m);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

function normalize(s) {
  const out = {
    action: ACTIONS.includes(s.action) ? s.action : 'drop',
    status: parseInt(s.status, 10) || 404,
    redirectUrl: String(s.redirectUrl || '').trim(),
    redirectCode: [301, 302, 307, 308].includes(+s.redirectCode) ? +s.redirectCode : 302,
    keepPath: !!s.keepPath,
    certFile: String(s.certFile || '').trim(),
    keyFile: String(s.keyFile || '').trim(),
  };
  const errors = [];
  if (out.action === 'status' && !(out.status >= 200 && out.status <= 599)) errors.push('Status must be 200-599');
  if (out.action === 'redirect' && !/^https?:\/\/[A-Za-z0-9.\-[\]:]+(\/[A-Za-z0-9._~%!$&'()*+,=:@/-]*)?$/.test(out.redirectUrl)) errors.push('Redirect URL like https://www.example.com/');
  if ((out.certFile || out.keyFile) && !(/^\/[A-Za-z0-9._@/-]+$/.test(out.certFile) && /^\/[A-Za-z0-9._@/-]+$/.test(out.keyFile))) errors.push('Certificate and key must both be absolute paths');
  if (errors.length) throw Object.assign(new Error(errors.join('; ')), { status: 400 });
  return out;
}

function generate(settings, listeners) {
  const s = normalize(settings);
  const plainAction = s.action === 'drop' ? 'return 444;'
    : s.action === 'status' ? `return ${s.status};`
    : `return ${s.redirectCode} ${s.redirectUrl.replace(/\/$/, '')}${s.keepPath ? '$request_uri' : '/'};`;
  const tlsServe = s.action !== 'drop' && s.certFile && s.keyFile;
  const http = listeners.filter(l => !l.ssl), https = listeners.filter(l => l.ssl);
  const lines = [
    '# Managed by nginx-manager (Visual Builder → Unknown hosts) — do not edit by hand.',
    `# nginx-manager default-server: ${JSON.stringify(s)}`,
    '# Catches requests whose Host matches no site, so they never land on the first site by accident.',
    '',
  ];
  if (http.length) {
    lines.push('server {',
      ...http.map(l => `    listen ${l.host ? `${l.host}:` : ''}${l.port} default_server;`),
      '    server_name _;',
      `    ${plainAction}`,
      '}', '');
  }
  if (https.length) {
    lines.push('server {',
      ...https.map(l => `    listen ${l.host ? `${l.host}:` : ''}${l.port} ssl default_server;`),
      '    server_name _;');
    if (tlsServe) lines.push(`    ssl_certificate ${s.certFile};`, `    ssl_certificate_key ${s.keyFile};`, `    ${plainAction}`);
    else lines.push('    ssl_reject_handshake on;      # refuse unknown names during TLS — no certificate needed or revealed');
    lines.push('}', '');
  }
  return lines.join('\n');
}

module.exports = { FILE, ACTIONS, scan, generate, parseOwn, normalize, parseListen };
