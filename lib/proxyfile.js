/**
 * nginx-manager — lib/proxyfile.js
 *
 * In-place editing of reverse-proxy sites inside a hand-maintained nginx file such as
 * conf.d/reverse-proxies.conf. A "site" is the group of top-level blocks for one
 * server_name, in the usual layout:
 *
 *   # ==========================================
 *   # JELLYFIN                                   <- header comment (site label)
 *   # ==========================================
 *   upstream jellyfin_backend { server ...; }    <- optional, when proxy_pass points at it
 *   server { listen 80; ... return 301 https://$host$request_uri; }   <- optional redirect
 *   server { listen 443 ssl; ... location / { proxy_pass ...; } }     <- main block
 *
 * Edits are surgical: each field only rewrites the directive(s) it owns, so comments,
 * tuning (keepalive, proxy_next_upstream, ...) and formatting elsewhere stay byte-for-byte.
 */

'use strict';

// ---------------------------------------------------------------------------
// Parser — blocks and directives with their exact character ranges
// ---------------------------------------------------------------------------
function parse(text) {
  const root = { type: 'root', children: [], bodyStart: 0, bodyEnd: text.length };
  const stack = [root];
  let words = [];
  let i = 0;
  const n = text.length;

  while (i < n) {
    const ch = text[i];
    // We are always between tokens here, and nginx starts a comment at any token-leading #
    if (ch === '#') {
      while (i < n && text[i] !== '\n') i++;
      continue;
    }
    if (/\s/.test(ch)) { i++; continue; }
    const top = stack[stack.length - 1];
    if (ch === ';') {
      if (words.length) {
        top.children.push({
          type: 'directive', name: words[0].text, args: words.slice(1),
          start: words[0].start, end: i + 1,
        });
      }
      words = [];
      i++;
      continue;
    }
    if (ch === '{') {
      const block = {
        type: 'block', name: words[0] ? words[0].text : '', args: words.slice(1),
        start: words[0] ? words[0].start : i, bodyStart: i + 1, children: [],
      };
      stack.push(block);
      words = [];
      i++;
      continue;
    }
    if (ch === '}') {
      if (stack.length === 1) throw new Error(`unexpected "}" at offset ${i}`);
      const block = stack.pop();
      block.bodyEnd = i;
      block.end = i + 1;
      stack[stack.length - 1].children.push(block);
      words = [];
      i++;
      continue;
    }
    // a word, possibly quoted
    const start = i;
    if (ch === '"' || ch === "'") {
      i++;
      while (i < n && text[i] !== ch) { if (text[i] === '\\') i++; i++; }
      i++;
    } else {
      while (i < n && !/[\s;{}]/.test(text[i])) i++;
    }
    words.push({ text: text.slice(start, i), start, end: i });
  }
  if (stack.length !== 1) throw new Error('unbalanced braces: missing "}"');
  return root;
}

const argsText = d => d.args.map(a => a.text).join(' ');
const unquote = s => s.replace(/^(["'])(.*)\1$/, '$2');
const directives = (block, name) => block.children.filter(c => c.type === 'directive' && c.name === name);
const firstDirective = (block, name) => directives(block, name)[0] || null;
const childBlocks = (block, name) => block.children.filter(c => c.type === 'block' && c.name === name);

function lineStart(text, idx) { return text.lastIndexOf('\n', idx - 1) + 1; }
function lineEnd(text, idx) { const e = text.indexOf('\n', idx); return e === -1 ? text.length : e; }
function indentAt(text, idx) { return text.slice(lineStart(text, idx), idx).match(/^[ \t]*/)[0]; }

// Range covering a node's whole line(s) when it sits alone on them, else just the node.
function lineRange(text, node) {
  const ls = lineStart(text, node.start);
  const le = lineEnd(text, node.end);
  const before = text.slice(ls, node.start);
  const after = text.slice(node.end, le);
  if (/^[ \t]*$/.test(before) && /^[ \t]*(#.*)?$/.test(after)) {
    return { start: ls, end: Math.min(le + 1, text.length) };
  }
  return { start: node.start, end: node.end };
}

// ---------------------------------------------------------------------------
// Site discovery
// ---------------------------------------------------------------------------
function blockPort(listens) {
  for (const l of listens) {
    const m = argsText(l).match(/(?:^|:|\])(\d+)(?:\s|$)/);
    if (m) return parseInt(m[1], 10);
  }
  return 80;
}

function serverInfo(node) {
  const names = directives(node, 'server_name').flatMap(d => d.args.map(a => a.text));
  const listens = directives(node, 'listen');
  const ret = firstDirective(node, 'return');
  const hasContent = childBlocks(node, 'location').length > 0 ||
    ['proxy_pass', 'root', 'alias'].some(n => firstDirective(node, n));
  const isHttpsRedirect = !!ret && !hasContent && /^30[1278]$/.test(ret.args[0] && ret.args[0].text) &&
    /^https:\/\//.test(unquote((ret.args[1] && ret.args[1].text) || ''));
  return {
    node, names, listens,
    ssl: listens.some(l => l.args.some(a => a.text === 'ssl')),
    port: blockPort(listens),
    isHttpsRedirect,
  };
}

// Comment lines directly above `idx` (no blank line in between) — the site header.
function headerAbove(text, idx) {
  let start = lineStart(text, idx);
  let hdrStart = start;
  for (;;) {
    if (hdrStart === 0) break;
    const prevStart = lineStart(text, hdrStart - 1);
    const line = text.slice(prevStart, hdrStart - 1);
    if (!/^\s*#/.test(line)) break;
    hdrStart = prevStart;
  }
  if (hdrStart === start) return null;
  let label = null, labelOffset = null, offset = hdrStart;
  for (const line of text.slice(hdrStart, start).split('\n')) {
    const content = line.replace(/^\s*#+\s?/, '');
    if (label === null && /[A-Za-z0-9]/.test(content)) {
      label = content.trim();
      const at = line.indexOf(content.trim());
      labelOffset = { start: offset + at, end: offset + at + content.trim().length };
    }
    offset += line.length + 1;
  }
  return { start: hdrStart, end: start, label, labelRange: labelOffset };
}

function parseProxyPass(value) {
  const m = unquote(value).match(/^(https?):\/\/([^/]+)(\/.*)?$/);
  if (!m) return null;
  return { scheme: m[1], host: m[2], path: m[3] || '' };
}

const LB_METHODS = ['least_conn', 'ip_hash', 'random', 'hash'];

function findSites(text) {
  const root = parse(text);
  const tops = root.children.filter(c => c.type === 'block');
  const upstreams = new Map(childBlocks(root, 'upstream').map(u => [u.args[0] && u.args[0].text, u]));
  const servers = childBlocks(root, 'server').map(serverInfo);

  // group server blocks by their first server_name
  const groups = new Map();
  for (const s of servers) {
    const key = s.names[0] || '_';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }

  const sites = [];
  for (const [name, members] of groups) {
    const redirects = members.filter(m => m.isHttpsRedirect);
    const mains = members.filter(m => !m.isHttpsRedirect).sort((a, b) => b.ssl - a.ssl);
    if (!mains.length) {
      sites.push(...redirects.map((r, i) => ({ key: i ? `${name}:${r.port}#${i}` : name, main: r, redirect: null, type: 'redirect' })));
      continue;
    }
    mains.forEach((main, i) => sites.push({
      key: i ? `${name}:${main.port}` : name,
      main,
      redirect: i === 0 ? redirects[0] || null : null,
    }));
  }

  // proxy_pass targets, to work out which upstreams belong to exactly one site
  const refCount = new Map();
  for (const site of sites) {
    const loc = childBlocks(site.main.node, 'location').find(l => argsText(l) === '/');
    const pp = loc && firstDirective(loc, 'proxy_pass');
    const target = pp && parseProxyPass(argsText(pp));
    site.loc = loc || null;
    site.proxyPass = pp || null;
    site.target = target;
    if (target && upstreams.has(target.host)) refCount.set(target.host, (refCount.get(target.host) || 0) + 1);
  }

  return sites.map(site => {
    const main = site.main.node;
    const loc = site.loc;
    const target = site.target;
    const upstream = target && upstreams.get(target.host) || null;
    const hsts = directives(main, 'add_header').some(d => /strict-transport-security/i.test(argsText(d)));
    const headers = loc ? directives(loc, 'proxy_set_header') : [];
    const readTimeout = loc && firstDirective(loc, 'proxy_read_timeout');
    const bodySize = firstDirective(main, 'client_max_body_size');
    const cert = firstDirective(main, 'ssl_certificate');
    const key = firstDirective(main, 'ssl_certificate_key');
    const nodes = [upstream && refCount.get(target.host) === 1 ? upstream : null,
      site.redirect && site.redirect.node, main].filter(Boolean).sort((a, b) => a.start - b.start);
    const header = headerAbove(text, nodes[0].start);
    const type = site.type || (site.proxyPass ? 'proxy' : firstDirective(main, 'return') ? 'redirect'
      : (firstDirective(main, 'root') || (loc && firstDirective(loc, 'root'))) ? 'static' : 'other');
    const ppText = site.proxyPass ? argsText(site.proxyPass) : '';

    return {
      key: site.key,
      label: header && header.label || site.main.names[0] || '(default)',
      serverName: site.main.names.join(' '),
      type,
      ssl: site.main.ssl,
      listenPort: site.main.port,
      httpRedirect: !!site.redirect,
      backends: upstream ? directives(upstream, 'server').map(argsText) : target ? [target.host] : [],
      backendScheme: target ? target.scheme : 'http',
      backendPath: target ? target.path : '',
      upstreamName: upstream ? target.host : null,
      upstreamShared: !!upstream && refCount.get(target.host) > 1,
      lbMethod: upstream ? (LB_METHODS.find(m => firstDirective(upstream, m)) || 'round_robin') : 'round_robin',
      certFile: cert ? unquote(argsText(cert)) : '',
      keyFile: key ? unquote(argsText(key)) : '',
      hsts,
      websockets: headers.some(h => /^upgrade$/i.test(h.args[0] && h.args[0].text)),
      clientMaxBodySize: bodySize ? argsText(bodySize) : '',
      proxyReadTimeout: readTimeout ? parseDuration(argsText(readTimeout)) : null,
      redirectTo: type === 'redirect' ? unquote(argsText(firstDirective(main, 'return')).replace(/^\d+\s+/, '')) : '',
      editable: type === 'proxy' && !!target && !ppText.includes('$'),
      readOnlyReason: type !== 'proxy' ? 'Only reverse-proxy sites can be edited here'
        : !target || ppText.includes('$') ? 'proxy_pass uses variables — edit the file directly' : null,
      // internal
      _nodes: nodes, _header: header, _main: main, _redirect: site.redirect && site.redirect.node,
      _loc: loc, _upstream: upstream, _proxyPass: site.proxyPass, _target: target,
    };
  });
}

function parseDuration(v) {
  const m = String(v).trim().match(/^(\d+)(ms|s|m|h)?$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return { ms: n / 1000, s: n, m: n * 60, h: n * 3600 }[m[2] || 's'];
}

function publicSite(s) {
  const out = {};
  for (const [k, v] of Object.entries(s)) if (!k.startsWith('_')) out[k] = v;
  return out;
}

// ---------------------------------------------------------------------------
// Validation — fields end up verbatim in nginx config, so be strict
// ---------------------------------------------------------------------------
const RE = {
  serverName: /^[A-Za-z0-9*._~-]+( [A-Za-z0-9*._~-]+)*$/,
  backend: /^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)(:\d{1,5})?( [a-z_]+=[A-Za-z0-9._:-]+| backup| down)*$/,
  path: /^(\/[A-Za-z0-9._~%!$&'()*+,=:@/-]*)?$/,
  absPath: /^\/[A-Za-z0-9._@/-]+$/,
  size: /^\d+[kKmMgG]?$/,
  label: /^[^\n\r#]{1,80}$/,
};

function validateFields(f, { creating }) {
  const errors = [];
  const check = (cond, msg) => { if (!cond) errors.push(msg); };
  if (f.name !== undefined) check(RE.label.test(f.name.trim()), 'Name: 1-80 characters, no # or newlines');
  if (f.serverName !== undefined || creating) check(RE.serverName.test((f.serverName || '').trim()), 'Domain: space-separated hostnames only');
  if (f.backends !== undefined || creating) {
    const b = (f.backends || []).map(x => x.trim()).filter(Boolean);
    check(b.length > 0, 'At least one backend is required');
    for (const x of b) check(RE.backend.test(x), `Backend "${x}": use host:port`);
  }
  if (f.backendScheme !== undefined) check(['http', 'https'].includes(f.backendScheme), 'Backend scheme must be http or https');
  if (f.backendPath !== undefined) check(RE.path.test(f.backendPath), 'Backend path must start with / and contain no spaces or ; { } #');
  if (f.lbMethod !== undefined) check(['round_robin', 'least_conn', 'ip_hash'].includes(f.lbMethod), 'Unknown load-balance method');
  for (const k of ['certFile', 'keyFile']) if (f[k]) check(RE.absPath.test(f[k]), `${k === 'certFile' ? 'Certificate' : 'Key'} must be an absolute path`);
  if (f.clientMaxBodySize) check(RE.size.test(f.clientMaxBodySize), 'Max body size like 20M, 512k or 0');
  if (f.proxyReadTimeout !== undefined && f.proxyReadTimeout !== null && f.proxyReadTimeout !== '')
    check(Number.isInteger(+f.proxyReadTimeout) && +f.proxyReadTimeout > 0 && +f.proxyReadTimeout <= 86400, 'Timeout must be 1-86400 seconds');
  if (f.listenPort !== undefined) check(Number.isInteger(+f.listenPort) && +f.listenPort > 0 && +f.listenPort < 65536, 'Port must be 1-65535');
  if (creating && f.ssl) check(f.certFile && f.keyFile, 'SSL needs a certificate and key');
  return errors;
}

// ---------------------------------------------------------------------------
// Edit helpers — collect {start, end, text} splices, apply from the end
// ---------------------------------------------------------------------------
function applyEdits(text, edits) {
  // From the end of the file backwards. At the same offset, apply the replacement before
  // the zero-width insertion so the inserted text ends up in front of it; multiple
  // insertions at one offset keep the order they were pushed in.
  const sorted = edits.map((e, i) => ({ ...e, i })).sort((a, b) => b.start - a.start || b.end - a.end || b.i - a.i);
  let out = text;
  let floor = Infinity;
  for (const e of sorted) {
    if (e.end > floor) throw new Error('internal error: overlapping edits');
    out = out.slice(0, e.start) + e.text + out.slice(e.end);
    floor = e.start;
  }
  return out;
}

function childIndent(text, block) {
  const first = block.children[0];
  if (first) return indentAt(text, first.start);
  return indentAt(text, block.start) + '    ';
}

// Set (replace or insert) a single-valued directive in `block`.
function setDirective(text, block, name, value, edits, anchors = []) {
  const existing = directives(block, name);
  if (existing.length) {
    const d = existing[0];
    const argStart = d.args.length ? d.args[0].start : d.end - 1;
    const argEnd = d.args.length ? d.args[d.args.length - 1].end : d.end - 1;
    if (text.slice(argStart, argEnd) !== value) {
      edits.push({ start: argStart, end: argEnd, text: (d.args.length ? '' : ' ') + value });
    }
    existing.slice(1).forEach(x => edits.push({ ...lineRange(text, x), text: '' }));
    return;
  }
  insertLine(text, block, `${name} ${value};`, edits, anchors);
}

function insertLine(text, block, line, edits, anchors = []) {
  const indent = childIndent(text, block);
  let anchor = null;
  for (const a of anchors) {
    const found = typeof a === 'function' ? block.children.filter(a).pop() : directives(block, a).pop();
    if (found) { anchor = found; break; }
  }
  if (anchor) {
    const at = lineEnd(text, anchor.end);
    edits.push({ start: at, end: at, text: `\n${indent}${line}` });
    return;
  }
  const firstBlock = block.children.find(c => c.type === 'block');
  if (firstBlock) {
    const at = lineStart(text, firstBlock.start);
    edits.push({ start: at, end: at, text: `${indent}${line}\n\n` });
    return;
  }
  const at = lineStart(text, block.bodyEnd);
  edits.push({ start: at, end: at, text: `${indent}${line}\n` });
}

function removeDirectives(text, nodes, edits) {
  for (const d of nodes) {
    const r = lineRange(text, d);
    // Don't leave a double blank line where the directive sat between two blank lines.
    const prevLine = r.start > 0 ? text.slice(lineStart(text, r.start - 1), r.start - 1) : null;
    const nextLine = text.slice(r.end, lineEnd(text, r.end));
    if (r.start !== d.start && prevLine !== null && /^[ \t]*$/.test(prevLine) && /^[ \t]*$/.test(nextLine) && r.end < text.length) {
      r.end = Math.min(lineEnd(text, r.end) + 1, text.length);
    }
    edits.push({ ...r, text: '' });
  }
}

function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'site';
}

function uniqueUpstreamName(text, base) {
  const root = parse(text);
  const taken = new Set(childBlocks(root, 'upstream').map(u => u.args[0] && u.args[0].text));
  let name = `${base}_backend`;
  for (let i = 2; taken.has(name); i++) name = `${base}_backend${i}`;
  return name;
}

function upstreamText(name, backends, lbMethod, indent = '') {
  return [
    `${indent}upstream ${name} {`,
    ...(lbMethod && lbMethod !== 'round_robin' ? [`${indent}    ${lbMethod};`] : []),
    ...backends.map(b => `${indent}    server ${b};`),
    `${indent}}`,
  ].join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Edit an existing site in place
// ---------------------------------------------------------------------------
function editSite(text, key, f, ctx = {}) {
  const site = findSites(text).find(s => s.key === key);
  if (!site) throw new Error(`site ${key} not found in file`);
  if (!site.editable) throw new Error(site.readOnlyReason || 'site is not editable');
  const errors = validateFields(f, { creating: false });
  if (errors.length) { const e = new Error(errors.join('; ')); e.status = 400; throw e; }

  const edits = [];
  const main = site._main, loc = site._loc;

  // label (header comment)
  if (f.name !== undefined && f.name.trim() && f.name.trim() !== site.label) {
    if (site._header && site._header.labelRange) {
      edits.push({ ...site._header.labelRange, text: f.name.trim() });
    } else {
      const at = lineStart(text, site._nodes[0].start);
      edits.push({ start: at, end: at, text: headerText(f.name.trim()) });
    }
  }

  // server_name in main + redirect
  if (f.serverName !== undefined && f.serverName.trim() !== site.serverName) {
    for (const block of [main, site._redirect].filter(Boolean)) {
      setDirective(text, block, 'server_name', f.serverName.trim(), edits, ['listen']);
    }
  }

  // backends / scheme / path / load-balancing
  const backends = f.backends !== undefined ? f.backends.map(b => b.trim()).filter(Boolean) : site.backends;
  const scheme = f.backendScheme || site.backendScheme;
  const pathPart = f.backendPath !== undefined ? f.backendPath : site.backendPath;
  const lbMethod = f.lbMethod || site.lbMethod;
  const backendsChanged = JSON.stringify(backends) !== JSON.stringify(site.backends);
  let proxyHost = site._target.host;

  if (site._upstream) {
    const up = site._upstream;
    if (backendsChanged) {
      const servers = directives(up, 'server');
      const indent = servers.length ? indentAt(text, servers[0].start) : childIndent(text, up);
      const block = backends.map(b => `${indent}server ${b};`).join('\n') + '\n';
      if (servers.length) {
        const first = lineRange(text, servers[0]);
        edits.push({ start: first.start, end: first.end, text: block });
        removeDirectives(text, servers.slice(1), edits);
      } else {
        const at = lineStart(text, up.bodyEnd);
        edits.push({ start: at, end: at, text: block });
      }
    }
    if (lbMethod !== site.lbMethod) {
      removeDirectives(text, LB_METHODS.flatMap(m => directives(up, m)), edits);
      if (lbMethod !== 'round_robin') {
        const at = lineEnd(text, up.bodyStart) + 1;
        edits.push({ start: at, end: at, text: `${childIndent(text, up)}${lbMethod};\n` });
      }
    }
  } else if (backends.length > 1 || (backendsChanged && lbMethod !== 'round_robin')) {
    // a single backend becomes a pool: add an upstream block above the site's blocks
    proxyHost = uniqueUpstreamName(text, slug(f.name || site.label));
    const at = lineStart(text, site._nodes[0].start);
    edits.push({ start: at, end: at, text: upstreamText(proxyHost, backends, lbMethod) });
  } else if (backendsChanged) {
    proxyHost = backends[0];
  }

  const newProxyPass = `${scheme}://${proxyHost}${pathPart}`;
  if (newProxyPass !== argsText(site._proxyPass)) {
    setDirective(text, loc, 'proxy_pass', newProxyPass, edits);
  }

  // TLS certificate (only for sites already serving TLS)
  if (site.ssl) {
    if (f.certFile && f.certFile !== site.certFile) setDirective(text, main, 'ssl_certificate', f.certFile, edits, ['server_name']);
    if (f.keyFile && f.keyFile !== site.keyFile) setDirective(text, main, 'ssl_certificate_key', f.keyFile, edits, ['ssl_certificate', 'server_name']);
    if (f.hsts !== undefined && !!f.hsts !== site.hsts) {
      const existing = directives(main, 'add_header').filter(d => /strict-transport-security/i.test(argsText(d)));
      if (f.hsts) insertLine(text, main, 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', edits, ['ssl_certificate_key', 'ssl_certificate', 'server_name']);
      else removeDirectives(text, existing, edits);
    }
  }

  // client_max_body_size (server level)
  if (f.clientMaxBodySize !== undefined && f.clientMaxBodySize !== site.clientMaxBodySize) {
    if (f.clientMaxBodySize) setDirective(text, main, 'client_max_body_size', f.clientMaxBodySize, edits, ['proxy_buffering', 'ssl_certificate_key', 'server_name']);
    else removeDirectives(text, directives(main, 'client_max_body_size'), edits);
  }

  // proxy_read_timeout (and proxy_send_timeout if the site already sets it)
  if (f.proxyReadTimeout !== undefined) {
    const want = f.proxyReadTimeout === '' || f.proxyReadTimeout === null ? null : parseInt(f.proxyReadTimeout, 10);
    if (want !== site.proxyReadTimeout) {
      if (want === null) {
        removeDirectives(text, [...directives(loc, 'proxy_read_timeout'), ...directives(loc, 'proxy_send_timeout')], edits);
      } else {
        setDirective(text, loc, 'proxy_read_timeout', `${want}s`, edits, ['proxy_connect_timeout', 'proxy_pass']);
        if (directives(loc, 'proxy_send_timeout').length) setDirective(text, loc, 'proxy_send_timeout', `${want}s`, edits);
      }
    }
  }

  // WebSockets
  if (f.websockets !== undefined && !!f.websockets !== site.websockets) {
    const hdr = name => directives(loc, 'proxy_set_header').filter(d => new RegExp(`^${name}$`, 'i').test(d.args[0] && d.args[0].text));
    if (f.websockets) {
      const lines = [];
      if (!directives(loc, 'proxy_http_version').length) lines.push('proxy_http_version 1.1;');
      lines.push('proxy_set_header Upgrade $http_upgrade;');
      if (!hdr('Connection').length) lines.push(`proxy_set_header Connection ${ctx.connectionUpgradeMap ? '$connection_upgrade' : '"upgrade"'};`);
      const indent = childIndent(text, loc);
      const at = lineStart(text, loc.bodyEnd);
      edits.push({ start: at, end: at, text: `\n${indent}# WebSockets\n` + lines.map(l => indent + l).join('\n') + '\n' });
    } else {
      removeDirectives(text, [...hdr('Upgrade'), ...hdr('Connection')], edits);
    }
  }

  return edits.length ? applyEdits(text, edits) : text;
}

// ---------------------------------------------------------------------------
// New sites, in the same layout as the hand-written ones
// ---------------------------------------------------------------------------
function headerText(label) {
  return `# ==========================================\n# ${label}\n# ==========================================\n`;
}

function generateSite(text, f, ctx = {}) {
  const errors = validateFields(f, { creating: true });
  if (errors.length) { const e = new Error(errors.join('; ')); e.status = 400; throw e; }
  const name = f.serverName.trim();
  const backends = f.backends.map(b => b.trim()).filter(Boolean);
  const scheme = f.backendScheme || 'http';
  const pathPart = f.backendPath || '';
  const label = (f.name || name.split(' ')[0]).trim();
  const out = [headerText(label)];

  let host = backends[0];
  if (backends.length > 1) {
    host = uniqueUpstreamName(text, slug(label));
    out.push(upstreamText(host, backends, f.lbMethod));
  }

  const loc = [
    `        proxy_pass ${scheme}://${host}${pathPart};`,
    '        proxy_set_header Host $host;',
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
    '        proxy_set_header X-Forwarded-Proto $scheme;',
    '        proxy_set_header X-Forwarded-Protocol $scheme;',
    '        proxy_set_header X-Forwarded-Host $http_host;',
  ];
  if (f.proxyReadTimeout) loc.push(`        proxy_read_timeout ${parseInt(f.proxyReadTimeout, 10)}s;`);
  if (f.websockets !== false) {
    loc.push('', '        # WebSockets', '        proxy_http_version 1.1;',
      '        proxy_set_header Upgrade $http_upgrade;',
      `        proxy_set_header Connection ${ctx.connectionUpgradeMap ? '$connection_upgrade' : '"upgrade"'};`);
  }

  if (f.ssl) {
    if (f.httpRedirect !== false) {
      out.push([
        'server {', '    listen 80;', '    listen [::]:80;', `    server_name ${name};`,
        '    return 301 https://$host$request_uri;', '}', '',
      ].join('\n') + '\n');
    }
    const srv = [
      'server {', '    listen 443 ssl;', '    listen [::]:443 ssl;', `    server_name ${name};`, '',
      `    ssl_certificate ${f.certFile};`, `    ssl_certificate_key ${f.keyFile};`,
    ];
    if (f.hsts) srv.push('    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;');
    if (f.clientMaxBodySize) srv.push('', `    client_max_body_size ${f.clientMaxBodySize};`);
    srv.push('', '    location / {', ...loc, '    }', '}');
    out.push(srv.join('\n') + '\n');
  } else {
    const port = parseInt(f.listenPort || 80, 10);
    const srv = ['server {', `    listen ${port};`, `    listen [::]:${port};`, `    server_name ${name};`];
    if (f.clientMaxBodySize) srv.push('', `    client_max_body_size ${f.clientMaxBodySize};`);
    srv.push('', '    location / {', ...loc, '    }', '}');
    out.push(srv.join('\n') + '\n');
  }
  return out.join('');
}

function addSite(text, f, ctx = {}) {
  const block = generateSite(text, f, ctx);
  let base = text;
  if (base.length && !base.endsWith('\n')) base += '\n';
  if (base.trim().length) base += '\n';
  else base = '';
  return base + block;
}

// ---------------------------------------------------------------------------
// Remove a site: its header, owned upstream, redirect and main blocks
// ---------------------------------------------------------------------------
function removeSite(text, key) {
  const site = findSites(text).find(s => s.key === key);
  if (!site) throw new Error(`site ${key} not found in file`);
  const ranges = [];
  if (site._header) ranges.push({ start: site._header.start, end: site._header.end });
  for (const node of site._nodes) {
    const r = { start: lineStart(text, node.start), end: Math.min(lineEnd(text, node.end) + 1, text.length) };
    ranges.push(r);
  }
  // swallow one blank line following the last block
  const last = ranges[ranges.length - 1];
  const rest = text.slice(last.end);
  const blank = rest.match(/^[ \t]*\n/);
  if (blank) last.end += blank[0].length;
  // merge ranges separated only by whitespace (the blank line between redirect and main)
  const merged = [];
  for (const r of ranges.sort((a, b) => a.start - b.start)) {
    const prev = merged[merged.length - 1];
    if (prev && /^\s*$/.test(text.slice(prev.end, r.start))) prev.end = Math.max(prev.end, r.end);
    else merged.push({ ...r });
  }
  const out = applyEdits(text, merged.map(r => ({ ...r, text: '' })));
  // removing the last site shouldn't leave blank lines at the end of the file
  return merged[merged.length - 1].end >= text.length ? out.replace(/\n\s*$/, '\n') : out;
}

// ---------------------------------------------------------------------------
// Point ssl_certificate / ssl_certificate_key directives (any depth) at new files.
//   pathMap: { oldPath: newPath }  → { text, count }
// ---------------------------------------------------------------------------
function replaceCertPaths(text, pathMap) {
  const root = parse(text);
  const edits = [];
  const walk = node => {
    for (const c of node.children) {
      if (c.type === 'block') walk(c);
      else if ((c.name === 'ssl_certificate' || c.name === 'ssl_certificate_key') && c.args.length === 1) {
        const to = pathMap[unquote(c.args[0].text)];
        if (to && to !== unquote(c.args[0].text)) edits.push({ start: c.args[0].start, end: c.args[0].end, text: to });
      }
    }
  };
  walk(root);
  return { text: edits.length ? applyEdits(text, edits) : text, count: edits.length };
}

module.exports = { parse, findSites, publicSite, editSite, addSite, generateSite, removeSite, validateFields, replaceCertPaths };
