/**
 * nginx-manager — lib/nginxconf.js
 *
 * Visual-builder site <-> nginx config conversion.
 */

'use strict';

const { randomUUID: uuidv4 } = require('crypto');

// ---------------------------------------------------------------------------
// Visual-builder: generate nginx config from site definition
// ---------------------------------------------------------------------------
function siteToNginxConf(site) {
  const lines = [];
  const ssl   = site.ssl && site.certFile;

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
// Lightweight nginx conf parser — extracts the key fields we care about.
// ---------------------------------------------------------------------------
function parseNginxConf(filename, raw) {
  const text  = raw.replace(/#[^\n]*/g, '');   // strip comments
  const lines = text.replace(/\r/g, '').split('\n').map(l => l.trim()).filter(Boolean);

  // Helper: grab first match of a directive inside a block string
  const directive = (block, name) => {
    // Directive at the start of a line, or after `{` / `;` on the same line
    const m = block.match(new RegExp(`(?:^|[\\n{;])\\s*${name}\\s+([^;{\\n]+);`));
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

module.exports = { siteToNginxConf, parseNginxConf };
