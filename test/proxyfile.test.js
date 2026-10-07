'use strict';

const test   = require('node:test');
const assert = require('node:assert');
const pf     = require('../lib/proxyfile');
const { unifiedDiff } = require('../lib/linediff');

// Same layout as a hand-maintained conf.d/reverse-proxies.conf
const FIXTURE = `# ==========================================
# MEDIA
# ==========================================
upstream media_backend {
    server 192.0.2.7:8096;

    # pooled connections — keep this comment
    keepalive 32;
    keepalive_timeout 60s;
}
server {
    listen 80;
    listen [::]:80;
    server_name media.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name media.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    proxy_buffering off;
    client_max_body_size 20M;

    location / {
        proxy_pass http://media_backend;
        proxy_connect_timeout 5s;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_next_upstream error timeout http_502;
        proxy_set_header Host $host;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}

# ==========================================
# REMOTE DESKTOP
# ==========================================
server {
    listen 80;
    listen [::]:80;
    server_name rd.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name rd.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://198.51.100.20:8080/guacamole/;
        proxy_set_header Host $host;

        # WebSockets
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# ==========================================
# VAULT
# ==========================================
server {
    listen 443 ssl;
    server_name vault.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    client_max_body_size 128M;

    location / {
        proxy_pass http://$vault_upstream;
    }
}
`;

const site = (text, key) => pf.findSites(text).map(pf.publicSite).find(s => s.key === key);
const changedLines = (a, b) => unifiedDiff(a, b, 0).split('\n').filter(l => /^[+-]/.test(l));

test('discovers sites with header labels, upstreams and paths', () => {
  const sites = pf.findSites(FIXTURE).map(pf.publicSite);
  assert.deepEqual(sites.map(s => s.key), ['media.example.com', 'rd.example.com', 'vault.example.com']);
  const media = sites[0];
  assert.equal(media.label, 'MEDIA');
  assert.equal(media.upstreamName, 'media_backend');
  assert.deepEqual(media.backends, ['192.0.2.7:8096']);
  assert.equal(media.clientMaxBodySize, '20M');
  assert.equal(media.proxyReadTimeout, 300);
  assert.equal(media.websockets, true);
  assert.equal(media.httpRedirect, true);
  assert.equal(media.editable, true);
  const rd = sites[1];
  assert.deepEqual(rd.backends, ['198.51.100.20:8080']);
  assert.equal(rd.backendPath, '/guacamole/');
  assert.equal(sites[2].editable, false, 'proxy_pass with a variable is read-only');
});

test('no-op edit changes nothing', () => {
  const s = site(FIXTURE, 'media.example.com');
  const out = pf.editSite(FIXTURE, s.key, {
    name: s.label, serverName: s.serverName, backends: s.backends, backendScheme: s.backendScheme,
    backendPath: s.backendPath, lbMethod: s.lbMethod, certFile: s.certFile, keyFile: s.keyFile,
    hsts: s.hsts, websockets: s.websockets, clientMaxBodySize: s.clientMaxBodySize, proxyReadTimeout: s.proxyReadTimeout,
  });
  assert.equal(out, FIXTURE);
});

test('editing an upstream pool keeps its other settings and comments', () => {
  const out = pf.editSite(FIXTURE, 'media.example.com', {
    backends: ['192.0.2.7:8096', '192.0.2.8:8096'], lbMethod: 'least_conn',
  });
  assert.deepEqual(changedLines(FIXTURE, out), ['+    least_conn;', '+    server 192.0.2.8:8096;']);
  assert.match(out, /# pooled connections — keep this comment\n    keepalive 32;/);
});

test('domain, timeout and body size touch only their own lines', () => {
  const out = pf.editSite(FIXTURE, 'rd.example.com', {
    serverName: 'desk.example.com', proxyReadTimeout: 120, clientMaxBodySize: '50M',
  });
  assert.deepEqual(changedLines(FIXTURE, out), [
    '-    server_name rd.example.com;', '+    server_name desk.example.com;',
    '-    server_name rd.example.com;', '+    server_name desk.example.com;',
    '+    client_max_body_size 50M;',
    '+        proxy_read_timeout 120s;',
  ]);
  assert.equal(site(out, 'desk.example.com').proxyReadTimeout, 120);
});

test('one backend becoming two creates an upstream pool', () => {
  const out = pf.editSite(FIXTURE, 'rd.example.com', { backends: ['198.51.100.20:8080', '198.51.100.21:8080'] });
  const s = site(out, 'rd.example.com');
  assert.equal(s.upstreamName, 'remote_desktop_backend');
  assert.deepEqual(s.backends, ['198.51.100.20:8080', '198.51.100.21:8080']);
  assert.equal(s.backendPath, '/guacamole/', 'path kept on proxy_pass');
  assert.ok(out.indexOf('upstream remote_desktop_backend') > out.indexOf('# REMOTE DESKTOP'), 'pool goes under the header');
});

test('label, path, HSTS and websockets', () => {
  let out = pf.editSite(FIXTURE, 'rd.example.com', { name: 'DESKTOP', backendPath: '/rd/', hsts: true, websockets: false });
  const s = site(out, 'rd.example.com');
  assert.equal(s.label, 'DESKTOP');
  assert.equal(s.backendPath, '/rd/');
  assert.equal(s.hsts, true);
  assert.equal(s.websockets, false);
  assert.match(out, /proxy_http_version 1\.1;/, 'http_version kept (keepalive needs it)');
  out = pf.editSite(out, 'rd.example.com', { websockets: true }, { connectionUpgradeMap: true });
  assert.equal(site(out, 'rd.example.com').websockets, true);
});

test('removing a directive does not leave a double blank line', () => {
  const out = pf.editSite(FIXTURE, 'media.example.com', { clientMaxBodySize: '' });
  assert.ok(!out.includes('\n\n\n'));
  assert.equal(site(out, 'media.example.com').clientMaxBodySize, '');
});

test('add appends a site in the same layout; remove takes it back out', () => {
  const fields = {
    name: 'GRAFANA', serverName: 'grafana.example.com', backends: ['192.0.2.50:3000'], ssl: true,
    certFile: '/etc/letsencrypt/live/example.com/fullchain.pem', keyFile: '/etc/letsencrypt/live/example.com/privkey.pem',
  };
  const out = pf.addSite(FIXTURE, fields, { connectionUpgradeMap: true });
  assert.ok(out.startsWith(FIXTURE), 'existing content untouched');
  const s = site(out, 'grafana.example.com');
  assert.equal(s.label, 'GRAFANA');
  assert.equal(s.httpRedirect, true);
  assert.equal(s.ssl, true);
  assert.match(out, /proxy_set_header Connection \$connection_upgrade;\n    }\n}\n$/);
  assert.equal(pf.removeSite(out, 'grafana.example.com'), FIXTURE);
});

test('add to an empty or missing file', () => {
  const out = pf.addSite('', { name: 'APP', serverName: 'app.example.com', backends: ['192.0.2.9:80'], ssl: false, listenPort: 8080 });
  assert.match(out, /^# =+\n# APP\n/);
  assert.equal(site(out, 'app.example.com').listenPort, 8080);
});

test('removing a site removes its own upstream but nothing else', () => {
  const out = pf.removeSite(FIXTURE, 'media.example.com');
  assert.ok(!out.includes('media_backend'));
  assert.ok(out.startsWith('# ==========================================\n# REMOTE DESKTOP'));
  assert.ok(!out.includes('\n\n\n'));
  assert.deepEqual(pf.findSites(out).map(s => s.key), ['rd.example.com', 'vault.example.com']);
});

test('rejects values that could inject config', () => {
  const bad = [
    { serverName: 'x.com; include /etc/passwd' },
    { backends: ['192.0.2.1:80; } server {'] },
    { backendPath: '/a; return 200' },
    { clientMaxBodySize: '1M; root /' },
    { name: 'x\n}' },
    { certFile: '/etc/x.pem; root /' },
  ];
  for (const f of bad) assert.throws(() => pf.editSite(FIXTURE, 'rd.example.com', f), /must|only|use host:port|like|characters/, JSON.stringify(f));
});

test('read-only sites refuse edits', () => {
  assert.throws(() => pf.editSite(FIXTURE, 'vault.example.com', { proxyReadTimeout: 30 }), /variables/);
});

test('replaceCertPaths swaps only matching ssl_certificate(_key) values', () => {
  const { text, count } = pf.replaceCertPaths(FIXTURE, {
    '/etc/letsencrypt/live/example.com/fullchain.pem': '/etc/nginx/ssl/example.com/fullchain.pem',
    '/etc/letsencrypt/live/example.com/privkey.pem': '/etc/nginx/ssl/example.com/privkey.pem',
  });
  assert.equal(count, 6, 'three sites × cert + key');
  assert.ok(!text.includes('/etc/letsencrypt/live/example.com/'));
  assert.deepEqual(changedLines(FIXTURE, text).filter(l => l.startsWith('+')).every(l => /ssl_certificate(_key)? \/etc\/nginx\/ssl\//.test(l)), true);
  assert.equal(pf.replaceCertPaths(FIXTURE, { '/nope': '/x' }).count, 0);
});
