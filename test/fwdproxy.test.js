'use strict';

const test   = require('node:test');
const assert = require('node:assert');
const bcrypt = require('bcryptjs');
const fp     = require('../lib/fwdproxy');

const base = {
  name: 'OFFICE PROXY', listen: '3128', allowNetworks: ['10.1.1.0/24'], allowedPorts: [443],
  allowedHosts: ['example.com', '*.example.com'], resolver: '192.0.2.53', users: [],
};

test('version gate: tunnel module needs nginx 1.31.0+', () => {
  assert.equal(fp.versionAtLeast('1.31.0'), true);
  assert.equal(fp.versionAtLeast('1.31.6'), true);
  assert.equal(fp.versionAtLeast('1.32.1'), true);
  assert.equal(fp.versionAtLeast('2.0.0'), true);
  assert.equal(fp.versionAtLeast('1.30.4'), false);
  assert.equal(fp.versionAtLeast('1.29.8'), false);
  assert.equal(fp.versionAtLeast(null), false);
  assert.equal(fp.versionAtLeast('nginx/1.31.2'), true);
});

test('generates maps + server and discovers them back', () => {
  const p = fp.plan('', { fields: base, nginxDir: '/etc/nginx' });
  assert.equal(p.key, 'office_proxy');
  assert.match(p.conf, /map \$request_port \$fwdproxy_office_proxy_port \{\n    default 0;\n    443 1;\n\}/);
  assert.match(p.conf, /    hostnames;\n    default 0;\n    example\.com 1;\n    \*\.example\.com 1;/);
  assert.match(p.conf, /allow 10\.1\.1\.0\/24;\n    deny all;/);
  assert.match(p.conf, /tunnel_pass;\n\}\n$/);
  assert.ok(!p.conf.includes('auth_basic'), 'no login section without users');
  const [d] = fp.findForwardProxies(p.conf).map(fp.publicProxy);
  assert.equal(d.label, 'OFFICE PROXY');
  assert.equal(d.listen, '3128');
  assert.deepEqual(d.allowNetworks, ['10.1.1.0/24']);
  assert.deepEqual(d.allowedPorts, [443]);
  assert.deepEqual(d.allowedHosts, ['example.com', '*.example.com']);
  assert.equal(d.blockIpLiterals, true);
  assert.equal(d.resolver, '192.0.2.53');
  assert.equal(d.idleTimeout, 300);
});

test('users: bcrypt hashes only, unchanged passwords keep their hash', () => {
  const p1 = fp.plan('', { fields: { ...base, users: [{ username: 'alice', password: 'correct-horse-battery' }] }, nginxDir: '/etc/nginx' });
  assert.equal(p1.authFile, '/etc/nginx/forward-proxy/office_proxy.htpasswd');
  assert.match(p1.conf, /auth_basic "Proxy";\n    auth_basic_user_file \/etc\/nginx\/forward-proxy\/office_proxy\.htpasswd;/);
  assert.ok(!p1.htpasswd.includes('correct-horse-battery'), 'no plaintext');
  const [alice] = fp.parseHtpasswd(p1.htpasswd);
  assert.match(alice.hash, /^\$2b\$11\$/);
  assert.ok(bcrypt.compareSync('correct-horse-battery', alice.hash.replace(/^\$2b\$/, '$2a$')));

  const cur = fp.findForwardProxies(p1.conf).map(fp.publicProxy)[0];
  const p2 = fp.plan(p1.conf, { key: cur.key, existingHtpasswd: p1.htpasswd, nginxDir: '/etc/nginx',
    fields: { ...cur, users: [{ username: 'alice' }, { username: 'bob', password: 'another-long-password' }] } });
  const after = fp.parseHtpasswd(p2.htpasswd);
  assert.equal(after.find(u => u.username === 'alice').hash, alice.hash);
  assert.deepEqual(after.map(u => u.username), ['alice', 'bob']);
  assert.throws(() => fp.plan(p1.conf, { key: cur.key, existingHtpasswd: p1.htpasswd, nginxDir: '/etc/nginx',
    fields: { ...cur, users: [{ username: 'carol' }] } }), /Set a password for new user carol/);
});

test('edit keeps unmanaged directives and a custom log path', () => {
  const p = fp.plan('', { fields: base, nginxDir: '/etc/nginx' });
  const hand = p.conf
    .replace('    tunnel_pass;', '    tunnel_buffer_size 32k;\n\n    tunnel_pass;')
    .replace('/var/log/nginx/fwdproxy_office_proxy.access.log', '/srv/logs/proxy.log');
  const cur = fp.findForwardProxies(hand).map(fp.publicProxy)[0];
  assert.deepEqual(cur.extraDirectives, ['tunnel_buffer_size 32k;']);
  const out = fp.plan(hand, { key: cur.key, nginxDir: '/etc/nginx', fields: { ...cur, idleTimeout: 600 } }).conf;
  assert.match(out, /tunnel_buffer_size 32k;/);
  assert.match(out, /access_log \/srv\/logs\/proxy\.log;/);
  assert.match(out, /tunnel_read_timeout 600s;/);
});

test('refuses open proxies and bad input', () => {
  assert.throws(() => fp.plan('', { fields: { ...base, allowNetworks: [], users: [] }, nginxDir: '/etc/nginx' }), /open proxy/);
  const bad = [
    { listen: '3128; include /x' }, { allowNetworks: ['10.0.0.0/8; allow all'] }, { allowedHosts: ['x.com; return 200'] },
    { resolver: 'dns.example.com' }, { allowedPorts: [] }, { name: 'x\n}' }, { authRealm: 'a" ; b' },
  ];
  for (const f of bad) assert.throws(() => fp.plan('', { fields: { ...base, ...f }, nginxDir: '/etc/nginx' }), undefined, JSON.stringify(f));
});

test('any destination host; IP literals blocked or not', () => {
  const p = fp.plan('', { fields: { ...base, allowedHosts: [], blockIpLiterals: false }, nginxDir: '/etc/nginx' });
  assert.match(p.conf, /hostnames;\n    default 1;\n\}/);
  const d = fp.findForwardProxies(p.conf).map(fp.publicProxy)[0];
  assert.equal(d.anyHost, true);
  assert.equal(d.blockIpLiterals, false);
});

test('second proxy gets its own variables; same listen is rejected; remove', () => {
  const a = fp.plan('', { fields: base, nginxDir: '/etc/nginx' }).conf;
  const b = fp.plan(a, { fields: { ...base, listen: '3129' }, nginxDir: '/etc/nginx' });
  assert.equal(b.key, 'office_proxy_2');
  assert.equal(fp.findForwardProxies(b.conf).length, 2);
  assert.throws(() => fp.plan(a, { fields: base, nginxDir: '/etc/nginx' }), /already listens on 3128/);
  const r = fp.remove(b.conf, 'office_proxy_2');
  assert.equal(r.conf, a);
  assert.equal(r.authFile, '');
});
