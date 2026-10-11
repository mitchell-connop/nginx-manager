'use strict';

const test = require('node:test');
const assert = require('node:assert');
const ds = require('../lib/defaultserver');

const FILES = {
  '/etc/nginx/conf.d/reverse-proxies.conf': `
server { listen 80; listen [::]:80; server_name a.example.com; return 301 https://$host$request_uri; }
server { listen 443 ssl; listen [::]:443 ssl; http2 on; server_name a.example.com b.example.com; }`,
  '/etc/nginx/conf.d/forward-proxies.conf': 'server { listen 3128; tunnel_pass; }',
  '/etc/nginx/conf.d/00-nginx-manager-status.conf': 'server { listen 127.0.0.1:8099; location = /nm_status { stub_status; } }',
  '/etc/nginx/stream.d/rtsp.conf': 'server { listen 8554; proxy_pass x; }',
};

test('covers name-based listeners only', () => {
  const s = ds.scan(FILES, '/etc/nginx/conf.d/00-nginx-manager-default.conf');
  assert.deepStrictEqual(s.listeners.map(l => `${l.key}${l.ssl ? ' ssl' : ''}`), ['*:443 ssl', '*:80', '[::]:443 ssl', '[::]:80']);
  assert.ok(s.skipped.some(x => x.key === '*:3128'));
  assert.ok(!s.listeners.some(l => l.port === 8554 || l.port === 8099));
});

test('drop: 444 on HTTP, TLS handshake rejected on HTTPS; settings round-trip', () => {
  const { listeners } = ds.scan(FILES, '');
  const out = ds.generate({ action: 'drop' }, listeners);
  assert.match(out, /listen 80 default_server;\n    listen \[::\]:80 default_server;\n    server_name _;\n    return 444;/);
  assert.match(out, /listen 443 ssl default_server;\n    listen \[::\]:443 ssl default_server;\n    server_name _;\n    ssl_reject_handshake on;/);
  assert.strictEqual(ds.parseOwn(out).action, 'drop');
});

test('redirect / status, with and without a certificate', () => {
  const { listeners } = ds.scan(FILES, '');
  const r = ds.generate({ action: 'redirect', redirectUrl: 'https://www.example.com/', redirectCode: 301, keepPath: false }, listeners);
  assert.match(r, /return 301 https:\/\/www\.example\.com\/;/);
  assert.match(r, /ssl_reject_handshake on;/);                     // no cert → HTTPS still refused
  const rc = ds.generate({ action: 'status', status: 404, certFile: '/etc/nginx/ssl/a/fullchain.pem', keyFile: '/etc/nginx/ssl/a/privkey.pem' }, listeners);
  assert.match(rc, /ssl_certificate \/etc\/nginx\/ssl\/a\/fullchain\.pem;\n    ssl_certificate_key \/etc\/nginx\/ssl\/a\/privkey\.pem;\n    return 404;/);
  assert.throws(() => ds.generate({ action: 'redirect', redirectUrl: 'javascript:x' }, listeners), /Redirect URL/);
});

test('an existing default_server is a conflict, not overwritten', () => {
  const s = ds.scan({ ...FILES, '/etc/nginx/conf.d/x.conf': 'server { listen 80 default_server; server_name x.example.com; }' }, '');
  assert.deepStrictEqual(s.conflicts.map(c => c.key), ['*:80']);
  assert.ok(!s.listeners.some(l => l.key === '*:80'));
});
