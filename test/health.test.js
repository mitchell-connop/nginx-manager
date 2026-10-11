'use strict';

const test = require('node:test');
const assert = require('node:assert');
const h = require('../lib/health');

const CONF = {
  '/etc/nginx/conf.d/reverse-proxies.conf': `
upstream jellyfin_backend { server 192.0.2.7:8096; server 192.0.2.8:8096 backup; keepalive 32; }
server { listen 443 ssl; server_name media.example.com;
  location / { proxy_pass http://jellyfin_backend; } }
server { listen 443 ssl; server_name home.example.com;
  location / { proxy_pass https://192.0.2.43:8123/; } }
server { listen 443 ssl; server_name var.example.com;
  location / { proxy_pass http://$backend; } }
server { listen 443 ssl; server_name sock.example.com;
  location / { proxy_pass http://unix:/run/app.sock; } }`,
  '/etc/nginx/stream.d/rtsp-streams.conf': 'upstream rtsp_cam { server 192.0.2.20:554; }\nserver { listen 8554; proxy_pass rtsp_cam; }',
};

test('targets come from upstreams and direct proxy_pass', () => {
  const t = h.deriveTargets(CONF);
  assert.deepStrictEqual(t.map(x => x.key), ['192.0.2.20:554', '192.0.2.43:8123', '192.0.2.7:8096', '192.0.2.8:8096']);
  assert.strictEqual(t.find(x => x.key === '192.0.2.43:8123').tls, true);
  assert.deepStrictEqual(t.find(x => x.key === '192.0.2.7:8096').usedBy, ['upstream jellyfin_backend']);
});

test('helper config honours per-target settings', () => {
  const t = h.deriveTargets(CONF);
  const cfg = JSON.parse(h.helperConfig(t, { defaults: h.DEFAULTS, targets: {
    '192.0.2.7:8096': { type: 'http', path: '/health', expect: '200' }, '192.0.2.8:8096': { disabled: true } } },
  { receiver: '192.0.2.42', port: 5514 }));
  assert.strictEqual(cfg.report.host, '192.0.2.42');
  assert.strictEqual(cfg.status, 'http://127.0.0.1:8099/nm_status');
  assert.ok(!cfg.targets.some(x => x.k === '192.0.2.8:8096'));
  assert.deepStrictEqual(cfg.targets.find(x => x.k === '192.0.2.7:8096'), { k: '192.0.2.7:8096', host: '192.0.2.7', port: 8096, type: 'http', tls: false, path: '/health', expect: '200', hostHeader: '' });
  assert.strictEqual(cfg.targets.find(x => x.k === '192.0.2.43:8123').type, 'tcp');
  assert.throws(() => h.validateTargetSettings({ path: 'no-slash' }), /path/);
  assert.throws(() => h.validateDefaults({ interval: 5, timeout: 5 }), /shorter/);
  assert.match(h.statusConf(), /listen 127\.0\.0\.1:8099;[\s\S]*stub_status;[\s\S]*deny all;/);
});

test('fall/rise thresholds and transitions', () => {
  const s = new h.HealthState({ getSettings: () => ({ defaults: { ...h.DEFAULTS, fall: 3, rise: 2 } }) });
  const events = [];
  s.on('transition', e => events.push(`${e.from}->${e.to}`));
  const r = ok => s.receive('a', { helper: '1.0', results: [{ k: 'b:1', ok, ms: 2, err: ok ? '' : 'refused' }], status: { active: 5, accepts: 1, handled: 1, requests: 1, reading: 0, writing: 1, waiting: 4 } });
  r(true);                                   // unknown -> up (silent)
  r(false); r(false);
  assert.strictEqual(s.view('a').targets['b:1'].status, 'up');
  r(false);                                  // third failure
  assert.strictEqual(s.view('a').targets['b:1'].status, 'down');
  r(true);
  assert.strictEqual(s.view('a').targets['b:1'].status, 'down');
  r(true);
  assert.deepStrictEqual(events, ['up->down', 'down->up']);
  assert.strictEqual(s.view('a').status.active, 5);
  assert.ok(s.view('a').targets['b:1'].uptime24h > 0.4);
});
