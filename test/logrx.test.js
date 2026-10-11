'use strict';

const test = require('node:test');
const assert = require('node:assert');
const dgram = require('dgram');
const fs = require('fs');
const os = require('os');
const path = require('path');
const lr = require('../lib/logrx');

const access = obj => `<190>Oct 11 06:00:51 lb-01 nginx: ${JSON.stringify(obj)}`;
const base = { t: '2026-10-11T06:00:51+00:00', c: '192.0.2.10', u: '', h: 'app.example.com', p: '443', m: 'GET', r: '/', v: 'HTTP/2.0',
  s: '200', b: '512', rt: '0.012', up: '10.0.0.5:8080', us: '200', ut: '0.011', tls: 'TLSv1.3', ua: 'curl/8' };

test('parses nginx syslog JSON lines and classifies the result', () => {
  const rx = new lr.LogReceiver({ resolveAgent: a => (a === '192.0.2.1' ? 'agent-1' : null) });
  const e = rx.receive(access(base), '192.0.2.1');
  assert.strictEqual(e.status, 200);
  assert.strictEqual(e.result, 'allowed');
  assert.strictEqual(e.host, 'app.example.com');
  assert.strictEqual(e.time, 0.012);
  assert.strictEqual(rx.receive(access({ ...base, s: '403' }), '192.0.2.1').result, 'denied');
  assert.strictEqual(rx.receive(access({ ...base, m: 'CONNECT', s: '407', up: '-' }), '192.0.2.1').result, 'denied');
  assert.strictEqual(rx.receive(access({ ...base, s: '404' }), '192.0.2.1').result, 'client_error');
  assert.strictEqual(rx.receive(access({ ...base, s: '504' }), '192.0.2.1').result, 'server_error');
  assert.strictEqual(rx.receive(access({ ...base, s: '101' }), '::ffff:192.0.2.1').result, 'allowed');
  assert.strictEqual(rx.entries('agent-1', 'access').length, 6);
  assert.strictEqual(rx.entries('agent-1', 'access')[2].upstream, '');
});

test('drops packets from unknown sources and junk', () => {
  const rx = new lr.LogReceiver({ resolveAgent: () => null });
  assert.strictEqual(rx.receive(access(base), '198.51.100.7'), null);
  const rx2 = new lr.LogReceiver({ resolveAgent: () => 'a' });
  assert.strictEqual(rx2.receive('hello', '192.0.2.1'), null);
  assert.strictEqual(rx2.receive('<190>Oct 11 06:00:51 lb-01 nginx: {not json', '192.0.2.1'), null);
});

test('keepalived lines keep their journal timestamp, get a level, and replays are deduplicated', () => {
  const rx = new lr.LogReceiver({ resolveAgent: () => 'a' });
  const line = '<13>Oct 11 06:01:00 lb-01 keepalived: 2026-10-09T00:49:44+0000 lb-01 Keepalived_vrrp[180]: (VI_1) Entering MASTER STATE';
  const e = rx.receive(line, '192.0.2.1');
  assert.strictEqual(e.at, '2026-10-09T00:49:44.000Z');
  assert.strictEqual(e.process, 'Keepalived_vrrp');
  assert.strictEqual(e.level, 'master');
  assert.strictEqual(rx.receive(line, '192.0.2.1'), null);
  const w = rx.receive('<13>Oct 11 06:01:00 lb-01 keepalived: 2026-10-09T00:49:41+0000 lb-01 Keepalived_vrrp[180]: Disabling track script check_nginx since not found/accessible', '192.0.2.1');
  assert.strictEqual(w.level, 'warn');
  assert.strictEqual(rx.entries('a', 'keepalived').length, 2);
});

test('keepalived_state reports go to the VIP monitor, not the keepalived log', () => {
  const rx = new lr.LogReceiver({ resolveAgent: () => 'a' });
  const got = [];
  rx.on('vrrp', (id, j) => got.push([id, j]));
  assert.strictEqual(rx.receive('<13>Oct 11 06:01:00 lb-01 keepalived_state: {"v":1,"keepalived":"active","addrs":["127.0.0.1","192.0.2.50"]}', '192.0.2.1'), null);
  assert.deepStrictEqual(got, [['a', { v: 1, keepalived: 'active', addrs: ['127.0.0.1', '192.0.2.50'] }]]);
  assert.strictEqual(rx.entries('a', 'keepalived').length, 0);
});

test('ring buffer is bounded', () => {
  const rx = new lr.LogReceiver({ resolveAgent: () => 'a', limits: { access: 3 } });
  for (let i = 0; i < 5; i++) rx.receive(access({ ...base, r: `/${i}` }), '192.0.2.1');
  assert.deepStrictEqual(rx.entries('a', 'access').map(e => e.uri), ['/2', '/3', '/4']);
});

test('keepalived history persists across restarts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nm-logrx-'));
  const id = '0f8fad5b-d9cb-469f-a165-70867728950e';
  const rx = new lr.LogReceiver({ resolveAgent: () => id, persistDir: dir });
  rx.receive('<13>Oct 11 06:01:00 lb-01 keepalived: 2026-10-09T00:49:44+0000 lb-01 Keepalived_vrrp[180]: (VI_1) Entering MASTER STATE', '192.0.2.1');
  rx.flush();
  const rx2 = new lr.LogReceiver({ resolveAgent: () => id, persistDir: dir });
  rx2.load();
  assert.strictEqual(rx2.entries(id, 'keepalived').length, 1);
  assert.strictEqual(rx2.receive('<13>Oct 11 06:01:00 lb-01 keepalived: 2026-10-09T00:49:44+0000 lb-01 Keepalived_vrrp[180]: (VI_1) Entering MASTER STATE', '192.0.2.1'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('receives over UDP and batches entries', async () => {
  const rx = new lr.LogReceiver({ port: 0, host: '127.0.0.1', resolveAgent: a => (a === '127.0.0.1' ? 'a' : null) });
  const port = await rx.start();
  const got = new Promise(resolve => rx.once('entries', resolve));
  const c = dgram.createSocket('udp4');
  c.send(access(base), port, '127.0.0.1');
  const batch = await got;
  c.close(); rx.stop();
  assert.strictEqual(batch.agentId, 'a');
  assert.strictEqual(batch.kind, 'access');
  assert.strictEqual(batch.entries[0].client, '192.0.2.10');
});

test('generated nginx files', () => {
  const files = lr.remoteLogFiles('/etc/nginx', '192.0.2.42', 5514);
  const conf = files['/etc/nginx/conf.d/00-nginx-manager-logging.conf'];
  const inc = files['/etc/nginx/nginx-manager/remote-log.inc'];
  assert.match(conf, /log_format nm_json escape=json/);
  assert.match(conf, /include \/etc\/nginx\/nginx-manager\/remote-log\.inc;/);
  assert.doesNotMatch(conf, /\$request\b|\$args|\$request_uri/);     // no query strings
  assert.match(inc, /access_log syslog:server=192\.0\.2\.42:5514,tag=nginx,severity=info nm_json;/);
  assert.match(lr.remoteLogFiles('/etc/nginx', '2001:db8::1')['/etc/nginx/nginx-manager/remote-log.inc'], /server=\[2001:db8::1\]:5514/);
  const ka = lr.keepalivedForwarderScript('192.0.2.42');
  assert.match(ka, /nm-keepalived\.sh 192\.0\.2\.42 5514$/m);
  assert.match(ka, /journalctl -u keepalived -f .*\| send -t keepalived$/m);
  assert.match(ka, /send -t keepalived_state /);
});
