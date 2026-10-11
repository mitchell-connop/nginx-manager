'use strict';

const test = require('node:test');
const assert = require('node:assert');
const rs = require('../lib/streams');
const lr = require('../lib/logrx');

const base = { name: 'FRONT DOOR CAMERA', listen: '8554', upstreams: '192.0.2.20', allowNetworks: '10.0.0.0/24' };

const MAIN = `user nginx;
events { worker_connections 1024; }
http {
    include /etc/nginx/conf.d/*.conf;
}
`;

test('generates upstream + server and discovers them back', () => {
  const p = rs.plan('', { fields: { ...base, backups: '192.0.2.30:8554' } });
  assert.strictEqual(p.key, 'front_door_camera');
  assert.match(p.conf, /upstream rtsp_front_door_camera \{\n    server 192\.0\.2\.20:554 max_fails=2 fail_timeout=30s;\n    server 192\.0\.2\.30:8554 backup;\n\}/);
  assert.match(p.conf, /listen 8554;/);
  assert.match(p.conf, /allow 10\.0\.0\.0\/24;\n    deny all;/);
  assert.match(p.conf, /proxy_pass rtsp_front_door_camera;/);
  assert.match(p.conf, /proxy_timeout 300s;/);
  const [s] = rs.findStreams(p.conf);
  assert.strictEqual(s.label, 'FRONT DOOR CAMERA');
  assert.deepStrictEqual(s.upstreams, ['192.0.2.20:554']);
  assert.deepStrictEqual(s.backups, ['192.0.2.30:8554']);
  assert.deepStrictEqual(s.allowNetworks, ['10.0.0.0/24']);
  assert.strictEqual(s.openToAll, false);
  assert.strictEqual(s.connectTimeout, 5);
  assert.strictEqual(s.managed, true);
});

test('second stream, edit in place keeps unmanaged directives, remove', () => {
  const a = rs.plan('', { fields: base }).conf;
  const b = rs.plan(a, { fields: { ...base, name: 'Garage', listen: '8555', upstreams: 'garage.lan:8554' } }).conf;
  assert.strictEqual(rs.findStreams(b).length, 2);
  const hand = b.replace('proxy_socket_keepalive on;\n}', 'proxy_socket_keepalive on;\n    proxy_buffer_size 64k;\n}');
  const cur = rs.findStreams(hand).find(s => s.key === 'garage');
  const edited = rs.plan(hand, { key: 'garage', fields: { ...cur, name: 'Garage', idleTimeout: 600 } }).conf;
  assert.match(edited, /proxy_timeout 600s;/);
  assert.match(edited, /proxy_buffer_size 64k;/);
  assert.strictEqual(rs.findStreams(edited).length, 2);
  assert.match(edited, /FRONT DOOR CAMERA/);
  const r1 = rs.remove(edited, 'garage');
  assert.strictEqual(r1.empty, false);
  assert.strictEqual(rs.findStreams(r1.conf).length, 1);
  assert.strictEqual(rs.remove(r1.conf, 'front_door_camera').empty, true);
});

test('rejects bad input, open-by-default and port clashes', () => {
  assert.throws(() => rs.plan('', { fields: { ...base, allowNetworks: '' } }), /Client networks are required/);
  for (const f of [{ listen: '70000' }, { listen: 'abc' }, { upstreams: '' }, { upstreams: 'bad host!' }, { name: '' }, { idleTimeout: 1 }]) {
    assert.throws(() => rs.plan('', { fields: { ...base, ...f } }), undefined, JSON.stringify(f));
  }
  const a = rs.plan('', { fields: base }).conf;
  assert.throws(() => rs.plan(a, { fields: { ...base, name: 'Other' } }), /already listens on port 8554/);
  assert.throws(() => rs.plan('', { fields: { ...base, listen: '443' }, usedPorts: [80, 443] }), /already used/);
  // explicit allow-all is accepted but flagged
  const open = rs.plan('', { fields: { ...base, allowNetworks: '0.0.0.0/0' } }).conf;
  assert.strictEqual(rs.findStreams(open)[0].openToAll, true);
});

test('stream {} block is added once to nginx.conf, or the include to an existing block', () => {
  const out = rs.ensureStreamBlock(MAIN, '/etc/nginx');
  assert.match(out, /\nstream \{\n[\s\S]*include \/etc\/nginx\/stream\.d\/\*\.conf;\n\}\n$/);
  assert.match(out, /include \/etc\/nginx\/nginx-manager\/remote-stream-log\[\.\]inc;/);
  assert.ok(out.startsWith(MAIN));
  assert.strictEqual(rs.ensureStreamBlock(out, '/etc/nginx'), out);
  assert.strictEqual(rs.streamBlockState(out, '/etc/nginx').includes, true);

  const existing = MAIN + 'stream {\n    server { listen 9000; proxy_pass 10.0.0.1:9000; }\n}\n';
  const out2 = rs.ensureStreamBlock(existing, '/etc/nginx');
  assert.match(out2, /proxy_pass 10\.0\.0\.1:9000; \}\n    include \/etc\/nginx\/stream\.d\/\*\.conf;\n\}\n$/);
  assert.strictEqual((out2.match(/^stream \{/gm) || []).length, 1);
});

test('listen ports across config files', () => {
  const ports = rs.listenPorts(['server {\n    listen 80;\n    listen [::]:443 ssl;\n    listen 192.0.2.1:8080;\n    listen 192.0.2.2;\n}']);
  assert.deepStrictEqual(ports.sort((a, b) => a - b), [80, 443, 8080]);
});

test('stream sessions show up in the Connections log', () => {
  const rx = new lr.LogReceiver({ resolveAgent: () => 'a' });
  const e = rx.receive('<190>Oct 11 06:00:51 lb-01 nginx_stream: {"t":"2026-10-11T06:00:51+00:00","c":"192.0.2.10","p":"8554","proto":"TCP","s":"200","b":"52428800","bi":"2048","st":"600.123","up":"192.0.2.20:554","uc":"0.002"}', '192.0.2.1');
  assert.strictEqual(e.stream, true);
  assert.strictEqual(e.method, 'TCP');
  assert.strictEqual(e.result, 'allowed');
  assert.strictEqual(e.time, 600.123);
  const denied = rx.receive('<190>Oct 11 06:00:51 lb-01 nginx_stream: {"t":"x","c":"198.51.100.1","p":"8554","proto":"TCP","s":"403","b":"0","bi":"0","st":"0.000","up":"","uc":""}', '192.0.2.1');
  assert.strictEqual(denied.result, 'denied');
  const files = lr.remoteLogFiles('/etc/nginx', '192.0.2.42', 5514, { stream: true });
  assert.match(files['/etc/nginx/nginx-manager/remote-stream-log.inc'], /access_log syslog:server=192\.0\.2\.42:5514,tag=nginx_stream,severity=info nm_stream_json;/);
  assert.strictEqual(Object.keys(lr.remoteLogFiles('/etc/nginx', '192.0.2.42')).length, 2);
});
