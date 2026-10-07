'use strict';

// Managed-certificate pipeline against a real certbot + Pebble (Let's Encrypt's test CA)
// with pebble-challtestsrv as DNS, deploying to a fake agent.
// Runs only when NM_TEST_PEBBLE=1 — see README "Development".
//   CERTBOT_BIN=…/certbot  REQUESTS_CA_BUNDLE=…/pebble.minica.pem  NM_TEST_HOOKS=<dir with auth-hook.sh/cleanup-hook.sh>

const test   = require('node:test');
const assert = require('node:assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const enabled = process.env.NM_TEST_PEBBLE === '1';
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nm-certs-'));

test('issue with certbot, deploy via agent, pin the key, renew', { skip: !enabled && 'set NM_TEST_PEBBLE=1' }, async (t) => {
  const grpc  = require('@grpc/grpc-js');
  const store = require('../lib/store');
  const { ensureTls } = require('../lib/tls');
  const { ManagementPlane, mpi } = require('../lib/mpi');
  const { CertManager, inspect } = require('../lib/certmanager');
  const { ISSUERS } = require('../lib/issuers');

  const sha = buf => crypto.createHash('sha256').update(buf).digest('base64');
  const meta = corr => ({ messageId: crypto.randomUUID(), correlationId: corr || crypto.randomUUID() });
  const INSTANCE = crypto.randomUUID();

  const tls = ensureTls(path.join(process.env.DATA_DIR, 'tls'));
  const mp = new ManagementPlane({ tls, port: 0, host: '127.0.0.1' });
  const port = await mp.start();
  t.after(() => mp.stop());

  const token = store.newToken();
  const agentId = crypto.randomUUID();
  store.writeAgents([{ id: agentId, name: 'lb-test', group: 'Test', tokenHash: store.hashToken(token) }]);

  const md = new grpc.Metadata(); md.set('authorization', token);
  const creds = grpc.credentials.createSsl(Buffer.from(tls.ca));
  const cmd = new mpi.CommandService(`localhost:${port}`, creds);
  const files = new mpi.FileService(`localhost:${port}`, creds);
  const call = (c, name, req) => new Promise((res, rej) => c[name](req, md, (e, r) => (e ? rej(e) : res(r))));

  await call(cmd, 'createConnection', { messageMeta: meta(), resource: {
    resourceId: crypto.randomUUID(), hostInfo: { hostId: crypto.randomUUID(), hostname: 'lb-test' },
    instances: [{ instanceMeta: { instanceId: INSTANCE, instanceType: 'INSTANCE_TYPE_NGINX', version: '1.27.0' },
      instanceRuntime: { configPath: '/etc/nginx/nginx.conf' } }],
  } });
  const nginxConf = Buffer.from('events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n');
  await call(files, 'updateOverview', { messageMeta: meta(), overview: {
    files: [{ fileMeta: { name: '/etc/nginx/nginx.conf', hash: sha(nginxConf), permissions: '0644', size: String(nginxConf.length) } }],
    configVersion: { instanceId: INSTANCE, version: 'x' } } });
  await call(files, 'updateFile', { file: { fileMeta: { name: '/etc/nginx/nginx.conf', hash: sha(nginxConf), permissions: '0644' } }, contents: { contents: nginxConf }, messageMeta: meta() });

  // fake agent: answer every config apply with OK after downloading the changed files
  const stream = cmd.subscribe(md);
  const applied = [];
  stream.on('data', async m => {
    if (m.request !== 'configApplyRequest') return;
    const ov = m.configApplyRequest.overview;
    const got = {};
    for (const f of ov.files) {
      if (f.fileMeta.name.startsWith('/etc/nginx/ssl/')) {
        const r = await call(files, 'getFile', { messageMeta: meta(), fileMeta: f.fileMeta });
        got[f.fileMeta.name] = Buffer.from(r.contents.contents);
      }
    }
    applied.push({ names: ov.files.map(f => f.fileMeta.name).sort(), got });
    stream.write({ messageMeta: meta(m.messageMeta.correlationId), commandResponse: { status: 'COMMAND_STATUS_OK', message: 'Config apply successful' } });
  });
  stream.on('error', () => {});
  t.after(() => stream.cancel());
  await new Promise(r => setTimeout(r, 200));

  // test DNS provider: certbot --manual with hooks that publish TXT records in challtestsrv
  const hooks = process.env.NM_TEST_HOOKS;
  const providers = {
    pebble: {
      label: 'test', fields: [], credentialsFile: null, env: () => ({}),
      args: () => ['--manual', '--preferred-challenges', 'dns',
        '--manual-auth-hook', path.join(hooks, 'auth-hook.sh'), '--manual-cleanup-hook', path.join(hooks, 'cleanup-hook.sh')],
    },
  };
  ISSUERS['custom-acme'].directory = 'https://localhost:14000/dir';
  const cm = new CertManager({ mp, providers });
  const logs = [];
  cm.on('log', (id, line) => logs.push(line));

  const cert = cm.create({
    name: 'example.test', source: 'custom-acme', domains: ['*.example.test', 'example.test'],
    issuer: { directory: 'https://localhost:14000/dir', email: 'ops@example.test' },
    challenge: { provider: 'pebble', propagationSeconds: 5 }, targets: [agentId],
  }, {});
  assert.equal(cert.certPath, '/etc/nginx/ssl/example.test/fullchain.pem');
  assert.equal(cert.keyPath, '/etc/nginx/ssl/example.test/privkey.pem');

  // 1. issue + deploy
  const after = await cm.process(cert.id);
  assert.equal(after.status.state, 'ok', logs.join('\n'));
  assert.deepEqual(after.status.sans.sort(), ['*.example.test', 'example.test']);
  assert.equal(after.status.keyMatches, true);
  assert.equal(after.status.deployments[agentId].state, 'ok');
  assert.equal(applied.length, 1);
  const pushed = applied[0].got;
  const info = inspect({ fullchain: pushed[cert.certPath], privkey: pushed[cert.keyPath] });
  assert.equal(info.keyMatches, true, 'the agent received a matching cert + key');

  let st = store.readState(agentId);
  assert.ok(st.pinned[cert.keyPath] && st.pinned[cert.certPath], 'deployed files are pinned');
  assert.equal(st.pinned[cert.keyPath].permissions, '0600');

  // 2. an unrelated config apply still carries the pinned key (agent would delete it otherwise)
  store.stageFile(agentId, '/etc/nginx/conf.d/site.conf', 'server { listen 80; }\n');
  const r = await mp.configApply(agentId);
  assert.equal(r.success, true);
  assert.ok(applied[1].names.includes(cert.keyPath), 'key included in later applies');
  assert.ok(applied[1].names.includes('/etc/nginx/conf.d/site.conf'));

  // 3. a deployment never pushes unrelated pending edits
  store.stageFile(agentId, '/etc/nginx/conf.d/half-done.conf', 'server { # wip\n');

  // 4. not due: no certbot run, no apply
  const runs = logs.filter(l => l.includes('$ certbot')).length;
  await cm.process(cert.id);
  assert.equal(logs.filter(l => l.includes('$ certbot')).length, runs, 'certbot not run when not due');
  assert.equal(applied.length, 2, 'nothing re-deployed when up to date');

  // 5. forced renewal: new serial, redeployed, draft untouched
  const serial = after.status.serial;
  const renewed = await cm.process(cert.id, { force: true });
  assert.notEqual(renewed.status.serial, serial);
  assert.equal(applied.length, 3);
  assert.ok(!applied[2].names.includes('/etc/nginx/conf.d/half-done.conf'), 'pending draft not pushed by deployment');
  st = store.readState(agentId);
  assert.ok(st.draft['/etc/nginx/conf.d/half-done.conf'], 'pending draft still pending');
  assert.equal(st.pinned[cert.certPath].hash, sha(fs.readFileSync(path.join(process.env.DATA_DIR, 'certbot/config/live', cert.id, 'fullchain.pem'))));

  // 6. secrets never appear in the public view — only whether they are set
  cm.saveSecrets(cert.id, { eabHmac: 'hmac-SECRET-123456', dns: { apiToken: 'token-SECRET-123456' } });
  const view = JSON.stringify(cm.view(cm.get(cert.id)));
  assert.ok(!view.includes('SECRET-123456'), 'no secret values in the view');
  assert.match(view, /"eabHmac":true/);
  const mode = fs.statSync(path.join(process.env.DATA_DIR, 'cert-secrets.json')).mode & 0o777;
  assert.equal(mode, 0o600, 'secrets file is 600');
});
