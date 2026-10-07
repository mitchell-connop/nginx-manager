'use strict';

// End-to-end test of the management plane against a fake agent that speaks the same
// mpi.v1 gRPC calls, in the same order, as NGINX Agent v3.

const test   = require('node:test');
const assert = require('node:assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nm-test-'));

const grpc  = require('@grpc/grpc-js');
const store = require('../lib/store');
const { ensureTls } = require('../lib/tls');
const { ManagementPlane, mpi } = require('../lib/mpi');

const sha = buf => crypto.createHash('sha256').update(buf).digest('base64');
const INSTANCE = crypto.randomUUID();
const meta = corr => ({ messageId: crypto.randomUUID(), correlationId: corr || crypto.randomUUID() });

function client(Service, port, ca, token) {
  const md = new grpc.Metadata();
  if (token) md.set('authorization', token);
  const c = new Service(`localhost:${port}`, grpc.credentials.createSsl(Buffer.from(ca)));
  const call = (name, req) => new Promise((resolve, reject) =>
    c[name](req, md, (err, res) => (err ? reject(err) : resolve(res))));
  return { c, md, call };
}

function protoFile(name, buf, perms = '0644') {
  return { fileMeta: { name, hash: sha(buf), permissions: perms, size: String(buf.length) } };
}

test('agent lifecycle: auth, file sync, config apply, rollback', async (t) => {
  const tls = ensureTls(path.join(process.env.DATA_DIR, 'tls'));
  const mp  = new ManagementPlane({ tls, port: 0, host: '127.0.0.1' });
  const port = await mp.start();
  t.after(() => mp.stop());

  const token = store.newToken();
  const agentId = crypto.randomUUID();
  store.writeAgents([{ id: agentId, name: 'lb-test', tokenHash: store.hashToken(token) }]);

  const resource = {
    resourceId: crypto.randomUUID(),
    hostInfo: { hostId: crypto.randomUUID(), hostname: 'lb-test', releaseInfo: { name: 'debian', versionId: '12' } },
    instances: [
      { instanceMeta: { instanceId: crypto.randomUUID(), instanceType: 'INSTANCE_TYPE_AGENT', version: 'v3.0.0' } },
      { instanceMeta: { instanceId: INSTANCE, instanceType: 'INSTANCE_TYPE_NGINX', version: '1.27.0' },
        instanceRuntime: { processId: 1234, binaryPath: '/usr/sbin/nginx', configPath: '/etc/nginx/nginx.conf' } },
    ],
  };

  // ── unknown token is rejected ─────────────────────────────────────────────
  const bad = client(mpi.CommandService, port, tls.ca, 'not-a-real-token');
  await assert.rejects(bad.call('createConnection', { messageMeta: meta(), resource }),
    err => err.code === grpc.status.UNAUTHENTICATED);
  const none = client(mpi.CommandService, port, tls.ca, null);
  await assert.rejects(none.call('createConnection', { messageMeta: meta(), resource }),
    err => err.code === grpc.status.UNAUTHENTICATED);

  // ── connect + subscribe ───────────────────────────────────────────────────
  const cmd   = client(mpi.CommandService, port, tls.ca, token);
  const files = client(mpi.FileService, port, tls.ca, token);
  const conn  = await cmd.call('createConnection', { messageMeta: meta(), resource });
  assert.equal(conn.response.status, 'COMMAND_STATUS_OK');
  assert.equal(store.findAgent(agentId).nginxVersion, '1.27.0');
  assert.equal(store.readState(agentId).configPath, '/etc/nginx/nginx.conf');

  const stream = cmd.c.subscribe(cmd.md);
  const inbox = [];
  let waiter = null;
  stream.on('data', m => { inbox.push(m); if (waiter) { const w = waiter; waiter = null; w(); } });
  stream.on('error', () => {});
  const next = async (pred) => {
    for (;;) {
      const i = inbox.findIndex(pred);
      if (i !== -1) return inbox.splice(i, 1)[0];
      await new Promise(r => { waiter = r; });
    }
  };
  t.after(() => stream.cancel());
  await next(m => m.request === 'healthRequest');
  assert.ok(mp.isOnline(agentId));

  // ── initial overview: manager asks for both files, agent uploads them ─────
  const nginxConf = Buffer.from('events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n');
  const siteConf  = Buffer.from('server { listen 80; server_name a.example; }\n');
  const certPem   = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----\n');
  const certFile  = protoFile('/etc/nginx/ssl/a.pem', certPem);
  certFile.fileMeta.certificateMeta = {
    subject: { commonName: 'a.example' }, sans: { dnsNames: ['a.example'] },
    dates: { notBefore: '1700000000', notAfter: '1900000000' },
  };
  const overview = [protoFile('/etc/nginx/nginx.conf', nginxConf), protoFile('/etc/nginx/conf.d/a.conf', siteConf), certFile];
  const corr = crypto.randomUUID();
  const ov1 = await files.call('updateOverview', {
    messageMeta: meta(corr),
    overview: { files: overview, configVersion: { instanceId: INSTANCE, version: 'x' }, configPath: '/etc/nginx/nginx.conf' },
  });
  assert.deepEqual(ov1.overview.files.map(f => f.fileMeta.name).sort(),
    ['/etc/nginx/conf.d/a.conf', '/etc/nginx/nginx.conf', '/etc/nginx/ssl/a.pem']);
  await files.call('updateFile', { file: { fileMeta: certFile.fileMeta }, contents: { contents: certPem }, messageMeta: meta(corr) });

  await files.call('updateFile', { file: overview[0], contents: { contents: nginxConf }, messageMeta: meta(corr) });
  // second file via the chunked stream API
  await new Promise((resolve, reject) => {
    const up = files.c.updateFileStream(files.md, (err, res) => (err ? reject(err) : resolve(res)));
    up.write({ meta: meta(corr), header: { fileMeta: overview[1].fileMeta, chunks: 2, chunkSize: 20 } });
    up.write({ meta: meta(corr), content: { chunkId: 0, data: siteConf.subarray(0, 20) } });
    up.write({ meta: meta(corr), content: { chunkId: 1, data: siteConf.subarray(20) } });
    up.end();
  });
  const ov2 = await files.call('updateOverview', {
    messageMeta: meta(corr),
    overview: { files: ov1.overview.files, configVersion: { instanceId: INSTANCE, version: 'x' } },
  });
  assert.equal(ov2.overview.files.length, 0, 'everything synced');
  assert.equal(Object.keys(store.readState(agentId).live).length, 3, 'partial follow-up overview merged, not replaced');
  const certMeta = store.readState(agentId).live['/etc/nginx/ssl/a.pem'].certificateMeta;
  assert.equal(certMeta && certMeta.subject, 'a.example', 'cert metadata survives the follow-up overview');
  assert.equal(certMeta.notAfter, new Date(1900000000 * 1000).toISOString());

  // ── stage edits and apply ─────────────────────────────────────────────────
  const siteConf2 = Buffer.from('server { listen 80; server_name a.example b.example; }\n');
  const newConf   = Buffer.from('server { listen 8080; }\n');
  store.stageFile(agentId, '/etc/nginx/conf.d/a.conf', siteConf2);
  store.stageFile(agentId, '/etc/nginx/conf.d/new.conf', newConf);

  const applying = mp.configApply(agentId);
  const req = await next(m => m.request === 'configApplyRequest');
  const sent = Object.fromEntries(req.configApplyRequest.overview.files.map(f => [f.fileMeta.name, f.fileMeta.hash]));
  assert.deepEqual(sent, {
    '/etc/nginx/ssl/a.pem': sha(certPem),
    '/etc/nginx/nginx.conf': sha(nginxConf),
    '/etc/nginx/conf.d/a.conf': sha(siteConf2),
    '/etc/nginx/conf.d/new.conf': sha(newConf),
  });
  assert.equal(req.configApplyRequest.overview.configVersion.instanceId, INSTANCE);

  // agent downloads changed files
  const got = await files.call('getFile', { messageMeta: meta(), fileMeta: { name: '/etc/nginx/conf.d/new.conf', hash: sha(newConf) } });
  assert.equal(Buffer.from(got.contents.contents).toString(), newConf.toString());
  await assert.rejects(
    files.call('getFile', { messageMeta: meta(), fileMeta: { name: '/etc/shadow', hash: sha(newConf) } }),
    err => err.code === grpc.status.NOT_FOUND, 'cannot fetch arbitrary paths');

  const reqCorr = req.messageMeta.correlationId;
  stream.write({ messageMeta: meta(reqCorr), commandResponse: { status: 'COMMAND_STATUS_OK', message: 'Config apply successful' },
    instanceId: INSTANCE, requestType: 'CONFIG_APPLY_REQUEST' });
  const ok = await applying;
  assert.equal(ok.success, true);
  let st = store.readState(agentId);
  assert.deepEqual(st.draft, {});
  assert.equal(st.live['/etc/nginx/conf.d/new.conf'].hash, sha(newConf));

  // ── failing apply keeps the draft (agent rolled back) ─────────────────────
  store.stageFile(agentId, '/etc/nginx/conf.d/new.conf', Buffer.from('this is not valid nginx\n'));
  store.stageDelete(agentId, '/etc/nginx/conf.d/a.conf');
  const failing = mp.configApply(agentId);
  const req2 = await next(m => m.request === 'configApplyRequest');
  assert.ok(!req2.configApplyRequest.overview.files.some(f => f.fileMeta.name === '/etc/nginx/conf.d/a.conf'),
    'deleted file left out of the overview');
  const c2 = req2.messageMeta.correlationId;
  stream.write({ messageMeta: meta(c2), commandResponse: { status: 'COMMAND_STATUS_ERROR', message: 'Config apply failed, rolling back config', error: 'nginx -t failed' } });
  stream.write({ messageMeta: meta(c2), commandResponse: { status: 'COMMAND_STATUS_FAILURE', message: 'Config apply failed, rollback successful', error: 'nginx -t failed' } });
  const fail = await failing;
  assert.equal(fail.success, false);
  st = store.readState(agentId);
  assert.equal(Object.keys(st.draft).length, 2, 'draft kept for fixing');
  assert.ok(st.live['/etc/nginx/conf.d/a.conf'], 'live state unchanged');

  // ── a new full overview (e.g. agent restart) replaces the live set ────────
  await files.call('updateOverview', {
    messageMeta: meta(),
    overview: { files: [overview[0]], configVersion: { instanceId: INSTANCE, version: 'y' } },
  });
  assert.deepEqual(Object.keys(store.readState(agentId).live), ['/etc/nginx/nginx.conf']);
});
