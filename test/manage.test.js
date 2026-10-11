'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Users, atLeast } = require('../lib/users');
const { AuditLog } = require('../lib/audit');
const { History } = require('../lib/history');
const gs = require('../lib/groupsync');
const { Alerts, webhookBody } = require('../lib/alerts');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nm-manage-'));

test('users: built-in admin, roles, password rules', async () => {
  const dir = tmp();
  const u = new Users({ file: path.join(dir, 'users.json'), adminPassword: 'plain-admin-pass' });
  assert.deepStrictEqual(await u.verify('admin', 'plain-admin-pass'), { username: 'admin', role: 'admin', builtin: true });
  assert.strictEqual(await u.verify('admin', 'nope'), null);
  u.create({ username: 'Alice', password: 'correct-horse-1', role: 'operator' });
  assert.strictEqual((await u.verify('alice', 'correct-horse-1')).role, 'operator');
  assert.strictEqual(await u.verify('alice', 'wrong-password'), null);
  assert.strictEqual(await u.verify('ghost', 'whatever-123'), null);
  assert.throws(() => u.create({ username: 'alice', password: 'correct-horse-1', role: 'viewer' }), /exists/);
  assert.throws(() => u.create({ username: 'bob', password: 'short', role: 'viewer' }), /10-256/);
  assert.throws(() => u.create({ username: 'bob', password: 'long-enough-pw', role: 'root' }), /Role/);
  assert.throws(() => u.remove('admin'), /built-in/);
  u.update('alice', { role: 'viewer' });
  assert.strictEqual(u.lookup('alice').role, 'viewer');
  assert.ok(!JSON.stringify(u.list()).includes('passwordHash'));
  u.remove('alice');
  assert.strictEqual(u.lookup('alice'), null);
  assert.ok(atLeast('admin', 'operator') && atLeast('operator', 'operator') && !atLeast('viewer', 'operator'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('audit log: append, filter, newest first', () => {
  const dir = tmp();
  const a = new AuditLog({ file: path.join(dir, 'audit.log') });
  a.record({ user: 'alice', action: 'login', result: 'ok' });
  a.record({ user: 'bob', action: 'config.apply', agent: 'lb-01', result: 'ok' });
  a.record({ user: 'alice', action: 'config.apply', agent: 'lb-02', result: 'failed' });
  assert.strictEqual(a.query()[0].agent, 'lb-02');
  assert.strictEqual(a.query({ user: 'alice' }).length, 2);
  assert.strictEqual(a.query({ action: 'config.apply', agent: 'lb-01' }).length, 1);
  assert.strictEqual(a.query({ q: 'FAILED' }).length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('history: snapshots only on change, apply attribution, changes list', () => {
  const dir = tmp();
  const h = new History({ dir });
  const id = '0f8fad5b-d9cb-469f-a165-70867728950e';
  const f1 = { '/etc/nginx/nginx.conf': { hash: 'a', permissions: '0644' }, '/etc/nginx/x.key': { hash: 'k', permissions: '0600', pin: true } };
  assert.strictEqual(h.record(id, f1).cause, 'server');
  assert.strictEqual(h.record(id, f1), null);                                      // unchanged
  const f2 = { ...f1, '/etc/nginx/conf.d/a.conf': { hash: 'b', permissions: '0644' }, '/etc/nginx/unk': { unmanaged: true } };
  const s2 = h.record(id, f2, { cause: 'server' });
  assert.deepStrictEqual(s2.changes, [{ name: '/etc/nginx/conf.d/a.conf', change: 'added' }]);
  assert.strictEqual(h.record(id, f2, { cause: 'apply', user: 'alice', label: 'Apply' }).user, 'alice');   // re-attributed
  const f3 = { '/etc/nginx/nginx.conf': { hash: 'c', permissions: '0644' } };
  const s3 = h.record(id, f3, { cause: 'apply', user: 'bob' });
  assert.deepStrictEqual(s3.changes.map(c => `${c.change} ${c.name}`), ['deleted /etc/nginx/conf.d/a.conf', 'modified /etc/nginx/nginx.conf', 'deleted /etc/nginx/x.key']);
  assert.strictEqual(h.summaries(id)[0].id, s3.id);
  assert.strictEqual(h.previous(id, s3.id).id, s2.id);
  assert.ok(!('files' in h.summaries(id)[0]));
  const h2 = new History({ dir });
  assert.strictEqual(h2.list(id).length, 3);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('group sync: drift, sync plan, propagate with conflicts', () => {
  const a = { id: 'a', name: 'lb-01', files: { '/n.conf': { hash: '1' }, '/s.conf': { hash: 'x' }, '/only-a': { hash: 'q' }, '/u': { unmanaged: true } } };
  const b = { id: 'b', name: 'lb-02', files: { '/n.conf': { hash: '1' }, '/s.conf': { hash: 'y' }, '/only-b': { hash: 'r' }, '/u': { hash: 'z' } } };
  const d = gs.compare([a, b]);
  assert.deepStrictEqual(d.drift.map(f => f.name), ['/only-a', '/only-b', '/s.conf']);
  assert.strictEqual(gs.compare([a, b], { ignore: ['/only-*', '/s.conf'] }).inSync, true);
  const [plan] = gs.planSync(a, [b]);
  assert.deepStrictEqual(plan.stage.map(f => f.name).sort(), ['/only-a', '/s.conf']);
  assert.deepStrictEqual(plan.remove.sort(), ['/only-b']);          // /u: source contents unknown — left alone
  assert.deepStrictEqual(gs.planSync(a, [b], { files: ['/s.conf'] })[0], { agentId: 'b', stage: [{ name: '/s.conf', hash: 'x', permissions: '0644', pin: false }], remove: [] });
  const prop = gs.planPropagate({ current: a.files, draft: { '/n.conf': { hash: '2' }, '/s.conf': { hash: 'x2' }, '/new': { hash: 'n' } } }, [b]);
  assert.deepStrictEqual(prop.conflicts, [{ agentId: 'b', name: '/s.conf' }]);
  const forced = gs.planPropagate({ current: a.files, draft: { '/s.conf': { hash: 'x2' }, '/only-a': { name: '/only-a', deleted: true } } }, [b], { force: true });
  assert.deepStrictEqual(forced.plans[0].stage.map(f => f.name), ['/s.conf']);
  assert.deepStrictEqual(forced.plans[0].remove, []);                               // b doesn't have /only-a
  assert.ok(gs.globToRe('/etc/nginx/**/local-*.conf').test('/etc/nginx/conf.d/x/local-a.conf'));
});

test('alerts: channels, cool-down, recovery, secrets masked', async () => {
  const dir = tmp();
  const mails = [];
  const al = new Alerts({ file: path.join(dir, 'alerts.json'), historyFile: path.join(dir, 'h.json'), stateFile: path.join(dir, 's.json'),
    mailer: async m => { mails.push(m); } });
  al.update({ email: { enabled: true, host: 'smtp.example.com', port: 587, user: 'u', pass: 'secret-pass', from: 'nm@example.com', to: 'ops@example.com' } });
  assert.strictEqual(al.view().email.pass, '');
  assert.strictEqual(al.view().email.passSet, true);
  al.update({ email: { ...al.view().email, pass: '' } });                         // blank keeps the password
  assert.strictEqual(al.settings.email.pass, 'secret-pass');
  assert.throws(() => al.update({ email: { enabled: true, host: 'smtp.example.com', from: 'x', to: 'ops@example.com' } }), /From/);
  const r = await al.notify({ event: 'backend_down', key: 'k1', title: 'Backend down', message: 'm' });
  assert.strictEqual(r.results[0].ok, true);
  assert.match(mails[0].subject, /Backend down/);
  assert.strictEqual((await al.notify({ event: 'backend_down', key: 'k1', title: 'Backend down' })).skipped, 'cooldown');
  await al.notify({ event: 'backend_down', key: 'k1', title: 'Recovered', recovery: true });
  assert.match(mails[1].subject, /^\[nginx-manager\] RESOLVED: Recovered/);
  assert.strictEqual((await al.notify({ event: 'backend_down', key: 'k2', title: 'x', recovery: true })).skipped, 'no prior alert');
  al.update({ events: { backend_down: false } });
  assert.strictEqual((await al.notify({ event: 'backend_down', key: 'k3', title: 'x' })).skipped, 'disabled');
  // cool-down state survives a restart
  await al.notify({ event: 'drift', key: 'd1', title: 'Drift' });
  const al2 = new Alerts({ file: path.join(dir, 'alerts.json'), historyFile: path.join(dir, 'h.json'), stateFile: path.join(dir, 's.json'), mailer: async () => {} });
  assert.strictEqual((await al2.notify({ event: 'drift', key: 'd1', title: 'Drift' })).skipped, 'cooldown');
  assert.strictEqual(al2.history().length, 3);
  // webhook headers are masked and kept when sent back masked
  al.update({ webhooks: [{ name: 'hook', url: 'https://hooks.example.com/x', format: 'slack', headers: { Authorization: 'Bearer abc' } }] });
  const v = al.view();
  assert.strictEqual(v.webhooks[0].headers.Authorization, '••••');
  al.update({ webhooks: v.webhooks });
  assert.strictEqual(al.settings.webhooks[0].headers.Authorization, 'Bearer abc');
  assert.throws(() => al.update({ webhooks: [{ url: 'ftp://x' }] }), /http/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('alerts: webhook formats', () => {
  const a = { event: 'drift', severity: 'warning', title: 'Drift in DMZ', message: '2 files', at: 'now' };
  assert.match(JSON.parse(webhookBody('slack', a).body).text, /\*🟠 Drift in DMZ\*/);
  assert.match(JSON.parse(webhookBody('discord', a).body).content, /Drift in DMZ/);
  const n = webhookBody('ntfy', a);
  assert.strictEqual(n.headers.Priority, '4');
  assert.strictEqual(n.body, '2 files');
  assert.strictEqual(JSON.parse(webhookBody('json', a).body).source, 'nginx-manager');
});
