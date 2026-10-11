'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const dgram = require('dgram');
const ea = require('../lib/extauth');

test('RADIUS PAP hiding matches the RFC 2865 §7.1 example', () => {
  const ra = Buffer.from('0f403f9473978057bd83d5cb98f4227a', 'hex');
  assert.strictEqual(ea.hidePassword('arctangent', 'xyzzy5461', ra).toString('hex'), '0dbe708d93d413ce3196e43f782a0aee');
});

// an independent minimal RADIUS server: decodes PAP, checks Message-Authenticator, answers
function fakeRadius({ secret, users, replySecret = secret }) {
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    const ra = msg.subarray(4, 20);
    const attrs = {}; let maOff = -1;
    for (let i = 20; i < msg.length;) { const t = msg[i], l = msg[i + 1]; if (t === 80) maOff = i; attrs[t] = msg.subarray(i + 2, i + l); i += l; }
    const copy = Buffer.from(msg); copy.fill(0, maOff + 2, maOff + 18);
    const maOk = maOff > 0 && crypto.createHmac('md5', secret).update(copy).digest().equals(attrs[80]);
    const hidden = attrs[2]; let prev = ra; const plain = Buffer.alloc(hidden.length);
    for (let i = 0; i < hidden.length; i += 16) {
      const b = crypto.createHash('md5').update(secret).update(prev).digest();
      for (let j = 0; j < 16; j++) plain[i + j] = hidden[i + j] ^ b[j];
      prev = hidden.subarray(i, i + 16);
    }
    const user = attrs[1].toString(), pass = plain.toString().replace(/\0+$/, '');
    const u = users[user];
    const ok = maOk && u && u.password === pass;
    const out = [];
    if (ok && u.cls) out.push(Buffer.concat([Buffer.from([25, u.cls.length + 2]), Buffer.from(u.cls)]));
    if (!ok) { const m = Buffer.from('bad login'); out.push(Buffer.concat([Buffer.from([18, m.length + 2]), m])); }
    const body = Buffer.concat(out);
    const head = Buffer.from([ok ? 2 : 3, msg[1], 0, 0]);
    const len = 20 + body.length; head.writeUInt16BE(len, 2);
    const respAuth = crypto.createHash('md5').update(Buffer.concat([head, ra, body, Buffer.from(replySecret)])).digest();
    sock.send(Buffer.concat([head, respAuth, body]), rinfo.port, rinfo.address);
  });
  return new Promise(r => sock.bind(0, '127.0.0.1', () => r({ port: sock.address().port, close: () => sock.close() })));
}

test('RADIUS: accept with Class → role, reject, wrong secret ignored', async () => {
  const srv = await fakeRadius({ secret: 's3cret', users: { alice: { password: 'pa ss/word-é', cls: 'nginx-manager-operator' }, bob: { password: 'x', cls: 'other' } } });
  const cfg = { ...ea.DEFAULTS.radius, enabled: true, host: '127.0.0.1', port: srv.port, secret: 's3cret', timeoutSec: 1, retries: 0 };
  let r = await ea.radiusAuthenticate(cfg, 'alice', 'pa ss/word-é');
  assert.strictEqual(r.ok, true); assert.strictEqual(r.role, 'operator');
  r = await ea.radiusAuthenticate(cfg, 'alice', 'wrong');
  assert.strictEqual(r.ok, false); assert.match(r.reason, /^rejected: bad login/);
  r = await ea.radiusAuthenticate(cfg, 'bob', 'x');
  assert.strictEqual(r.ok, false); assert.match(r.reason, /no Class value maps/);
  r = await ea.radiusAuthenticate({ ...cfg, defaultRole: 'viewer' }, 'bob', 'x');
  assert.strictEqual(r.role, 'viewer');
  srv.close();
  const bad = await fakeRadius({ secret: 's3cret', replySecret: 'other', users: { alice: { password: 'p', cls: 'nginx-manager-admin' } } });
  r = await ea.radiusAuthenticate({ ...cfg, port: bad.port }, 'alice', 'p');
  assert.strictEqual(r.ok, false); assert.match(r.reason, /no reply/);
  assert.ok(r.trace.some(t => /authenticator check/.test(t)));
  bad.close();
});

test('LDAP: group mapping, nested lookup, empty password never binds', async () => {
  const calls = [];
  class FakeClient {
    constructor(o) { this.o = o; }
    async startTLS() { calls.push('starttls'); }
    async bind(dn, pw) {
      calls.push(`bind ${dn}`);
      if (dn === 'CN=svc,DC=x' && pw === 'svcpw') return;
      if (dn === 'CN=Al,OU=U,DC=x' && pw === 'alpw') return;
      throw Object.assign(new Error('80090308: LdapErr: DSID, comment: AcceptSecurityContext error, data 52e'), { code: 49 });
    }
    async search(base, opts) {
      calls.push(`search ${opts.filter}`);
      if (/sAMAccountName=al\)/.test(opts.filter)) return { searchEntries: [{ dn: 'CN=Al,OU=U,DC=x', memberOf: ['CN=Ops,DC=x'], cn: 'Al' }] };
      if (/1\.2\.840\.113556\.1\.4\.1941:=CN=Admins,DC=x/.test(opts.filter)) return { searchEntries: [{ dn: base }] };
      return { searchEntries: [] };
    }
    async unbind() {}
  }
  const a = new ea.ExternalAuth({ ldapClient: FakeClient });
  a.settings.ldap = { ...a.settings.ldap, enabled: true, url: 'ldap://dc', starttls: true, mode: 'search', bindDn: 'CN=svc,DC=x', bindPassword: 'svcpw',
    baseDn: 'DC=x', groups: { admin: 'CN=Admins,DC=x', operator: 'CN=Ops,DC=x', viewer: '' }, nested: true };
  let r = await a.authenticate('al', 'alpw');
  assert.strictEqual(r.ok, true); assert.strictEqual(r.role, 'admin'); assert.strictEqual(r.source, 'ldap');   // nested admin beats direct operator
  a.settings.ldap.nested = false;
  r = await a.authenticate('al', 'alpw');
  assert.strictEqual(r.role, 'operator');
  r = await a.authenticate('al', 'nope');
  assert.strictEqual(r.ok, false); assert.strictEqual(r.reason, 'invalid credentials');
  calls.length = 0;
  r = await a.authenticate('al', '');
  assert.strictEqual(r.ok, false); assert.strictEqual(calls.length, 0);
  r = await a.authenticate('a*)(uid=*', 'x');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(ea.escapeFilter('a*(b)\\'), 'a\\2a\\28b\\29\\5c');
});

test('settings: validation and secrets masked', () => {
  const a = new ea.ExternalAuth({});
  assert.throws(() => a.update({ ldap: { enabled: true, url: 'http://x', baseDn: 'DC=x' } }), /LDAP URL/);
  assert.throws(() => a.update({ ldap: { enabled: true, url: 'ldaps://dc', baseDn: 'DC=x', mode: 'search' } }), /service account/);
  assert.throws(() => a.update({ ldap: { enabled: true, url: 'ldaps://dc', baseDn: 'DC=x', mode: 'direct', userTemplate: '{{username}}@x' } }), /Map at least one group/);
  a.update({ ldap: { enabled: true, url: 'ldaps://dc', baseDn: 'DC=x', mode: 'search', bindDn: 'CN=svc', bindPassword: 'pw', defaultRole: 'viewer' } });
  assert.strictEqual(a.view().ldap.bindPassword, '');
  assert.strictEqual(a.view().ldap.bindPasswordSet, true);
  a.update({ ldap: { ...a.view().ldap } });
  assert.strictEqual(a.settings.ldap.bindPassword, 'pw');
  assert.throws(() => a.update({ radius: { enabled: true, host: 'r', secret: '' } }), /secret/);
});

test('service-account bind failure is reported as such, not as a bad user password', async () => {
  class C { async bind() { throw Object.assign(new Error('data 52e'), { code: 49 }); } async unbind() {} }
  const a = new ea.ExternalAuth({ ldapClient: C });
  a.settings.ldap = { ...a.settings.ldap, enabled: true, url: 'ldaps://dc', mode: 'search', bindDn: 'svc', bindPassword: 'x', baseDn: 'DC=x', defaultRole: 'viewer', tlsServerName: 'dc01.example.com' };
  const r = await a.authenticate('al', 'pw');
  assert.match(r.reason, /^service account bind failed/);
});

test('login name forms: bare, DOMAIN\\user, user@upn → one canonical user', async () => {
  assert.deepStrictEqual(ea.parseLogin('corp.example\\Jane.Doe'), { name: 'Jane.Doe', upn: null, domain: 'corp.example' });
  assert.deepStrictEqual(ea.parseLogin('MJC\\al'), { name: 'al', upn: null, domain: 'MJC' });
  assert.deepStrictEqual(ea.parseLogin('al@example.com'), { name: 'al', upn: 'al@example.com', domain: 'example.com' });
  const filters = [];
  class C {
    async bind(dn, pw) { if (dn === 'svc' && pw === 'svcpw') return; if (dn === 'CN=Al,DC=x' && pw === 'alpw') return; if (dn === 'al@example.com' && pw === 'alpw') return; throw Object.assign(new Error('data 52e'), { code: 49 }); }
    async search(base, o) { filters.push(o.filter); return /sAMAccountName=al\)|userPrincipalName=al@example\.com/i.test(o.filter) ? { searchEntries: [{ dn: 'CN=Al,DC=x', sAMAccountName: 'Al', memberOf: ['CN=Admins,DC=x'] }] } : { searchEntries: [] }; }
    async unbind() {}
  }
  const a = new ea.ExternalAuth({ ldapClient: C });
  a.settings.ldap = { ...a.settings.ldap, enabled: true, url: 'ldaps://dc', mode: 'search', bindDn: 'svc', bindPassword: 'svcpw', baseDn: 'DC=x',
    groups: { admin: 'CN=Admins,DC=x', operator: '', viewer: '' }, nested: false };
  for (const u of ['al', 'X\\al', 'x.example.com\\AL', 'al@example.com']) {
    const r = await a.authenticate(u, 'alpw');
    assert.strictEqual(r.ok, true, u); assert.strictEqual(r.username, 'al', u); assert.strictEqual(r.role, 'admin', u);
  }
  assert.ok(filters.some(f => f.includes('(userPrincipalName=al@example.com)')));
  // direct mode: a typed UPN binds as itself
  a.settings.ldap = { ...a.settings.ldap, mode: 'direct', userTemplate: 'CN={{username}},DC=nope' };
  assert.strictEqual((await a.authenticate('al@example.com', 'alpw')).ok, true);
});
