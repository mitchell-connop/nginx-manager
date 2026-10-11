/**
 * nginx-manager — lib/extauth.js
 *
 * Sign-in against an external directory: LDAP / Active Directory, or RADIUS.
 * The role (viewer/operator/admin) comes from the directory on every sign-in:
 *
 *   LDAP    group membership (memberOf, optionally nested via AD's LDAP_MATCHING_RULE_IN_CHAIN)
 *   RADIUS  a reply attribute (Class or Filter-Id) whose value names the role
 *
 * Unmatched users get defaultRole, or are refused when it is empty. Settings live in
 * data/auth.json (0600); the bind password and RADIUS secret are never returned to the browser.
 *
 * RADIUS is implemented here (RFC 2865 Access-Request with PAP, plus the RFC 3579
 * Message-Authenticator that servers require since the 2024 "Blast-RADIUS" fixes) —
 * the npm radius packages are unmaintained.
 */

'use strict';

const fs = require('fs');
const crypto = require('crypto');
const dgram = require('dgram');

const ROLE_ORDER = ['admin', 'operator', 'viewer'];
const USERNAME = /^[A-Za-z0-9._@\\-]{1,128}$/;

const DEFAULTS = {
  order: ['ldap', 'radius'],
  ldap: {
    enabled: false, url: '', starttls: false, verifyTls: true, caPem: '',
    mode: 'search',                        // search: service bind → find user → bind as user;  direct: bind with userTemplate
    bindDn: '', bindPassword: '', baseDn: '',
    userFilter: '(sAMAccountName={{username}})', userTemplate: '{{username}}@example.com',
    nested: true,                          // AD nested groups (1.2.840.113556.1.4.1941)
    groups: { admin: '', operator: '', viewer: '' }, defaultRole: '',
  },
  radius: {
    enabled: false, host: '', port: 1812, secret: '', timeoutSec: 5, retries: 2, nasIdentifier: 'nginx-manager',
    roleAttribute: 'Class', roles: { admin: 'nginx-manager-admin', operator: 'nginx-manager-operator', viewer: 'nginx-manager-viewer' }, defaultRole: '',
  },
};

const clone = o => JSON.parse(JSON.stringify(o));
const err = (m, status = 400) => Object.assign(new Error(m), { status });

// RFC 4515 filter value escaping / RFC 4514 isn't needed: DNs come from the server
function escapeFilter(v) {
  return String(v).replace(/[\\*()\0]/g, c => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

function pickRole(matches, defaultRole) {
  for (const r of ROLE_ORDER) if (matches.includes(r)) return r;
  return defaultRole || null;
}

// ---------------------------------------------------------------------------
// LDAP / AD
// ---------------------------------------------------------------------------
async function ldapAuthenticate(cfg, username, password, { Client = require('ldapts').Client } = {}) {
  const trace = [];
  const tlsOptions = { rejectUnauthorized: cfg.verifyTls !== false, ...(cfg.caPem ? { ca: [cfg.caPem] } : {}) };
  const client = new Client({ url: cfg.url, timeout: 8000, connectTimeout: 8000, tlsOptions: cfg.url.startsWith('ldaps:') ? tlsOptions : undefined });
  const lcase = s => String(s).toLowerCase();
  try {
    if (cfg.starttls && cfg.url.startsWith('ldap:')) { await client.startTLS(tlsOptions); trace.push('StartTLS ok'); }
    const filter = cfg.userFilter.replace(/\{\{username\}\}/g, escapeFilter(username));
    let entry;
    const attrs = ['memberOf', 'cn', 'displayName', 'mail', 'userPrincipalName', 'sAMAccountName', 'uid'];
    if (cfg.mode === 'direct') {
      const who = cfg.userTemplate.replace(/\{\{username\}\}/g, username);
      await client.bind(who, password);
      trace.push(`bound as ${who}`);
      const r = await client.search(cfg.baseDn, { scope: 'sub', filter, attributes: attrs, sizeLimit: 2 });
      if (r.searchEntries.length !== 1) throw err(`user search returned ${r.searchEntries.length} entries`, 401);
      entry = r.searchEntries[0];
    } else {
      await client.bind(cfg.bindDn, cfg.bindPassword);
      trace.push('service bind ok');
      const r = await client.search(cfg.baseDn, { scope: 'sub', filter, attributes: attrs, sizeLimit: 2 });
      if (r.searchEntries.length !== 1) throw err(r.searchEntries.length ? 'username matches more than one entry' : 'user not found', 401);
      entry = r.searchEntries[0];
      trace.push(`found ${entry.dn}`);
      await client.bind(entry.dn, password);            // the actual password check
      trace.push('user bind ok');
      await client.bind(cfg.bindDn, cfg.bindPassword);  // back to the service account for group lookups
    }
    const memberOf = [].concat(entry.memberOf || []).map(String);
    const matches = [];
    for (const role of ROLE_ORDER) {
      const g = (cfg.groups[role] || '').trim();
      if (!g) continue;
      let ok = memberOf.some(m => lcase(m) === lcase(g));
      if (!ok && cfg.nested) {
        // AD: is the user a (transitive) member of g?
        const r = await client.search(entry.dn, { scope: 'base', filter: `(memberOf:1.2.840.113556.1.4.1941:=${escapeFilter(g)})`, attributes: ['dn'] }).catch(() => ({ searchEntries: [] }));
        ok = r.searchEntries.length > 0;
      }
      if (ok) matches.push(role);
    }
    const role = pickRole(matches, cfg.defaultRole);
    trace.push(`groups: ${memberOf.length} direct; matched ${matches.join(', ') || 'none'}`);
    return { ok: !!role, role, dn: entry.dn, displayName: String(entry.displayName || entry.cn || username), groups: memberOf, trace,
      reason: role ? null : 'not in any group mapped to a role' };
  } catch (e) {
    const code = e.code || e.name || '';
    const invalid = /InvalidCredentials|49/.test(String(code)) || /invalid credentials|data 52e/i.test(e.message);
    trace.push(`error: ${e.message}`);
    return { ok: false, role: null, reason: invalid ? 'invalid credentials' : e.message, trace };
  } finally {
    await client.unbind().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// RADIUS (PAP)
// ---------------------------------------------------------------------------
const ATTR = { 'User-Name': 1, 'User-Password': 2, 'Filter-Id': 11, 'Reply-Message': 18, Class: 25, 'NAS-Identifier': 32, 'Message-Authenticator': 80 };

function attr(type, value) {
  const v = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  if (v.length > 253) throw err('RADIUS attribute too long');
  return Buffer.concat([Buffer.from([type, v.length + 2]), v]);
}

function hidePassword(password, secret, authenticator) {
  const pw = Buffer.from(password, 'utf8');
  if (pw.length > 128) throw err('password too long for RADIUS');
  const padded = Buffer.alloc(Math.max(16, Math.ceil(pw.length / 16) * 16));
  pw.copy(padded);
  const out = Buffer.alloc(padded.length);
  let prev = authenticator;
  for (let i = 0; i < padded.length; i += 16) {
    const b = crypto.createHash('md5').update(Buffer.from(secret, 'utf8')).update(prev).digest();
    for (let j = 0; j < 16; j++) out[i + j] = padded[i + j] ^ b[j];
    prev = out.subarray(i, i + 16);
  }
  return out;
}

function parseAttrs(buf) {
  const out = [];
  for (let i = 20; i + 2 <= buf.length;) {
    const t = buf[i], l = buf[i + 1];
    if (l < 2 || i + l > buf.length) break;
    out.push({ type: t, value: buf.subarray(i + 2, i + l), offset: i });
    i += l;
  }
  return out;
}

function buildAccessRequest({ username, password, secret, nasIdentifier, id = crypto.randomInt(256), authenticator = crypto.randomBytes(16) }) {
  const body = Buffer.concat([
    attr(ATTR['User-Name'], username),
    attr(ATTR['User-Password'], hidePassword(password, secret, authenticator)),
    attr(ATTR['NAS-Identifier'], nasIdentifier || 'nginx-manager'),
    attr(ATTR['Message-Authenticator'], Buffer.alloc(16)),
  ]);
  const pkt = Buffer.concat([Buffer.from([1, id, 0, 0]), authenticator, body]);
  pkt.writeUInt16BE(pkt.length, 2);
  const ma = crypto.createHmac('md5', secret).update(pkt).digest();
  ma.copy(pkt, pkt.length - 16);
  return { pkt, id, authenticator };
}

// verify Response Authenticator (and Message-Authenticator if present)
function verifyResponse(res, reqAuthenticator, secret) {
  if (res.length < 20 || res.readUInt16BE(2) > res.length) return false;
  const len = res.readUInt16BE(2);
  const r = res.subarray(0, len);
  const expect = crypto.createHash('md5').update(Buffer.concat([r.subarray(0, 4), reqAuthenticator, r.subarray(20), Buffer.from(secret, 'utf8')])).digest();
  if (!crypto.timingSafeEqual(expect, r.subarray(4, 20))) return false;
  const ma = parseAttrs(r).find(a => a.type === ATTR['Message-Authenticator']);
  if (ma) {
    const copy = Buffer.from(r);
    reqAuthenticator.copy(copy, 4);
    copy.fill(0, ma.offset + 2, ma.offset + 18);
    const want = crypto.createHmac('md5', secret).update(copy).digest();
    if (!crypto.timingSafeEqual(want, ma.value)) return false;
  }
  return true;
}

function radiusAuthenticate(cfg, username, password) {
  return new Promise(resolve => {
    const trace = [];
    let req;
    try { req = buildAccessRequest({ username, password, secret: cfg.secret, nasIdentifier: cfg.nasIdentifier }); }
    catch (e) { resolve({ ok: false, role: null, reason: e.message, trace }); return; }
    const sock = dgram.createSocket(cfg.host.includes(':') ? 'udp6' : 'udp4');
    let tries = 0, timer = null, done = false;
    const finish = r => { if (done) return; done = true; clearTimeout(timer); try { sock.close(); } catch {} resolve({ ...r, trace }); };
    const send = () => {
      if (tries++ > (cfg.retries ?? 2)) return finish({ ok: false, role: null, reason: 'no reply from the RADIUS server' });
      trace.push(`Access-Request #${tries} → ${cfg.host}:${cfg.port}`);
      sock.send(req.pkt, cfg.port, cfg.host, e => { if (e) finish({ ok: false, role: null, reason: e.message }); });
      timer = setTimeout(send, (cfg.timeoutSec || 5) * 1000);
    };
    sock.on('error', e => finish({ ok: false, role: null, reason: e.message }));
    sock.on('message', msg => {
      if (msg[1] !== req.id) return;
      if (!verifyResponse(msg, req.authenticator, cfg.secret)) { trace.push('reply failed authenticator check (wrong secret?) — ignored'); return; }
      const code = msg[0];
      const attrs = parseAttrs(msg);
      const reply = attrs.filter(a => a.type === ATTR['Reply-Message']).map(a => a.value.toString('utf8')).join(' ');
      if (code !== 2) return finish({ ok: false, role: null, reason: code === 3 ? `rejected${reply ? `: ${reply}` : ''}` : code === 11 ? 'server asked for a challenge (MFA) — not supported' : `unexpected reply code ${code}` });
      const want = ATTR[cfg.roleAttribute] || ATTR.Class;
      const values = attrs.filter(a => a.type === want).map(a => a.value.toString('utf8').trim());
      const matches = ROLE_ORDER.filter(r => cfg.roles[r] && values.some(v => v.toLowerCase() === cfg.roles[r].toLowerCase()));
      const role = pickRole(matches, cfg.defaultRole);
      trace.push(`Access-Accept; ${cfg.roleAttribute} = ${values.join(', ') || '(none)'}`);
      finish({ ok: !!role, role, reason: role ? null : `accepted, but no ${cfg.roleAttribute} value maps to a role`, groups: values });
    });
    send();
  });
}

// ---------------------------------------------------------------------------
// Settings + dispatcher
// ---------------------------------------------------------------------------
class ExternalAuth {
  constructor({ file, ldapClient } = {}) {
    this.file = file;
    this.ldapClient = ldapClient;
    this.settings = this.load();
  }

  load() {
    let s = {};
    try { s = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch {}
    const d = clone(DEFAULTS);
    return {
      order: Array.isArray(s.order) ? s.order.filter(x => ['ldap', 'radius'].includes(x)) : d.order,
      ldap: { ...d.ldap, ...(s.ldap || {}), groups: { ...d.ldap.groups, ...((s.ldap || {}).groups || {}) } },
      radius: { ...d.radius, ...(s.radius || {}), roles: { ...d.radius.roles, ...((s.radius || {}).roles || {}) } },
    };
  }

  save() {
    if (!this.file) return;
    fs.writeFileSync(this.file + '.tmp', JSON.stringify(this.settings, null, 2), { mode: 0o600 });
    fs.renameSync(this.file + '.tmp', this.file);
  }

  view() {
    const s = clone(this.settings);
    s.ldap.bindPasswordSet = !!s.ldap.bindPassword; s.ldap.bindPassword = '';
    s.radius.secretSet = !!s.radius.secret; s.radius.secret = '';
    return s;
  }

  enabled() { return this.settings.ldap.enabled || this.settings.radius.enabled; }

  update(input) {
    const cur = this.settings, next = clone(cur);
    const role = r => (r === '' || r === null || r === undefined ? '' : ROLE_ORDER.includes(r) ? r : (() => { throw err(`role must be one of ${ROLE_ORDER.join(', ')} or empty`); })());
    if (input.ldap) {
      const l = input.ldap;
      next.ldap = {
        enabled: !!l.enabled, url: String(l.url || '').trim(), starttls: !!l.starttls, verifyTls: l.verifyTls !== false,
        caPem: String(l.caPem || '').trim(), mode: l.mode === 'direct' ? 'direct' : 'search',
        bindDn: String(l.bindDn || '').trim(), bindPassword: l.bindPassword ? String(l.bindPassword) : cur.ldap.bindPassword,
        baseDn: String(l.baseDn || '').trim(), userFilter: String(l.userFilter || DEFAULTS.ldap.userFilter).trim(),
        userTemplate: String(l.userTemplate || DEFAULTS.ldap.userTemplate).trim(), nested: l.nested !== false,
        groups: { admin: String((l.groups || {}).admin || '').trim(), operator: String((l.groups || {}).operator || '').trim(), viewer: String((l.groups || {}).viewer || '').trim() },
        defaultRole: role(l.defaultRole),
      };
      const L = next.ldap;
      if (L.enabled) {
        if (!/^ldaps?:\/\/[A-Za-z0-9.\-[\]:]+$/.test(L.url)) throw err('LDAP URL like ldaps://dc01.example.com:636 or ldap://dc01.example.com');
        if (!L.baseDn) throw err('Base DN is required, e.g. DC=example,DC=com');
        if (!L.userFilter.includes('{{username}}')) throw err('User filter must contain {{username}}');
        if (L.mode === 'search' && (!L.bindDn || !L.bindPassword)) throw err('Search mode needs a service account (bind DN + password)');
        if (L.mode === 'direct' && !L.userTemplate.includes('{{username}}')) throw err('User template must contain {{username}}');
        if (L.url.startsWith('ldap:') && !L.starttls) {
          // allowed for lab use, but passwords then cross the network in clear text — the UI warns
        }
        if (L.caPem && !/-----BEGIN CERTIFICATE-----/.test(L.caPem)) throw err('CA must be a PEM certificate');
        if (!L.defaultRole && !Object.values(L.groups).some(Boolean)) throw err('Map at least one group to a role, or set a default role');
      }
    }
    if (input.radius) {
      const r = input.radius;
      next.radius = {
        enabled: !!r.enabled, host: String(r.host || '').trim(), port: parseInt(r.port, 10) || 1812,
        secret: r.secret ? String(r.secret) : cur.radius.secret, timeoutSec: Math.min(30, Math.max(1, parseInt(r.timeoutSec, 10) || 5)),
        retries: Math.min(5, Math.max(0, parseInt(r.retries, 10) || 0)), nasIdentifier: String(r.nasIdentifier || 'nginx-manager').trim().slice(0, 64),
        roleAttribute: ['Class', 'Filter-Id'].includes(r.roleAttribute) ? r.roleAttribute : 'Class',
        roles: { admin: String((r.roles || {}).admin || '').trim(), operator: String((r.roles || {}).operator || '').trim(), viewer: String((r.roles || {}).viewer || '').trim() },
        defaultRole: role(r.defaultRole),
      };
      const R = next.radius;
      if (R.enabled) {
        if (!/^[A-Za-z0-9.\-:]+$/.test(R.host)) throw err('RADIUS server host or IP is required');
        if (!R.secret) throw err('RADIUS shared secret is required');
        if (!R.defaultRole && !Object.values(R.roles).some(Boolean)) throw err('Map at least one attribute value to a role, or set a default role');
      }
    }
    if (Array.isArray(input.order)) next.order = input.order.filter(x => ['ldap', 'radius'].includes(x));
    this.settings = next;
    this.save();
    return this.view();
  }

  // try each enabled provider in order; returns { ok, role, source, ... }
  async authenticate(username, password, { only } = {}) {
    if (!USERNAME.test(String(username || '')) || typeof password !== 'string' || !password) {
      return { ok: false, reason: 'invalid credentials' };           // never send an empty password (LDAP anonymous bind!)
    }
    const tried = [];
    for (const src of this.settings.order) {
      if (only && src !== only) continue;
      const cfg = this.settings[src];
      if (!cfg.enabled) continue;
      const r = src === 'ldap'
        ? await ldapAuthenticate(cfg, username, password, this.ldapClient ? { Client: this.ldapClient } : {})
        : await radiusAuthenticate(cfg, username, password);
      tried.push({ source: src, ...r });
      if (r.ok) return { ...r, source: src, tried };
    }
    const last = tried[tried.length - 1];
    return { ok: false, reason: last ? last.reason : 'no external sign-in configured', tried };
  }
}

module.exports = { ExternalAuth, DEFAULTS, escapeFilter, buildAccessRequest, verifyResponse, hidePassword, parseAttrs, ATTR, radiusAuthenticate, ldapAuthenticate };
