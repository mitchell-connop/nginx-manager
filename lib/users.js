/**
 * nginx-manager — lib/users.js
 *
 * Users and roles, in data/users.json (bcrypt hashes only).
 *
 *   admin     everything, including users, alert settings, branding, enrolling/removing servers
 *   operator  edit and apply configuration, certificates, rollbacks, group sync
 *   viewer    read-only (never sees private keys)
 *
 * The built-in "admin" account authenticates with ADMIN_PASSWORD from .env (break-glass,
 * can't be removed or demoted from the UI). Every other account lives in users.json.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ROLES = ['viewer', 'operator', 'admin'];
const BUILTIN = 'admin';
const USERNAME = /^[a-z0-9][a-z0-9._@-]{1,63}$/;
let DUMMY_HASH = null;   // compared against for unknown users, so timing doesn't reveal which usernames exist

function rank(role) { return ROLES.indexOf(role); }
function atLeast(role, min) { return rank(role) >= rank(min); }

class Users {
  constructor({ file, adminPassword }) {
    this.file = file;
    this.adminPassword = adminPassword;
    this.cache = null;
  }

  read() {
    if (this.cache) return this.cache;
    try { this.cache = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { this.cache = []; }
    if (!Array.isArray(this.cache)) this.cache = [];
    return this.cache;
  }

  write(list) {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file + '.tmp', JSON.stringify(list, null, 2), { mode: 0o600 });
    fs.renameSync(this.file + '.tmp', this.file);
    this.cache = list;
  }

  list() {
    return [
      { username: BUILTIN, role: 'admin', builtin: true },
      ...this.read().map(({ passwordHash, ...u }) => u),
      ...this.readExternal().filter(e => !this.exists(e.username)),
    ];
  }

  exists(username) { return username === BUILTIN || this.read().some(u => u.username === username); }

  // Directory (LDAP/RADIUS) users seen at sign-in — for display only; their role comes from the directory each time
  externalFile() { return this.file.replace(/users\.json$/, 'external-users.json'); }
  readExternal() { try { const l = JSON.parse(fs.readFileSync(this.externalFile(), 'utf8')); return Array.isArray(l) ? l : []; } catch { return []; } }
  recordExternal({ username, role, source, displayName }) {
    const list = this.readExternal().filter(e => e.username !== username);
    list.push({ username, role, source, displayName: displayName || '', external: true, lastLogin: new Date().toISOString() });
    fs.writeFileSync(this.externalFile(), JSON.stringify(list, null, 2), { mode: 0o600 });
  }

  // { username, role } or null — used on every request so removed/demoted users lose access at once
  lookup(username) {
    if (username === BUILTIN) return { username: BUILTIN, role: 'admin', builtin: true };
    const u = this.read().find(x => x.username === username);
    return u ? { username: u.username, role: u.role } : null;
  }

  async verify(username, password) {
    if (typeof password !== 'string' || !password) return null;
    const name = String(username || BUILTIN).trim().toLowerCase() || BUILTIN;
    if (name === BUILTIN) {
      const ap = this.adminPassword;
      let ok;
      if (/^\$2[aby]\$/.test(ap)) ok = await bcrypt.compare(password, ap);
      else {
        const a = crypto.createHash('sha256').update(password).digest();
        const b = crypto.createHash('sha256').update(String(ap)).digest();
        ok = crypto.timingSafeEqual(a, b);
      }
      return ok ? this.lookup(BUILTIN) : null;
    }
    const u = this.read().find(x => x.username === name);
    if (!u && !DUMMY_HASH) DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 11);
    const ok = await bcrypt.compare(password, u ? u.passwordHash : DUMMY_HASH);
    if (!u || !ok) return null;
    this.write(this.read().map(x => (x.username === name ? { ...x, lastLogin: new Date().toISOString() } : x)));
    return this.lookup(name);
  }

  validatePassword(pw) {
    if (typeof pw !== 'string' || pw.length < 10 || pw.length > 256) throw Object.assign(new Error('Password must be 10-256 characters'), { status: 400 });
  }

  create({ username, password, role }) {
    const name = String(username || '').trim().toLowerCase();
    if (!USERNAME.test(name)) throw Object.assign(new Error('Username: 2-64 characters, lowercase letters, digits, . _ @ -'), { status: 400 });
    if (name === BUILTIN || this.read().some(u => u.username === name)) throw Object.assign(new Error(`User ${name} already exists`), { status: 409 });
    if (!ROLES.includes(role)) throw Object.assign(new Error(`Role must be one of ${ROLES.join(', ')}`), { status: 400 });
    this.validatePassword(password);
    const user = { username: name, role, passwordHash: bcrypt.hashSync(password, 11), createdAt: new Date().toISOString(), lastLogin: null };
    this.write([...this.read(), user]);
    return this.lookup(name);
  }

  update(username, { role, password }) {
    if (username === BUILTIN) throw Object.assign(new Error('The built-in admin is managed through ADMIN_PASSWORD in .env'), { status: 400 });
    const list = this.read();
    const u = list.find(x => x.username === username);
    if (!u) throw Object.assign(new Error('User not found'), { status: 404 });
    const next = { ...u };
    if (role !== undefined) {
      if (!ROLES.includes(role)) throw Object.assign(new Error(`Role must be one of ${ROLES.join(', ')}`), { status: 400 });
      next.role = role;
    }
    if (password !== undefined) { this.validatePassword(password); next.passwordHash = bcrypt.hashSync(password, 11); }
    this.write(list.map(x => (x.username === username ? next : x)));
    return this.lookup(username);
  }

  remove(username) {
    if (username === BUILTIN) throw Object.assign(new Error("The built-in admin can't be removed"), { status: 400 });
    const list = this.read();
    if (!list.some(x => x.username === username)) throw Object.assign(new Error('User not found'), { status: 404 });
    this.write(list.filter(x => x.username !== username));
  }
}

module.exports = { Users, ROLES, BUILTIN, atLeast };
