/**
 * nginx-manager — lib/audit.js
 *
 * Append-only audit log (JSON lines) in data/audit.log, rotated to audit.log.1 at 5 MB.
 * Entries: { at, user, ip, action, agent?, target?, result?, detail? } — never secrets.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const MAX_BYTES = 5 * 1024 * 1024;

class AuditLog extends EventEmitter {
  constructor({ file }) {
    super();
    this.file = file;
  }

  record(entry) {
    const e = { at: new Date().toISOString(), ...entry };
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      try { if (fs.statSync(this.file).size > MAX_BYTES) fs.renameSync(this.file, this.file + '.1'); } catch {}
      fs.appendFileSync(this.file, JSON.stringify(e) + '\n', { mode: 0o600 });
    } catch (err) { console.warn('[nginx-manager] audit:', err.message); }
    this.emit('entry', e);
    return e;
  }

  // newest first; filters: user, agent, action (substring), q (free text)
  query({ limit = 200, user, agent, action, q } = {}) {
    const lines = [];
    for (const f of [this.file, this.file + '.1']) {
      try { lines.push(...fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).reverse()); } catch {}
    }
    const out = [];
    for (const l of lines) {
      let e; try { e = JSON.parse(l); } catch { continue; }
      if (user && e.user !== user) continue;
      if (agent && e.agent !== agent) continue;
      if (action && !String(e.action || '').includes(action)) continue;
      if (q && !JSON.stringify(e).toLowerCase().includes(String(q).toLowerCase())) continue;
      out.push(e);
      if (out.length >= limit) break;
    }
    return out;
  }
}

module.exports = { AuditLog };
