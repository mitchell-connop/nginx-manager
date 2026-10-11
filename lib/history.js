/**
 * nginx-manager — lib/history.js
 *
 * Config history per server: a snapshot of the complete file set (name → content hash,
 * permissions) every time it changes, whether through an apply here or an edit made on the
 * server itself (reported by the agent's file watcher). File contents live in the
 * content-addressed blob store, so a snapshot is small and every version can be restored.
 *
 *   data/history/<agentId>.json  [{ id, at, cause, user, label, result, files: { name: { hash, permissions, pin? } } }]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEEP = 200;

function fingerprint(files) {
  const h = crypto.createHash('sha256');
  for (const name of Object.keys(files).sort()) h.update(`${name}\0${files[name].hash}\0${files[name].permissions || ''}\n`);
  return h.digest('hex');
}

// compact form of a store file map; unmanaged files (contents unknown) are left out
function compact(files) {
  const out = {};
  for (const [name, f] of Object.entries(files)) {
    if (!f || f.unmanaged || !f.hash) continue;
    out[name] = { hash: f.hash, permissions: f.permissions || '0644', ...(f.pin ? { pin: true } : {}) };
  }
  return out;
}

function changesBetween(prev, next) {
  const a = prev || {}, b = next || {};
  const out = [];
  for (const name of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (!a[name]) out.push({ name, change: 'added' });
    else if (!b[name]) out.push({ name, change: 'deleted' });
    else if (a[name].hash !== b[name].hash || a[name].permissions !== b[name].permissions) out.push({ name, change: 'modified' });
  }
  return out.sort((x, y) => x.name.localeCompare(y.name));
}

class History {
  constructor({ dir }) {
    this.dir = dir;
    this.cache = new Map();
  }

  file(agentId) {
    if (!/^[A-Za-z0-9_-]+$/.test(agentId)) throw new Error('bad agent id');
    return path.join(this.dir, `${agentId}.json`);
  }

  list(agentId) {
    if (this.cache.has(agentId)) return this.cache.get(agentId);
    let list = [];
    try { list = JSON.parse(fs.readFileSync(this.file(agentId), 'utf8')); } catch {}
    if (!Array.isArray(list)) list = [];
    this.cache.set(agentId, list);
    return list;
  }

  save(agentId, list) {
    fs.mkdirSync(this.dir, { recursive: true });
    const f = this.file(agentId);
    fs.writeFileSync(f + '.tmp', JSON.stringify(list), { mode: 0o600 });
    fs.renameSync(f + '.tmp', f);
    this.cache.set(agentId, list);
  }

  // Record the file set if it differs from the latest snapshot. Returns the snapshot or null.
  record(agentId, files, { cause = 'server', user = null, label = '', result = null } = {}) {
    const set = compact(files);
    const fp = fingerprint(set);
    const list = this.list(agentId);
    const last = list[list.length - 1];
    if (last && last.fp === fp) {
      // same content: an apply confirming what the agent already reported — attribute it
      if (cause === 'apply' && last.cause !== 'apply' && Date.now() - Date.parse(last.at) < 120e3) {
        Object.assign(last, { cause, user, label, result });
        this.save(agentId, list);
        return last;
      }
      return null;
    }
    const snap = {
      id: `${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,
      at: new Date().toISOString(), cause, user, label, result, fp,
      changes: changesBetween(last && last.files, set),
      files: set,
    };
    list.push(snap);
    if (list.length > KEEP) list.splice(0, list.length - KEEP);
    this.save(agentId, list);
    return snap;
  }

  get(agentId, id) { return this.list(agentId).find(s => s.id === id) || null; }

  previous(agentId, id) {
    const list = this.list(agentId);
    const i = list.findIndex(s => s.id === id);
    return i > 0 ? list[i - 1] : null;
  }

  summaries(agentId) {
    return this.list(agentId).map(({ files, fp, ...s }) => ({ ...s, fileCount: Object.keys(files).length })).reverse();
  }

  forget(agentId) {
    this.cache.delete(agentId);
    try { fs.unlinkSync(this.file(agentId)); } catch {}
  }
}

module.exports = { History, fingerprint, compact, changesBetween };
