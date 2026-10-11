/**
 * nginx-manager — lib/groupsync.js
 *
 * Keeping the members of a group (e.g. a keepalived pair) identical.
 *
 *   compare()     drift report: every file whose content differs between members, or that only
 *                 some members have. Uses the *current* file sets (what is on the servers,
 *                 including pinned keys), so pending edits don't count as drift.
 *   planSync()    copy a source member's files onto the other members (stage only)
 *   planPropagate()  carry one member's pending edits to the others, refusing files that the
 *                 other member has changed independently (conflicts) unless forced
 *
 * Paths matching a group's ignore patterns (simple globs, e.g. "/etc/nginx/conf.d/local-*.conf")
 * are left out of both.
 */

'use strict';

function globToRe(g) {
  const s = String(g).trim();
  return new RegExp('^' + s.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*') + '$');
}

function ignorer(patterns = []) {
  const res = patterns.filter(p => String(p).trim()).map(globToRe);
  return name => res.some(r => r.test(name));
}

// members: [{ id, name, files: { name: { hash, permissions, unmanaged } } }]
function compare(members, { ignore = [] } = {}) {
  const skip = ignorer(ignore);
  const names = new Set();
  for (const m of members) for (const n of Object.keys(m.files)) if (!skip(n)) names.add(n);
  const files = [];
  for (const name of [...names].sort()) {
    const states = {};
    for (const m of members) {
      const f = m.files[name];
      states[m.id] = f ? (f.unmanaged ? 'unmanaged' : f.hash) : null;
    }
    const vals = Object.values(states);
    if (vals.includes('unmanaged')) continue;              // contents unknown — can't compare
    const inSync = vals.every(v => v === vals[0]);
    if (!inSync) files.push({ name, states, missingOn: members.filter(m => !states[m.id]).map(m => m.id) });
  }
  return { members: members.map(m => ({ id: m.id, name: m.name })), drift: files, inSync: files.length === 0 };
}

// Stage plan to make every target match the source for the given files (default: all drifted).
// Returns [{ agentId, stage: [{ name, hash, permissions, pin }], remove: [name] }]
function planSync(source, targets, { files = null, ignore = [] } = {}) {
  const skip = ignorer(ignore);
  return targets.map(t => {
    const stage = [], remove = [];
    const names = files || [...new Set([...Object.keys(source.files), ...Object.keys(t.files)])];
    for (const name of names) {
      if (skip(name)) continue;
      const s = source.files[name], d = t.files[name];
      if (s && s.unmanaged) continue;
      if (s && (!d || d.hash !== s.hash || (d.permissions || '0644') !== (s.permissions || '0644'))) {
        stage.push({ name, hash: s.hash, permissions: s.permissions || '0644', pin: !!s.pin });
      } else if (!s && d && !d.unmanaged) remove.push(name);
    }
    return { agentId: t.id, stage, remove };
  });
}

// source.current/source.draft: the source's files before its edits and its pending edits.
// A target file conflicts when it differs from the source's *current* version (someone changed
// it separately), so blindly copying the edit would discard that change.
function planPropagate(source, targets, { force = false, ignore = [] } = {}) {
  const skip = ignorer(ignore);
  const plans = [], conflicts = [];
  for (const t of targets) {
    const stage = [], remove = [];
    for (const [name, d] of Object.entries(source.draft)) {
      if (skip(name)) continue;
      const base = source.current[name], cur = t.files[name];
      const same = (!base && !cur) || (base && cur && base.hash === cur.hash);
      if (!same && !force) { conflicts.push({ agentId: t.id, name }); continue; }
      if (d.deleted) { if (cur) remove.push(name); }
      else stage.push({ name, hash: d.hash, permissions: d.permissions || '0644', pin: !!d.pin });
    }
    plans.push({ agentId: t.id, stage, remove });
  }
  return { plans, conflicts };
}

module.exports = { compare, planSync, planPropagate, globToRe };
