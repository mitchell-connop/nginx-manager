/**
 * nginx-manager — lib/usage.js
 *
 * Usage statistics aggregated from the request/stream log the servers stream to the
 * manager (lib/logrx). Two resolutions per agent:
 *
 *   minutes  last 48 h   counters only
 *   hours    last 30 d   counters + top-N maps (sites, clients, status codes, upstreams, stream ports)
 *
 * Latency is kept as a fixed histogram so percentiles can be merged across buckets and
 * servers. Saved to data/usage/<agentId>.json at most once a minute.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const MINUTE = 60e3;
const HOUR = 60 * MINUTE;
const KEEP_MINUTES = 48 * 60;
const KEEP_HOURS = 30 * 24;
const TOP_CAP = 60;          // entries kept per top-N map in an hour bucket
const SAVE_MS = 60e3;

// latency histogram upper bounds (seconds); the last bin is open-ended
const BINS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, Infinity];
const RESULTS = ['allowed', 'client_error', 'server_error', 'denied'];

const RANGES = {
  '1h':  { span: HOUR,           step: MINUTE,      res: 'minutes' },
  '6h':  { span: 6 * HOUR,       step: 5 * MINUTE,  res: 'minutes' },
  '24h': { span: 24 * HOUR,      step: 15 * MINUTE, res: 'minutes' },
  '7d':  { span: 7 * 24 * HOUR,  step: HOUR,        res: 'hours' },
  '30d': { span: 30 * 24 * HOUR, step: 6 * HOUR,    res: 'hours' },
};

function emptyCounters() {
  return { n: 0, allowed: 0, client_error: 0, server_error: 0, denied: 0, bytes: 0, bytesIn: 0,
    timeSum: 0, timeN: 0, hist: BINS.map(() => 0), streams: 0, streamBytes: 0 };
}

function addCounters(a, b) {
  for (const k of ['n', ...RESULTS, 'bytes', 'bytesIn', 'timeSum', 'timeN', 'streams', 'streamBytes']) a[k] += b[k] || 0;
  for (let i = 0; i < BINS.length; i++) a.hist[i] += (b.hist && b.hist[i]) || 0;
  return a;
}

function bump(map, key, fields) {
  if (!key) return;
  const cur = map[key] || (map[key] = {});
  for (const [k, v] of Object.entries(fields)) cur[k] = (cur[k] || 0) + v;
}

// keep the TOP_CAP biggest entries by n; the rest fold into "(other)"
function capMap(map) {
  const keys = Object.keys(map);
  if (keys.length <= TOP_CAP) return map;
  keys.sort((a, b) => (map[b].n || 0) - (map[a].n || 0));
  const out = {};
  const other = { ...(map['(other)'] || {}) };
  keys.forEach((k, i) => {
    if (i < TOP_CAP - 1 && k !== '(other)') out[k] = map[k];
    else if (k !== '(other)') for (const [f, v] of Object.entries(map[k])) other[f] = (other[f] || 0) + v;
  });
  out['(other)'] = other;
  return out;
}

function percentile(hist, p) {
  const total = hist.reduce((a, b) => a + b, 0);
  if (!total) return null;
  const target = total * p;
  let acc = 0;
  for (let i = 0; i < hist.length; i++) {
    if (acc + hist[i] >= target) {
      const lo = i ? BINS[i - 1] : 0;
      const hi = BINS[i] === Infinity ? lo * 2 : BINS[i];
      return lo + (hi - lo) * ((target - acc) / hist[i]);     // linear within the bin
    }
    acc += hist[i];
  }
  return BINS[BINS.length - 2];
}

class UsageStore {
  constructor({ dir = null } = {}) {
    this.dir = dir;
    this.data = new Map();       // agentId -> { minutes: Map(t -> counters), hours: Map(t -> {c, top}) }
    this.dirty = new Set();
    this.timer = null;
  }

  start() {
    this.load();
    this.timer = setInterval(() => this.save(), SAVE_MS);
    this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.save();
  }

  agent(id) {
    let d = this.data.get(id);
    if (!d) this.data.set(id, d = { minutes: new Map(), hours: new Map() });
    return d;
  }

  record(agentId, e, now = Date.now()) {
    let at = Date.parse(e.at);
    if (!Number.isFinite(at) || Math.abs(at - now) > HOUR) at = now;     // bad/odd clocks: file under arrival time
    const d = this.agent(agentId);
    const m = Math.floor(at / MINUTE) * MINUTE;
    const h = Math.floor(at / HOUR) * HOUR;
    let mc = d.minutes.get(m);
    if (!mc) d.minutes.set(m, mc = emptyCounters());
    let hb = d.hours.get(h);
    if (!hb) d.hours.set(h, hb = { c: emptyCounters(), top: { hosts: {}, clients: {}, status: {}, upstreams: {}, streams: {} } });

    const err = e.result === 'server_error' ? 1 : 0;
    const denied = e.result === 'denied' ? 1 : 0;
    for (const c of [mc, hb.c]) {
      c.n++;
      if (c[e.result] !== undefined) c[e.result]++;
      c.bytes += e.bytes || 0;
      if (e.stream) {
        c.streams++;
        c.streamBytes += (e.bytes || 0) + (e.bytesIn || 0);
        c.bytesIn += e.bytesIn || 0;
      } else if (typeof e.time === 'number') {
        c.timeSum += e.time; c.timeN++;
        let i = 0; while (e.time > BINS[i]) i++;
        c.hist[i]++;
      }
    }
    const t = hb.top;
    if (e.stream) bump(t.streams, String(e.port || '?'), { n: 1, bytes: (e.bytes || 0) + (e.bytesIn || 0), time: e.time || 0, denied, err });
    else bump(t.hosts, e.host || '(none)', { n: 1, bytes: e.bytes || 0, denied, err });
    bump(t.clients, e.client, { n: 1, bytes: e.bytes || 0, denied });
    bump(t.status, String(e.status || 0), { n: 1 });
    if (e.upstream) for (const u of String(e.upstream).split(/\s+:\s+|\s*,\s*/)) bump(t.upstreams, u.trim(), { n: 1, err });
    this.dirty.add(agentId);
  }

  prune(d, now = Date.now()) {
    const mCut = now - KEEP_MINUTES * MINUTE, hCut = now - KEEP_HOURS * HOUR;
    for (const t of d.minutes.keys()) if (t < mCut) d.minutes.delete(t);
    for (const t of d.hours.keys()) if (t < hCut) d.hours.delete(t);
  }

  // ---- persistence -------------------------------------------------------
  file(id) { return path.join(this.dir, `${id}.json`); }

  load() {
    if (!this.dir) return;
    let names = [];
    try { names = fs.readdirSync(this.dir); } catch { return; }
    for (const name of names) {
      const m = name.match(/^([A-Za-z0-9_-]+)\.json$/);
      if (!m) continue;
      try {
        const raw = JSON.parse(fs.readFileSync(path.join(this.dir, name), 'utf8'));
        const d = this.agent(m[1]);
        for (const [t, c] of raw.minutes || []) d.minutes.set(t, c);
        for (const [t, b] of raw.hours || []) d.hours.set(t, b);
        this.prune(d);
      } catch (err) { console.warn(`[nginx-manager] usage: could not read ${name}: ${err.message}`); }
    }
  }

  save() {
    if (!this.dir || !this.dirty.size) return;
    try { fs.mkdirSync(this.dir, { recursive: true }); } catch {}
    for (const id of this.dirty) {
      if (!/^[A-Za-z0-9_-]+$/.test(id)) continue;
      const d = this.data.get(id);
      if (!d) continue;
      this.prune(d);
      for (const b of d.hours.values()) for (const k of Object.keys(b.top)) b.top[k] = capMap(b.top[k]);
      try {
        const f = this.file(id);
        fs.writeFileSync(f + '.tmp', JSON.stringify({ v: 1, minutes: [...d.minutes], hours: [...d.hours] }));
        fs.renameSync(f + '.tmp', f);
      } catch (err) { console.warn(`[nginx-manager] usage: could not save ${id}: ${err.message}`); }
    }
    this.dirty.clear();
  }

  forget(id) {
    this.data.delete(id);
    if (this.dir) { try { fs.unlinkSync(this.file(id)); } catch {} }
  }

  // ---- queries -----------------------------------------------------------
  query(agentIds, rangeKey = '24h', now = Date.now()) {
    const r = RANGES[rangeKey] || RANGES['24h'];
    const end = Math.floor(now / r.step) * r.step + r.step;
    const start = end - r.span;
    const slots = new Map();
    for (let t = start; t < end; t += r.step) slots.set(t, emptyCounters());
    const total = emptyCounters();
    const top = { hosts: {}, clients: {}, status: {}, upstreams: {}, streams: {} };
    let firstData = null;

    for (const id of agentIds) {
      const d = this.data.get(id);
      if (!d) continue;
      const src = r.res === 'minutes' ? d.minutes : d.hours;
      for (const [t, v] of src) {
        if (t < start || t >= end) continue;
        const c = r.res === 'minutes' ? v : v.c;
        addCounters(slots.get(Math.floor((t - start) / r.step) * r.step + start), c);
        addCounters(total, c);
        if (firstData === null || t < firstData) firstData = t;
      }
      // top lists always come from hour buckets overlapping the range
      for (const [t, b] of d.hours) {
        if (t + HOUR <= start || t >= end) continue;
        for (const k of Object.keys(top)) for (const [key, f] of Object.entries(b.top[k] || {})) bump(top[k], key, f);
      }
    }

    const series = [...slots].map(([t, c]) => ({
      t, n: c.n, allowed: c.allowed, client_error: c.client_error, server_error: c.server_error, denied: c.denied,
      bytes: c.bytes, streams: c.streams,
      p50: percentile(c.hist, 0.5), p95: percentile(c.hist, 0.95),
    }));
    const list = (m, n = 10) => Object.entries(m).map(([key, f]) => ({ key, ...f }))
      .sort((a, b) => (b.n || 0) - (a.n || 0)).slice(0, n);
    return {
      range: rangeKey, step: r.step, start, end, firstData,
      totals: {
        n: total.n, allowed: total.allowed, client_error: total.client_error, server_error: total.server_error,
        denied: total.denied, bytes: total.bytes, streams: total.streams, streamBytes: total.streamBytes,
        avg: total.timeN ? total.timeSum / total.timeN : null,
        p50: percentile(total.hist, 0.5), p95: percentile(total.hist, 0.95), p99: percentile(total.hist, 0.99),
      },
      series,
      top: { hosts: list(top.hosts), clients: list(top.clients), status: list(top.status, 12), upstreams: list(top.upstreams), streams: list(top.streams) },
    };
  }
}

module.exports = { UsageStore, RANGES, BINS, percentile };
