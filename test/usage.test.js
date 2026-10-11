'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { UsageStore, percentile, BINS } = require('../lib/usage');

const NOW = Date.UTC(2026, 9, 11, 12, 30, 0);
const ev = (o = {}) => ({ at: new Date(NOW).toISOString(), client: '192.0.2.10', host: 'app.example.com', status: 200,
  result: 'allowed', bytes: 1000, time: 0.02, upstream: '10.0.0.5:8080', ...o });

test('aggregates counters, top lists and percentiles', () => {
  const u = new UsageStore();
  for (let i = 0; i < 90; i++) u.record('a', ev(), NOW);
  for (let i = 0; i < 5; i++) u.record('a', ev({ status: 403, result: 'denied', client: '198.51.100.7', upstream: '', time: 0 }), NOW);
  for (let i = 0; i < 5; i++) u.record('a', ev({ status: 502, result: 'server_error', time: 3, upstream: '10.0.0.5:8080, 10.0.0.6:8080' }), NOW);
  u.record('a', ev({ stream: true, method: 'TCP', port: '8554', host: '', bytes: 5e6, bytesIn: 1e3, time: 600, upstream: '192.0.2.20:554' }), NOW);
  const q = u.query(['a'], '1h', NOW);
  assert.strictEqual(q.totals.n, 101);
  assert.strictEqual(q.totals.denied, 5);
  assert.strictEqual(q.totals.server_error, 5);
  assert.strictEqual(q.totals.streams, 1);
  assert.strictEqual(q.series.length, 60);
  assert.strictEqual(q.series.reduce((a, s) => a + s.n, 0), 101);
  assert.ok(q.totals.p50 > 0.01 && q.totals.p50 <= 0.025, `p50 ${q.totals.p50}`);
  assert.ok(q.totals.p99 > 2.5, `p99 ${q.totals.p99}`);         // stream session time is not a latency
  assert.strictEqual(q.top.hosts[0].key, 'app.example.com');
  assert.strictEqual(q.top.hosts[0].err, 5);
  assert.strictEqual(q.top.clients.find(c => c.key === '198.51.100.7').denied, 5);
  assert.strictEqual(q.top.upstreams.find(x => x.key === '10.0.0.6:8080').n, 5);
  assert.strictEqual(q.top.streams[0].key, '8554');
  assert.strictEqual(q.top.status.find(x => x.key === '403').n, 5);
});

test('ranges, group sums and retention', () => {
  const u = new UsageStore();
  u.record('a', ev(), NOW);
  u.record('b', ev(), NOW);
  u.record('a', ev({ at: new Date(NOW - 3 * 24 * 3600e3).toISOString() }), NOW - 3 * 24 * 3600e3);   // 3 days ago
  assert.strictEqual(u.query(['a', 'b'], '24h', NOW).totals.n, 2);
  assert.strictEqual(u.query(['a'], '7d', NOW).totals.n, 2);
  assert.strictEqual(u.query(['a'], '7d', NOW).series.length, 168);
  u.prune(u.agent('a'), NOW + 31 * 24 * 3600e3);
  assert.strictEqual(u.agent('a').hours.size, 0);
  // a timestamp far from now is filed under arrival time
  u.record('c', ev({ at: '2001-01-01T00:00:00Z' }), NOW);
  assert.strictEqual(u.query(['c'], '1h', NOW).totals.n, 1);
});

test('persists and reloads; top maps are capped', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nm-usage-'));
  const id = '0f8fad5b-d9cb-469f-a165-70867728950e';
  const u = new UsageStore({ dir });
  for (let i = 0; i < 200; i++) u.record(id, ev({ client: `192.0.2.${i % 250}` }), Date.now());
  u.save();
  const u2 = new UsageStore({ dir });
  u2.load();
  const q = u2.query([id], '1h');
  assert.strictEqual(q.totals.n, 200);
  const hour = [...u2.agent(id).hours.values()][0];
  assert.ok(Object.keys(hour.top.clients).length <= 60);
  assert.ok(hour.top.clients['(other)'].n > 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('percentile interpolates within histogram bins', () => {
  const h = BINS.map(() => 0); h[4] = 10;     // all in (0.05, 0.1]
  const p = percentile(h, 0.5);
  assert.ok(p > 0.05 && p < 0.1);
  assert.strictEqual(percentile(BINS.map(() => 0), 0.5), null);
});
