/**
 * nginx-manager — lib/health.js
 *
 * Backend health checks run FROM THE DATA PLANE. The manager is the control plane and may sit
 * in another VLAN, so it can't judge whether a load balancer can reach its backends. Instead a
 * small helper on each server (helper/nm-helper.py, systemd unit nginx-manager-helper) probes
 * the backends and reads nginx's stub_status on loopback, and reports both over the same UDP
 * syslog channel as the request log (tag nginx_health).
 *
 *   targets     derived from the config the agent reports: upstream server lines, direct
 *               proxy_pass/grpc_pass addresses, stream upstreams
 *   helper.json written to <nginx>/nginx-manager/helper.json by the agent (pinned — nginx never
 *               references it, so the agent wouldn't report it back)
 *   state       per server and target; up/down decided here with fall/rise thresholds so the
 *               helper stays a dumb prober
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const pf = require('./proxyfile');

const HELPER_VERSION = '1.0';
const STATUS_PORT = 8099;
const DEFAULTS = { interval: 10, timeout: 3, fall: 3, rise: 2 };

// ---------------------------------------------------------------------------
// Targets from config
// ---------------------------------------------------------------------------
function walk(node, fn, ctx = []) {
  for (const c of node.children || []) {
    fn(c, ctx);
    if (c.type === 'block') walk(c, fn, [...ctx, c.name]);
  }
}

function splitHostPort(addr, defPort) {
  const v = String(addr).trim();
  let m = v.match(/^\[([0-9a-fA-F:]+)\](?::(\d+))?$/);
  if (m) return { host: m[1], port: +(m[2] || defPort) };
  m = v.match(/^([^:/\s]+)(?::(\d+))?$/);
  return m ? { host: m[1], port: +(m[2] || defPort) } : null;
}

const keyOf = (host, port) => (host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`);

// files: { name: text } → [{ key, host, port, tls, scheme, usedBy: [labels] }]
function deriveTargets(files) {
  const upstreams = new Map();     // name -> [{ host, port, context }]
  const passes = [];               // { target, scheme, label, context }
  for (const [file, text] of Object.entries(files)) {
    let root;
    try { root = pf.parse(text); } catch { continue; }
    walk(root, (n, ctx) => {
      const context = ctx.includes('stream') || /\/stream\.d\//.test(file) ? 'stream' : 'http';
      if (n.type === 'block' && n.name === 'upstream' && n.args[0]) {
        const servers = (n.children || []).filter(c => c.type === 'directive' && c.name === 'server' && c.args[0])
          .map(c => c.args[0].text).filter(a => !a.startsWith('unix:'));
        upstreams.set(n.args[0].text, { servers, context });
      }
      if (n.type === 'directive' && ['proxy_pass', 'grpc_pass'].includes(n.name) && n.args[0]) {
        passes.push({ raw: n.args[0].text, directive: n.name, context, file: path.basename(file) });
      }
    });
  }
  const out = new Map();
  const add = (host, port, tls, label) => {
    const key = keyOf(host, port);
    const t = out.get(key) || { key, host, port, tls: false, usedBy: [] };
    t.tls = t.tls || tls;
    if (label && !t.usedBy.includes(label)) t.usedBy.push(label);
    out.set(key, t);
  };
  const used = new Set();
  for (const p of passes) {
    if (p.raw.includes('$')) continue;                                   // variables: resolved at runtime
    let scheme = p.directive === 'grpc_pass' ? 'grpc' : 'tcp', rest = p.raw;
    const m = p.raw.match(/^([a-z]+):\/\/(.+)$/i);
    if (m) { scheme = m[1].toLowerCase(); rest = m[2]; }
    rest = rest.split('/')[0];
    const tls = scheme === 'https' || scheme === 'grpcs';
    if (upstreams.has(rest)) {
      used.add(rest);
      for (const s of upstreams.get(rest).servers) {
        const hp = splitHostPort(s, p.context === 'stream' ? 80 : tls ? 443 : 80);
        if (hp) add(hp.host, hp.port, tls, `upstream ${rest}`);
      }
      continue;
    }
    if (rest.startsWith('unix:')) continue;
    const hp = splitHostPort(rest, tls ? 443 : 80);
    if (hp) add(hp.host, hp.port, tls, p.file);
  }
  // upstreams defined but referenced only through variables still deserve a check
  for (const [name, u] of upstreams) {
    if (used.has(name)) continue;
    for (const s of u.servers) { const hp = splitHostPort(s, 80); if (hp) add(hp.host, hp.port, false, `upstream ${name}`); }
  }
  return [...out.values()].sort((a, b) => a.key.localeCompare(b.key));
}

// ---------------------------------------------------------------------------
// Files deployed to the server
// ---------------------------------------------------------------------------
function helperPaths(nginxDir) {
  return {
    config: `${nginxDir}/nginx-manager/helper.json`,
    status: `${nginxDir}/conf.d/00-nginx-manager-status.conf`,
  };
}

function statusConf(port = STATUS_PORT) {
  return [
    '# Managed by nginx-manager: loopback-only stub_status read by the nginx-manager helper',
    '# (live connections on the Health tab). Not reachable from the network.',
    'server {',
    `    listen 127.0.0.1:${port};`,
    '    access_log off;',
    '    location = /nm_status {',
    '        stub_status;',
    '        allow 127.0.0.1;',
    '        deny all;',
    '    }',
    '    location / { return 404; }',
    '}',
    '',
  ].join('\n');
}

function helperConfig(targets, settings, { receiver, port, statusPort = STATUS_PORT }) {
  const d = { ...DEFAULTS, ...(settings.defaults || {}) };
  return JSON.stringify({
    version: 1,
    interval: d.interval,
    timeout: d.timeout,
    report: { host: receiver, port },
    status: `http://127.0.0.1:${statusPort}/nm_status`,
    targets: targets.filter(t => !(settings.targets[t.key] || {}).disabled).map(t => {
      const s = settings.targets[t.key] || {};
      return {
        k: t.key, host: t.host, port: t.port,
        type: s.type === 'http' ? 'http' : 'tcp',
        ...(s.type === 'http' ? { tls: s.tls !== undefined ? !!s.tls : t.tls, path: s.path || '/', expect: s.expect || '200-399', hostHeader: s.hostHeader || '' } : {}),
      };
    }),
  }, null, 2) + '\n';
}

// systemd unit + script install; the helper's targets arrive later through the agent
function helperInstallScript(helperSource) {
  return [
    '#!/bin/bash',
    '# Run as root on each nginx server: installs the nginx-manager helper (backend health checks + live connections).',
    '# It runs unprivileged and only reads helper.json, written by nginx-manager through NGINX Agent.',
    'set -euo pipefail',
    'command -v python3 >/dev/null || { apt-get update && apt-get install -y python3-minimal; }',
    'install -d -m 755 /usr/local/lib/nginx-manager',
    "cat > /usr/local/lib/nginx-manager/nm-helper.py <<'NMHELPER'",
    helperSource.trimEnd(),
    'NMHELPER',
    'chmod 755 /usr/local/lib/nginx-manager/nm-helper.py',
    "cat > /etc/systemd/system/nginx-manager-helper.service <<'EOF'",
    '[Unit]',
    'Description=nginx-manager helper (backend health checks, live connections)',
    'After=network-online.target nginx.service',
    'Wants=network-online.target',
    '',
    '[Service]',
    'ExecStart=/usr/bin/python3 /usr/local/lib/nginx-manager/nm-helper.py /etc/nginx/nginx-manager/helper.json',
    'Restart=always',
    'RestartSec=5',
    'DynamicUser=yes',
    'NoNewPrivileges=yes',
    'ProtectSystem=strict',
    'ProtectHome=yes',
    'PrivateTmp=yes',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    'EOF',
    'systemctl daemon-reload',
    'systemctl enable --now nginx-manager-helper.service',
    'systemctl restart nginx-manager-helper.service',
    'systemctl --no-pager --lines=0 status nginx-manager-helper.service',
  ].join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Settings (data/health-settings.json)
// ---------------------------------------------------------------------------
function loadSettings(file) {
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { defaults: { ...DEFAULTS, ...(s.defaults || {}) }, targets: s.targets || {} };
  } catch { return { defaults: { ...DEFAULTS }, targets: {} }; }
}

function validateTargetSettings(s) {
  const out = {};
  if (s.type !== undefined) { if (!['tcp', 'http'].includes(s.type)) throw Object.assign(new Error('type must be tcp or http'), { status: 400 }); out.type = s.type; }
  if (s.path !== undefined) { if (!/^\/[^\s]*$/.test(s.path) || s.path.length > 200) throw Object.assign(new Error('path must start with /'), { status: 400 }); out.path = s.path; }
  if (s.expect !== undefined) { if (!/^\d{3}(-\d{3})?(,\s*\d{3}(-\d{3})?)*$/.test(s.expect)) throw Object.assign(new Error('expect: e.g. 200-399 or 200,204'), { status: 400 }); out.expect = s.expect; }
  if (s.hostHeader !== undefined) { if (s.hostHeader && !/^[A-Za-z0-9.-]+(:\d+)?$/.test(s.hostHeader)) throw Object.assign(new Error('Host header must be a hostname'), { status: 400 }); out.hostHeader = s.hostHeader; }
  if (s.tls !== undefined) out.tls = !!s.tls;
  if (s.disabled !== undefined) out.disabled = !!s.disabled;
  return out;
}

function validateDefaults(d) {
  const out = { ...DEFAULTS };
  for (const [k, lo, hi] of [['interval', 5, 300], ['timeout', 1, 30], ['fall', 1, 10], ['rise', 1, 10]]) {
    if (d[k] === undefined) continue;
    const v = parseInt(d[k], 10);
    if (!(v >= lo && v <= hi)) throw Object.assign(new Error(`${k} must be ${lo}-${hi}`), { status: 400 });
    out[k] = v;
  }
  if (out.timeout >= out.interval) throw Object.assign(new Error('timeout must be shorter than the interval'), { status: 400 });
  return out;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
class HealthState extends EventEmitter {
  constructor({ getSettings }) {
    super();
    this.getSettings = getSettings;
    this.targets = new Map();     // agentId -> Map(key -> state)
    this.status = new Map();      // agentId -> { at, active, reading, writing, waiting, accepts, handled, requests, helper }
    this.lastReport = new Map();  // agentId -> { at, helper }
  }

  receive(agentId, msg, now = Date.now()) {
    if (!msg || typeof msg !== 'object') return;
    const { fall, rise } = this.getSettings().defaults;
    this.lastReport.set(agentId, { at: new Date(now).toISOString(), helper: String(msg.helper || '') });
    if (msg.status && typeof msg.status === 'object') {
      const s = msg.status;
      const sample = { at: new Date(now).toISOString() };
      for (const k of ['active', 'reading', 'writing', 'waiting', 'accepts', 'handled', 'requests']) sample[k] = Number.isFinite(+s[k]) ? +s[k] : null;
      this.status.set(agentId, sample);
      this.emit('status', agentId, sample);
    }
    let map = this.targets.get(agentId);
    if (!map) this.targets.set(agentId, map = new Map());
    for (const r of Array.isArray(msg.results) ? msg.results : []) {
      if (!r || typeof r.k !== 'string' || r.k.length > 300) continue;
      const t = map.get(r.k) || { key: r.k, status: 'unknown', okRun: 0, failRun: 0, since: null, lastAt: null, ms: null, code: null, error: '', minutes: [] };
      const ok = !!r.ok;
      t.okRun = ok ? t.okRun + 1 : 0;
      t.failRun = ok ? 0 : t.failRun + 1;
      t.lastAt = new Date(now).toISOString();
      t.ms = Number.isFinite(+r.ms) ? Math.round(+r.ms * 10) / 10 : null;
      t.code = r.code || null;
      t.error = ok ? '' : String(r.err || 'failed').slice(0, 200);
      // per-minute availability for the last 24 h
      const minute = Math.floor(now / 60e3) * 60e3;
      let b = t.minutes[t.minutes.length - 1];
      if (!b || b.t !== minute) { b = { t: minute, ok: 0, fail: 0 }; t.minutes.push(b); if (t.minutes.length > 1440) t.minutes.shift(); }
      if (ok) b.ok++; else b.fail++;
      const prev = t.status;
      if (ok && (t.status !== 'up') && (t.okRun >= rise || t.status === 'unknown')) t.status = 'up';
      if (!ok && t.status !== 'down' && (t.failRun >= fall)) t.status = 'down';
      if (prev !== t.status) {
        t.since = t.lastAt;
        if (prev !== 'unknown' || t.status === 'down') this.emit('transition', { agentId, key: r.k, from: prev, to: t.status, error: t.error, at: t.lastAt });
      }
      map.set(r.k, t);
    }
  }

  view(agentId) {
    const map = this.targets.get(agentId) || new Map();
    const out = {};
    for (const [k, t] of map) {
      const ok = t.minutes.reduce((a, b) => a + b.ok, 0), fail = t.minutes.reduce((a, b) => a + b.fail, 0);
      out[k] = { status: t.status, since: t.since, lastAt: t.lastAt, ms: t.ms, code: t.code, error: t.error,
        uptime24h: ok + fail ? ok / (ok + fail) : null,
        recent: t.minutes.slice(-60).map(b => (b.fail ? (b.ok ? 'partial' : 'down') : 'up')) };
    }
    return { report: this.lastReport.get(agentId) || null, status: this.status.get(agentId) || null, targets: out };
  }

  forget(agentId) { this.targets.delete(agentId); this.status.delete(agentId); this.lastReport.delete(agentId); }
}

module.exports = {
  HELPER_VERSION, STATUS_PORT, DEFAULTS, deriveTargets, helperPaths, statusConf, helperConfig, helperInstallScript,
  loadSettings, validateTargetSettings, validateDefaults, HealthState, splitHostPort,
};
