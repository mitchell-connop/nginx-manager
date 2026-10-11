/**
 * nginx-manager — lib/cve.js
 *
 * CVE detection for the managed servers, from what the agents report:
 *
 *   nginx        nginx.org security advisories (https://nginx.org/en/security_advisories.html) —
 *                the authoritative list, with vulnerable/fixed version ranges per advisory.
 *                Advisories tied to a module are checked against the server's config: a vulnerable
 *                version whose module isn't used is reported as "not in use" rather than "affected".
 *   nginx-agent  OSV.dev (Go module github.com/nginx/agent/v3)
 *
 * Sources are fetched at most every REFRESH_MS and cached in data/cve-cache.json so the
 * page works offline and across restarts. OS packages (OpenSSL, keepalived…) aren't
 * covered: the agent doesn't report them.
 */

'use strict';

const fs = require('fs');
const https = require('https');
const { EventEmitter } = require('events');

const ADVISORIES_URL = 'https://nginx.org/en/security_advisories.html';
const OSV_URL = 'https://api.osv.dev/v1/query';
const AGENT_MODULE = 'github.com/nginx/agent/v3';
const REFRESH_MS = 24 * 3600e3;

// ---------------------------------------------------------------------------
// HTTP (no dependency; longer happy-eyeballs window for slow IPv4 paths)
// ---------------------------------------------------------------------------
function request(url, { method = 'GET', body = null, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method, timeout, autoSelectFamily: true, autoSelectFamilyAttemptTimeout: 2000,
      headers: { 'User-Agent': 'nginx-manager', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(text);
        else reject(new Error(`${url}: HTTP ${res.statusCode}`));
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${url}: timed out`)));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------
function parseVersion(v) {
  const m = String(v || '').match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  return m ? [+m[1], +m[2], +(m[3] || 0)] : null;
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

// "0.9.6-1.31.2, 1.0.7-1.0.15" | "1.25.3" | "all" | "nginx/Windows 0.7.52-1.3.0" | "none"
function parseRanges(spec) {
  const s = String(spec || '').trim();
  const windowsOnly = /nginx\/Windows/i.test(s);
  if (/^none$/i.test(s)) return { all: false, ranges: [], windowsOnly };
  if (/(^|\s)all$/i.test(s)) return { all: true, ranges: [], windowsOnly };
  const ranges = [];
  for (const part of s.replace(/nginx\/Windows/ig, '').split(',')) {
    const m = part.trim().match(/^(\d+\.\d+(?:\.\d+)?)(?:\s*-\s*(\d+\.\d+(?:\.\d+)?))?$/);
    if (m) ranges.push([parseVersion(m[1]), parseVersion(m[2] || m[1])]);
  }
  return { all: false, ranges, windowsOnly };
}

function inRanges(version, spec) {
  const v = parseVersion(version);
  if (!v) return null;
  if (spec.all) return true;
  return spec.ranges.some(([lo, hi]) => cmp(v, lo) >= 0 && cmp(v, hi) <= 0);
}

// The first fixed release on the server's branch (same major.minor), else the lowest newer fix.
function fixedFor(version, notVulnerable) {
  const v = parseVersion(version);
  if (!v) return null;
  const fixes = String(notVulnerable || '').split(',').map(x => x.trim().replace(/\+$/, '')).map(parseVersion).filter(Boolean);
  const same = fixes.filter(f => f[0] === v[0] && f[1] === v[1] && cmp(f, v) > 0).sort(cmp)[0];
  if (same) return same.join('.');
  const newer = fixes.filter(f => cmp(f, v) > 0).sort(cmp)[0];
  return newer ? newer.join('.') : null;
}

// ---------------------------------------------------------------------------
// nginx.org advisories
// ---------------------------------------------------------------------------
const decode = s => s.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ').trim();

function parseAdvisories(html) {
  const out = [];
  for (const m of String(html).matchAll(/<li><p>([\s\S]*?)<\/p><\/li>/g)) {
    const parts = m[1].split(/<br\s*\/?>/i);
    const title = decode(parts[0] || '');
    if (!title) continue;
    const field = name => {
      const p = parts.find(x => decode(x).toLowerCase().startsWith(name.toLowerCase() + ':'));
      return p ? decode(p).slice(name.length + 1).trim() : '';
    };
    const cves = [...m[1].matchAll(/CVE-\d{4}-\d{4,}/g)].map(x => x[0]).filter((x, i, a) => a.indexOf(x) === i);
    const adv = parts.map(p => p.match(/href="([^"]+)"[^>]*>\s*Advisory/i)).find(Boolean);
    const vulnerable = field('Vulnerable');
    if (!vulnerable) continue;
    out.push({
      title,
      severity: field('Severity').toLowerCase() || 'unknown',
      cves,
      advisory: adv ? adv[1] : null,
      notVulnerable: field('Not vulnerable'),
      vulnerable,
    });
  }
  return out;
}

// Advisories tied to an optional module/feature → how to tell from the config whether it's in use.
const FEATURES = [
  { re: /nginx\/Windows/i, feature: 'nginx for Windows', test: () => false },
  { re: /ngx_http_v3_module|HTTP\/3|QUIC/i, feature: 'HTTP/3 (QUIC)', test: c => /\blisten\s[^;]*\bquic\b|\bhttp3\s+on\b/.test(c) },
  { re: /ngx_http_v2_module|HTTP\/2|ngx_http_spdy|SPDY/i, feature: 'HTTP/2', test: c => /\bhttp2\b|\bspdy\b/.test(c) },
  { re: /proxy_v2/i, feature: 'proxying over HTTP/2', test: c => /^\s*proxy_http_version\s+2/m.test(c) },
  { re: /grpc/i, feature: 'gRPC proxying', test: c => /^\s*grpc_pass\s/m.test(c) },
  { re: /mp4/i, feature: 'ngx_http_mp4_module', test: c => /^\s*mp4\s*;/m.test(c) },
  { re: /slice/i, feature: 'ngx_http_slice_module', test: c => /^\s*slice\s/m.test(c) },
  { re: /\bssi\b|ngx_http_ssi_module/i, feature: 'SSI', test: c => /^\s*ssi\s+on/m.test(c) },
  { re: /dav/i, feature: 'WebDAV', test: c => /^\s*dav_methods\s/m.test(c) },
  { re: /mail|smtp|imap|pop3/i, feature: 'mail proxy', test: c => /^\s*mail\s*\{/m.test(c) },
  { re: /charset/i, feature: 'charset conversion', test: c => /^\s*(charset|source_charset)\s/m.test(c) },
  { re: /scgi|uwsgi/i, feature: 'SCGI/uWSGI', test: c => /^\s*(scgi_pass|uwsgi_pass)\s/m.test(c) },
  { re: /map and regex/i, feature: 'map with regex', test: c => /\bmap\s+\S+\s+\S+\s*\{[^}]*?(^|\s)~/m.test(c) },
  { re: /resolver/i, feature: 'resolver', test: c => /^\s*resolver\s/m.test(c) },
  { re: /image_filter/i, feature: 'image filter', test: c => /^\s*image_filter\s/m.test(c) },
  { re: /njs/i, feature: 'njs', test: c => /^\s*js_/m.test(c) },
  { re: /realip|ngx_stream|stream module/i, feature: 'stream module', test: c => /^\s*stream\s*\{/m.test(c) },
];

function assessNginx(version, advisories, configText = '') {
  const findings = [];
  for (const a of advisories) {
    const spec = parseRanges(a.vulnerable);
    if (spec.windowsOnly) continue;
    const hit = inRanges(version, spec);
    if (!hit) continue;
    const f = FEATURES.find(x => x.re.test(a.title));
    const used = f ? f.test(configText) : true;
    findings.push({
      id: a.cves[0] || a.title,
      cves: a.cves,
      title: a.title,
      severity: a.severity,
      advisory: a.advisory,
      vulnerable: a.vulnerable,
      fixedIn: fixedFor(version, a.notVulnerable),
      feature: f ? f.feature : null,
      status: a.severity === 'none' ? 'info' : used ? 'affected' : 'not_in_use',
    });
  }
  const order = { major: 0, high: 0, critical: 0, medium: 1, low: 2, minor: 2, none: 3, unknown: 3 };
  const rank = { affected: 0, not_in_use: 1, info: 2 };
  findings.sort((x, y) => (rank[x.status] - rank[y.status]) || (order[x.severity] ?? 3) - (order[y.severity] ?? 3));
  const highest = list => { const v = list.filter(x => x.fixedIn).map(x => parseVersion(x.fixedIn)).sort(cmp).pop(); return v ? v.join('.') : null; };
  return {
    findings,
    upgradeTo: highest(findings.filter(x => x.status === 'affected')),            // fixes what affects this config
    upgradeToAll: highest(findings.filter(x => x.status !== 'info')),             // also the not-in-use ones
  };
}

// ---------------------------------------------------------------------------
// OSV (nginx-agent)
// ---------------------------------------------------------------------------
function osvSeverity(v) {
  const s = (v.database_specific && v.database_specific.severity) || '';
  if (s) return s.toLowerCase();
  const cvss = (v.severity || []).find(x => /CVSS/.test(x.type));
  return cvss ? 'see CVSS' : 'unknown';
}

function osvFixed(v) {
  for (const a of v.affected || []) for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) return e.fixed.replace(/^v/, '');
  return null;
}

function assessOsv(vulns) {
  return (vulns || []).map(v => ({
    id: v.id,
    cves: (v.aliases || []).filter(a => /^CVE-/.test(a)),
    title: v.summary || (v.details || '').split('\n')[0].slice(0, 160) || v.id,
    severity: osvSeverity(v),
    advisory: `https://osv.dev/vulnerability/${v.id}`,
    fixedIn: osvFixed(v),
    status: 'affected',
  }));
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------
class CveScanner extends EventEmitter {
  constructor({ cacheFile = null, fetcher = request } = {}) {
    super();
    this.cacheFile = cacheFile;
    this.fetch = fetcher;
    this.cache = { advisories: null, advisoriesAt: null, osv: {}, errors: {} };
    this.refreshing = null;
    this.load();
  }

  load() {
    if (!this.cacheFile) return;
    try { this.cache = { ...this.cache, ...JSON.parse(fs.readFileSync(this.cacheFile, 'utf8')) }; } catch {}
  }

  save() {
    if (!this.cacheFile) return;
    try {
      fs.writeFileSync(this.cacheFile + '.tmp', JSON.stringify(this.cache));
      fs.renameSync(this.cacheFile + '.tmp', this.cacheFile);
    } catch (err) { console.warn('[nginx-manager] cve: could not save cache:', err.message); }
  }

  stale(at) { return !at || Date.now() - Date.parse(at) > REFRESH_MS; }

  // agentVersions: versions of nginx-agent in use (OSV is queried per version)
  async refresh({ force = false, agentVersions = [] } = {}) {
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      if (force || this.stale(this.cache.advisoriesAt)) {
        try {
          const list = parseAdvisories(await this.fetch(ADVISORIES_URL));
          if (!list.length) throw new Error('no advisories found on the page (format changed?)');
          this.cache.advisories = list;
          this.cache.advisoriesAt = new Date().toISOString();
          delete this.cache.errors.nginx;
        } catch (err) { this.cache.errors.nginx = err.message; }
      }
      for (const raw of new Set(agentVersions.filter(Boolean))) {
        const version = String(raw).replace(/^v/, '');
        const cur = this.cache.osv[version];
        if (!force && cur && !this.stale(cur.at)) continue;
        try {
          const text = await this.fetch(OSV_URL, { method: 'POST', body: JSON.stringify({ package: { name: AGENT_MODULE, ecosystem: 'Go' }, version: `v${version}` }) });
          this.cache.osv[version] = { at: new Date().toISOString(), vulns: JSON.parse(text).vulns || [] };
          delete this.cache.errors.osv;
        } catch (err) { this.cache.errors.osv = err.message; }
      }
      this.save();
      this.emit('change');
    })().finally(() => { this.refreshing = null; });
    return this.refreshing;
  }

  // agent: { id, name, nginxVersion, agentVersion }, configText: all of its nginx config
  assess(agent, configText) {
    const out = { id: agent.id, name: agent.name, nginx: null, agent: null };
    if (agent.nginxVersion && this.cache.advisories) {
      out.nginx = { version: agent.nginxVersion, ...assessNginx(agent.nginxVersion, this.cache.advisories, configText) };
    }
    const av = agent.agentVersion && String(agent.agentVersion).replace(/^v/, '');
    if (av && this.cache.osv[av]) out.agent = { version: av, findings: assessOsv(this.cache.osv[av].vulns) };
    return out;
  }

  sources() {
    const osvAt = Object.values(this.cache.osv).map(x => x.at).sort().pop() || null;
    return {
      nginx: { url: ADVISORIES_URL, at: this.cache.advisoriesAt, count: (this.cache.advisories || []).length, error: this.cache.errors.nginx || null },
      osv: { url: 'https://osv.dev', module: AGENT_MODULE, at: osvAt, error: this.cache.errors.osv || null },
    };
  }
}

module.exports = {
  CveScanner, parseAdvisories, parseRanges, inRanges, fixedFor, assessNginx, assessOsv, parseVersion, FEATURES,
};
