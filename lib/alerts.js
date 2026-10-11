/**
 * nginx-manager — lib/alerts.js
 *
 * Notifications by email (SMTP) and/or webhooks. Settings in data/alerts.json (mode 0600; the
 * SMTP password and webhook headers are never sent back to the browser). Every alert also goes
 * to data/alert-history.json so the UI can show what was sent.
 *
 * Events (each can be switched off):
 *   vip_failover, agent_offline (+ recovery), apply_failed, cert_failed, cert_expiring,
 *   cve_new, backend_down (+ recovery), error_spike, denied_spike, drift
 *
 * The same key (event + subject) is not re-sent within the cool-down, so a flapping backend or
 * a sustained spike produces one message, not hundreds. Recoveries are always sent.
 */

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const { EventEmitter } = require('events');

const EVENTS = {
  vip_failover:  { label: 'VIP failover', severity: 'warning' },
  agent_offline: { label: 'Server offline / back online', severity: 'critical' },
  apply_failed:  { label: 'Config apply failed', severity: 'critical' },
  cert_failed:   { label: 'Certificate renewal failed', severity: 'critical' },
  cert_expiring: { label: 'Certificate expiring soon', severity: 'warning' },
  cve_new:       { label: 'New CVE affecting a server', severity: 'warning' },
  backend_down:  { label: 'Backend down / recovered', severity: 'critical' },
  error_spike:   { label: '5xx error spike', severity: 'warning' },
  denied_spike:  { label: 'Denied-request spike', severity: 'info' },
  drift:         { label: 'Group config drift', severity: 'warning' },
  test:          { label: 'Test', severity: 'info' },
};

const DEFAULTS = {
  email: { enabled: false, host: '', port: 587, security: 'starttls', user: '', pass: '', from: '', to: [] },
  webhooks: [],
  events: Object.fromEntries(Object.keys(EVENTS).filter(k => k !== 'test').map(k => [k, true])),
  thresholds: { certDays: 14, errorPct: 10, deniedPct: 25, minRequests: 50, windowMin: 5, offlineMin: 2, driftMin: 15 },
  cooldownMin: 60,
};

const WEBHOOK_FORMATS = ['json', 'slack', 'discord', 'ntfy', 'teams'];

function clone(o) { return JSON.parse(JSON.stringify(o)); }

function request(url, { method = 'POST', headers = {}, body = '', timeout = 10000 }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method, timeout, headers: { 'Content-Length': Buffer.byteLength(body), ...headers } }, res => {
      res.resume();
      res.on('end', () => (res.statusCode < 300 ? resolve(res.statusCode) : reject(new Error(`HTTP ${res.statusCode}`))));
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    req.end(body);
  });
}

function webhookBody(format, a) {
  const line = `${a.severity === 'critical' ? '🔴' : a.severity === 'warning' ? '🟠' : a.severity === 'ok' ? '🟢' : '🔵'} ${a.title}`;
  switch (format) {
    case 'slack': return { type: 'application/json', body: JSON.stringify({ text: `*${line}*\n${a.message}` }) };
    case 'discord': return { type: 'application/json', body: JSON.stringify({ content: `**${line}**\n${a.message}`.slice(0, 1990) }) };
    case 'teams': return { type: 'application/json', body: JSON.stringify({ text: `**${line}**\n\n${a.message}` }) };
    case 'ntfy': return {
      type: 'text/plain; charset=utf-8', body: a.message,
      headers: { Title: a.title.replace(/[^\x20-\x7E]/g, ''), Priority: a.severity === 'critical' ? '5' : a.severity === 'warning' ? '4' : '3', Tags: a.event },
    };
    default: return { type: 'application/json', body: JSON.stringify({ source: 'nginx-manager', ...a }) };
  }
}

class Alerts extends EventEmitter {
  constructor({ file, historyFile, stateFile = null, mailer = null }) {
    super();
    this.file = file;
    this.historyFile = historyFile;
    this.stateFile = stateFile;      // cool-down memory survives restarts (no re-alert storm on boot)
    this.mailer = mailer;            // injectable for tests: async ({ settings, subject, text }) => void
    this.sent = new Map();           // key -> last sent ms (cool-down; presence = "alerting" for recoveries)
    try { this.sent = new Map(Object.entries(JSON.parse(fs.readFileSync(stateFile, 'utf8')))); } catch {}
    this.settings = this.load();
  }

  saveState() {
    if (!this.stateFile) return;
    try { fs.writeFileSync(this.stateFile, JSON.stringify(Object.fromEntries(this.sent)), { mode: 0o600 }); } catch {}
  }

  load() {
    let s = {};
    try { s = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch {}
    const d = clone(DEFAULTS);
    return {
      email: { ...d.email, ...(s.email || {}) },
      webhooks: Array.isArray(s.webhooks) ? s.webhooks : [],
      events: { ...d.events, ...(s.events || {}) },
      thresholds: { ...d.thresholds, ...(s.thresholds || {}) },
      cooldownMin: s.cooldownMin || d.cooldownMin,
    };
  }

  save() {
    fs.writeFileSync(this.file + '.tmp', JSON.stringify(this.settings, null, 2), { mode: 0o600 });
    fs.renameSync(this.file + '.tmp', this.file);
  }

  // Browser view: secrets replaced by flags
  view() {
    const s = clone(this.settings);
    s.email.passSet = !!s.email.pass; s.email.pass = '';
    s.webhooks = s.webhooks.map(w => ({ ...w, headers: Object.fromEntries(Object.keys(w.headers || {}).map(k => [k, '••••'])) }));
    return { ...s, catalog: Object.fromEntries(Object.entries(EVENTS).filter(([k]) => k !== 'test').map(([k, v]) => [k, v.label])), formats: WEBHOOK_FORMATS };
  }

  update(input) {
    const cur = this.settings;
    const next = clone(cur);
    const err = m => Object.assign(new Error(m), { status: 400 });
    if (input.email) {
      const e = input.email;
      next.email = {
        enabled: !!e.enabled,
        host: String(e.host || '').trim(),
        port: parseInt(e.port, 10) || 587,
        security: ['starttls', 'tls', 'none'].includes(e.security) ? e.security : 'starttls',
        user: String(e.user || '').trim(),
        pass: e.pass ? String(e.pass) : (e.clearPass ? '' : cur.email.pass),     // blank keeps the stored one
        from: String(e.from || '').trim(),
        to: (Array.isArray(e.to) ? e.to : String(e.to || '').split(/[\s,;]+/)).map(x => x.trim()).filter(Boolean),
      };
      if (next.email.enabled) {
        if (!/^[A-Za-z0-9.-]+$/.test(next.email.host)) throw err('SMTP host is required');
        if (!/^[^\s@]+@[^\s@]+$/.test(next.email.from.replace(/^.*<(.+)>$/, '$1'))) throw err('From address is required');
        if (!next.email.to.length || next.email.to.some(t => !/^[^\s@]+@[^\s@]+$/.test(t))) throw err('At least one valid recipient is required');
      }
    }
    if (input.webhooks) {
      if (!Array.isArray(input.webhooks) || input.webhooks.length > 20) throw err('webhooks must be a list (max 20)');
      next.webhooks = input.webhooks.map((w, i) => {
        let u;
        try { u = new URL(String(w.url || '')); } catch { throw err(`Webhook ${i + 1}: invalid URL`); }
        if (!/^https?:$/.test(u.protocol)) throw err(`Webhook ${i + 1}: URL must be http(s)`);
        const prev = cur.webhooks.find(x => x.id === w.id) || {};
        const headers = {};
        for (const [k, v] of Object.entries(w.headers || {})) {
          if (!/^[A-Za-z0-9-]{1,64}$/.test(k)) throw err(`Webhook ${i + 1}: bad header name ${k}`);
          headers[k] = v === '••••' && prev.headers ? prev.headers[k] : String(v);   // masked = unchanged
          if (/[\r\n]/.test(headers[k] || '')) throw err(`Webhook ${i + 1}: bad header value`);
        }
        return {
          id: w.id || `wh-${Date.now().toString(36)}-${i}`,
          name: String(w.name || u.hostname).slice(0, 60),
          url: u.toString(),
          format: WEBHOOK_FORMATS.includes(w.format) ? w.format : 'json',
          enabled: w.enabled !== false,
          headers,
        };
      });
    }
    if (input.events) for (const k of Object.keys(next.events)) if (input.events[k] !== undefined) next.events[k] = !!input.events[k];
    if (input.thresholds) {
      const lim = { certDays: [1, 90], errorPct: [1, 100], deniedPct: [1, 100], minRequests: [1, 100000], windowMin: [1, 60], offlineMin: [1, 120], driftMin: [1, 1440] };
      for (const [k, [lo, hi]] of Object.entries(lim)) {
        if (input.thresholds[k] === undefined) continue;
        const v = Number(input.thresholds[k]);
        if (!(v >= lo && v <= hi)) throw err(`${k} must be ${lo}-${hi}`);
        next.thresholds[k] = v;
      }
    }
    if (input.cooldownMin !== undefined) {
      const v = Number(input.cooldownMin);
      if (!(v >= 1 && v <= 1440)) throw err('cool-down must be 1-1440 minutes');
      next.cooldownMin = v;
    }
    this.settings = next;
    this.save();
    return this.view();
  }

  history(limit = 100) {
    try { return JSON.parse(fs.readFileSync(this.historyFile, 'utf8')).slice(-limit).reverse(); } catch { return []; }
  }

  addHistory(entry) {
    let list = [];
    try { list = JSON.parse(fs.readFileSync(this.historyFile, 'utf8')); } catch {}
    list.push(entry);
    if (list.length > 500) list = list.slice(-500);
    try { fs.writeFileSync(this.historyFile, JSON.stringify(list), { mode: 0o600 }); } catch {}
  }

  /**
   * notify({ event, key, title, message, severity?, server?, group?, recovery?, remindMin? })
   * key identifies the subject for the cool-down (e.g. "backend_down:lb-01:10.0.0.5:8096").
   */
  async notify(a) {
    const s = this.settings;
    if (a.event !== 'test' && !s.events[a.event]) return { skipped: 'disabled' };
    const key = a.key || `${a.event}:${a.title}`;
    const now = Date.now();
    // remindMin: for lasting conditions (CVE, expiring cert, server offline) — how long before repeating
    const quiet = (a.remindMin || s.cooldownMin) * 60e3;
    if (!a.recovery && a.event !== 'test' && this.sent.has(key) && now - this.sent.get(key) < quiet) return { skipped: 'cooldown' };
    if (a.recovery && !this.sent.has(key)) return { skipped: 'no prior alert' };       // only "recovered" what we reported
    if (a.recovery) this.sent.delete(key); else this.sent.set(key, now);
    this.saveState();

    const alert = {
      event: a.event, severity: a.recovery ? 'ok' : (a.severity || (EVENTS[a.event] || {}).severity || 'info'),
      title: a.title, message: a.message || '', server: a.server || null, group: a.group || null, at: new Date().toISOString(),
    };
    const results = [];
    if (s.email.enabled && s.email.host && s.email.to.length) {
      try { await this.sendEmail(alert); results.push({ channel: 'email', ok: true }); }
      catch (e) { results.push({ channel: 'email', ok: false, error: e.message }); }
    }
    for (const w of s.webhooks.filter(x => x.enabled)) {
      try {
        const b = webhookBody(w.format, alert);
        await request(w.url, { headers: { 'Content-Type': b.type, 'User-Agent': 'nginx-manager', ...(b.headers || {}), ...(w.headers || {}) }, body: b.body });
        results.push({ channel: w.name, ok: true });
      } catch (e) { results.push({ channel: w.name, ok: false, error: e.message }); }
    }
    for (const r of results.filter(x => !x.ok)) console.warn(`[nginx-manager] alert via ${r.channel} failed: ${r.error}`);
    this.addHistory({ ...alert, results });
    this.emit('sent', { ...alert, results });
    return { alert, results };
  }

  async sendEmail(alert) {
    const subject = `[nginx-manager] ${alert.severity === 'ok' ? 'RESOLVED: ' : ''}${alert.title}`;
    const text = `${alert.message}\n\n${alert.server ? `Server: ${alert.server}\n` : ''}${alert.group ? `Group: ${alert.group}\n` : ''}Time: ${alert.at}\n`;
    if (this.mailer) return this.mailer({ settings: this.settings.email, subject, text });
    const nodemailer = require('nodemailer');
    const e = this.settings.email;
    const transport = nodemailer.createTransport({
      host: e.host, port: e.port,
      secure: e.security === 'tls',
      requireTLS: e.security === 'starttls',
      ignoreTLS: e.security === 'none',
      auth: e.user ? { user: e.user, pass: e.pass } : undefined,
      connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 20000,
    });
    await transport.sendMail({ from: e.from, to: e.to.join(', '), subject, text });
  }
}

module.exports = { Alerts, EVENTS, DEFAULTS, WEBHOOK_FORMATS, webhookBody };
