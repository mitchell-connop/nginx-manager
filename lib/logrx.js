/**
 * nginx-manager — lib/logrx.js
 *
 * Remote log receiver: a small UDP syslog listener that the managed servers stream to.
 *
 *   nginx       access_log syslog:server=<manager>:5514,tag=nginx nm_json;   (JSON lines, see LOG_FORMAT)
 *   keepalived  journalctl -u keepalived -f -o short-iso | logger --udp -n <manager> -P 5514 -t keepalived
 *
 * Packets are attributed to an agent by source address and dropped when the source
 * isn't a known agent. Entries live in a ring buffer per agent and kind and are batched
 * to listeners every BATCH_MS. Keepalived entries (rare, and the history matters) are also
 * saved to persistDir so they survive a restart; request logs are memory only.
 */

'use strict';

const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const DEFAULT_PORT = 5514;
const BATCH_MS = 500;
const LIMITS = { access: 2000, keepalived: 500 };

// Query strings are deliberately left out ($uri, not $request): they often carry tokens.
const LOG_FORMAT_NAME = 'nm_json';
const LOG_FORMAT = `log_format ${LOG_FORMAT_NAME} escape=json '{"t":"$time_iso8601","c":"$remote_addr","u":"$remote_user",' ` +
  `'"h":"$host","p":"$server_port","m":"$request_method","r":"$uri","v":"$server_protocol","s":"$status",' ` +
  `'"b":"$body_bytes_sent","rt":"$request_time","up":"$upstream_addr","us":"$upstream_status",' ` +
  `'"ut":"$upstream_response_time","tls":"$ssl_protocol","ua":"$http_user_agent"}';`;

// Stream (TCP/UDP) sessions — logged when the session ends
const STREAM_FORMAT_NAME = 'nm_stream_json';
const STREAM_LOG_FORMAT = `log_format ${STREAM_FORMAT_NAME} escape=json '{"t":"$time_iso8601","c":"$remote_addr","p":"$server_port",' ` +
  `'"proto":"$protocol","s":"$status","b":"$bytes_sent","bi":"$bytes_received","st":"$session_time",' ` +
  `'"up":"$upstream_addr","uc":"$upstream_connect_time"}';`;

// <PRI>Mmm dd hh:mm:ss host tag[pid]: msg   (RFC 3164, as sent by nginx and util-linux logger)
const RFC3164 = /^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?([\s\S]*)$/;
// journalctl -o short-iso:  2026-10-11T06:00:00+0000 host Proc[pid]: text
const SHORT_ISO = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:[+-]\d\d:?\d\d|Z)?) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ([\s\S]*)$/;

function parseSyslog(text) {
  const m = String(text).replace(/\r?\n$/, '').match(RFC3164);
  if (!m) return null;
  return { pri: Number(m[1]), stamp: m[2], host: m[3], tag: m[4], msg: m[5] };
}

// allowed | denied | client_error | server_error
function classify(status, method) {
  const s = Number(status) || 0;
  if ([401, 403, 407, 429, 444, 495, 496, 497].includes(s)) return 'denied';
  if (s >= 500) return 'server_error';
  if (s >= 400) return 'client_error';
  if (s >= 100) return 'allowed';
  return method ? 'client_error' : 'server_error';
}

const dash = v => (v === undefined || v === null || v === '' || v === '-' ? '' : String(v));
const num = v => { const n = parseFloat(v); return Number.isFinite(n) ? n : null; };

function parseAccess(msg, receivedAt) {
  let j;
  try { j = JSON.parse(msg); } catch { return null; }
  if (!j || typeof j !== 'object') return null;
  const status = parseInt(j.s, 10) || 0;
  const method = dash(j.m);
  return {
    at: dash(j.t) || receivedAt,
    client: dash(j.c),
    user: dash(j.u),
    host: dash(j.h),
    port: dash(j.p),
    method,
    uri: dash(j.r),
    protocol: dash(j.v),
    status,
    bytes: parseInt(j.b, 10) || 0,
    time: num(j.rt),
    upstream: dash(j.up),
    upstreamStatus: dash(j.us),
    upstreamTime: dash(j.ut),
    tls: dash(j.tls),
    userAgent: dash(j.ua).slice(0, 300),
    result: classify(status, method),
  };
}

function parseStream(msg, receivedAt) {
  let j;
  try { j = JSON.parse(msg); } catch { return null; }
  if (!j || typeof j !== 'object') return null;
  const status = parseInt(j.s, 10) || 0;
  return {
    at: dash(j.t) || receivedAt,
    client: dash(j.c),
    user: '',
    host: '',
    port: dash(j.p),
    method: dash(j.proto) || 'TCP',
    uri: '',
    protocol: 'stream',
    status,
    bytes: parseInt(j.b, 10) || 0,
    bytesIn: parseInt(j.bi, 10) || 0,
    time: num(j.st),
    upstream: dash(j.up),
    upstreamStatus: '',
    upstreamTime: dash(j.uc),
    tls: '',
    userAgent: '',
    stream: true,
    result: classify(status, 'TCP'),
  };
}

function keepalivedLevel(text) {
  if (/Entering MASTER STATE/i.test(text)) return 'master';
  if (/Entering BACKUP STATE/i.test(text)) return 'backup';
  if (/Entering FAULT STATE|Stopped|Stopping|stopped|exited|failed|cannot|Disabling|error/i.test(text)) return 'warn';
  return 'info';
}

function parseKeepalived(msg, receivedAt) {
  const m = msg.match(SHORT_ISO);
  const at = m ? new Date(m[1].replace(/([+-]\d\d)(\d\d)$/, '$1:$2')) : null;
  return {
    at: at && !isNaN(at) ? at.toISOString() : receivedAt,
    process: m ? m[3] : 'keepalived',
    text: (m ? m[4] : msg).slice(0, 2000),
    level: keepalivedLevel(m ? m[4] : msg),
    stamped: !!m,
  };
}

class LogReceiver extends EventEmitter {
  /**
   * @param {object} o
   * @param {number} [o.port]
   * @param {(address: string) => string|null} o.resolveAgent  source IP -> agent id
   */
  constructor({ port = DEFAULT_PORT, host = '0.0.0.0', resolveAgent, limits = {}, persistDir = null } = {}) {
    super();
    this.persistDir = persistDir;
    this.port = port;
    this.host = host;
    this.resolveAgent = resolveAgent || (() => null);
    this.limits = { ...LIMITS, ...limits };
    this.buffers = new Map();     // `${agentId}:${kind}` -> entries[]
    this.seen = new Map();        // agentId -> Set of keepalived keys (dedupe journal replays)
    this.lastAt = new Map();      // `${agentId}:${kind}` -> ISO time of last entry
    this.pending = new Map();     // `${agentId}:${kind}` -> entries awaiting the next batch
    this.unknown = new Set();
    this.socket = null;
    this.timer = null;
  }

  load() {
    if (!this.persistDir) return;
    let names = [];
    try { names = fs.readdirSync(this.persistDir); } catch { return; }
    for (const name of names) {
      const m = name.match(/^(.+)-keepalived\.json$/);
      if (!m) continue;
      try {
        const entries = JSON.parse(fs.readFileSync(path.join(this.persistDir, name), 'utf8'));
        if (!Array.isArray(entries)) continue;
        this.buffers.set(`${m[1]}:keepalived`, entries.slice(-this.limits.keepalived));
        this.seen.set(m[1], new Set(entries.filter(e => e.stamped).map(e => `${e.at}|${e.process}|${e.text}`)));
      } catch {}
    }
  }

  save(agentId) {
    if (!this.persistDir || !/^[A-Za-z0-9_-]+$/.test(agentId)) return;
    try {
      fs.mkdirSync(this.persistDir, { recursive: true });
      const file = path.join(this.persistDir, `${agentId}-keepalived.json`);
      fs.writeFileSync(file + '.tmp', JSON.stringify(this.entries(agentId, 'keepalived')));
      fs.renameSync(file + '.tmp', file);
    } catch (err) { console.warn('[nginx-manager] log receiver: could not save keepalived log:', err.message); }
  }

  start() {
    this.load();
    return new Promise((resolve, reject) => {
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: false });
      sock.once('error', reject);
      sock.on('message', (buf, rinfo) => this.receive(buf.toString('utf8'), rinfo.address));
      sock.bind(this.port, this.host, () => {
        sock.removeListener('error', reject);
        sock.on('error', err => console.warn('[nginx-manager] log receiver:', err.message));
        this.socket = sock;
        this.port = sock.address().port;
        this.timer = setInterval(() => this.flush(), BATCH_MS);
        this.timer.unref();
        resolve(this.port);
      });
    });
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.socket) { try { this.socket.close(); } catch {} }
    this.socket = null;
  }

  receive(text, address) {
    const agentId = this.resolveAgent(String(address).replace(/^::ffff:/, ''));
    if (!agentId) {
      if (!this.unknown.has(address) && this.unknown.size < 100) {
        this.unknown.add(address);
        console.warn(`[nginx-manager] log receiver: ignoring syslog from ${address} (not a known agent address)`);
      }
      return null;
    }
    const s = parseSyslog(text);
    if (!s) return null;
    const receivedAt = new Date().toISOString();
    if (s.tag === 'nginx_health') {
      // nginx-manager helper: backend probe results + stub_status (lib/health)
      let j; try { j = JSON.parse(s.msg); } catch { return null; }
      this.emit('health', agentId, j);
      return null;
    }
    if (/^nginx/.test(s.tag) && s.msg.startsWith('{')) {
      const e = s.tag === 'nginx_stream' ? parseStream(s.msg, receivedAt) : parseAccess(s.msg, receivedAt);
      return e ? this.push(agentId, 'access', e) : null;
    }
    if (s.tag === 'keepalived_state') {
      // the forwarder's 10-second report: addresses on the server's interfaces + keepalived's state (lib/vip)
      let j; try { j = JSON.parse(s.msg); } catch { return null; }
      this.emit('vrrp', agentId, j);
      return null;
    }
    if (/keepalived/i.test(s.tag)) {
      const e = parseKeepalived(s.msg, receivedAt);
      if (e.stamped) {
        // the forwarder replays recent journal lines whenever it (re)starts
        const key = `${e.at}|${e.process}|${e.text}`;
        let seen = this.seen.get(agentId);
        if (!seen) this.seen.set(agentId, seen = new Set());
        if (seen.has(key)) return null;
        seen.add(key);
        if (seen.size > this.limits.keepalived * 2) seen.delete(seen.values().next().value);
      }
      return this.push(agentId, 'keepalived', e);
    }
    return null;
  }

  push(agentId, kind, entry) {
    const k = `${agentId}:${kind}`;
    let buf = this.buffers.get(k);
    if (!buf) this.buffers.set(k, buf = []);
    buf.push(entry);
    if (buf.length > this.limits[kind]) buf.splice(0, buf.length - this.limits[kind]);
    this.lastAt.set(k, new Date().toISOString());
    let p = this.pending.get(k);
    if (!p) this.pending.set(k, p = []);
    p.push(entry);
    return entry;
  }

  flush() {
    for (const [k, entries] of this.pending) {
      if (!entries.length) continue;
      const i = k.lastIndexOf(':');
      const agentId = k.slice(0, i), kind = k.slice(i + 1);
      if (kind === 'keepalived') this.save(agentId);
      this.emit('entries', { agentId, kind, entries });
    }
    this.pending.clear();
  }

  entries(agentId, kind, limit) {
    const buf = this.buffers.get(`${agentId}:${kind}`) || [];
    return limit ? buf.slice(-limit) : buf.slice();
  }

  stats(agentId) {
    const out = {};
    for (const kind of Object.keys(LIMITS)) {
      out[kind] = { count: (this.buffers.get(`${agentId}:${kind}`) || []).length, lastAt: this.lastAt.get(`${agentId}:${kind}`) || null };
    }
    return out;
  }

  clear(agentId, kind) {
    this.buffers.delete(`${agentId}:${kind}`);
    if (kind === 'keepalived') this.save(agentId);
  }
}

// ---------------------------------------------------------------------------
// Files deployed to the nginx server
// ---------------------------------------------------------------------------
function remoteLogPaths(nginxDir) {
  return {
    conf: `${nginxDir}/conf.d/00-nginx-manager-logging.conf`,
    inc: `${nginxDir}/nginx-manager/remote-log.inc`,
    streamInc: `${nginxDir}/nginx-manager/remote-stream-log.inc`,
  };
}

// Glob so the include is a no-op until remote logging is enabled (no match is not an error).
function remoteLogInclude(nginxDir) {
  return `${nginxDir}/nginx-manager/remote-log[.]inc`;
}

// stream: also the stream-context file (only once nginx.conf has a stream {} block that includes it,
// otherwise nothing references it and the agent wouldn't track it)
function remoteLogFiles(nginxDir, receiver, port = DEFAULT_PORT, { stream = false } = {}) {
  const p = remoteLogPaths(nginxDir);
  const target = receiver.includes(':') ? `[${receiver}]:${port}` : `${receiver}:${port}`;
  return {
    ...(stream ? { [p.streamInc]: [
      '# Managed by nginx-manager: streams TCP/UDP session logs to the manager (Log tab → Connections).',
      '# Included in the stream {} block of nginx.conf.',
      STREAM_LOG_FORMAT,
      `access_log syslog:server=${target},tag=nginx_stream,severity=info ${STREAM_FORMAT_NAME};`,
      '',
    ].join('\n') } : {}),
    [p.conf]: [
      '# Managed by nginx-manager: streams a request log to the manager (Log tab → Connections).',
      '# Disable it there rather than editing this file. The local access.log is unaffected.',
      LOG_FORMAT,
      `include ${p.inc};`,
      '',
    ].join('\n'),
    [p.inc]: [
      '# Managed by nginx-manager. Also included by servers that set their own access_log',
      '# (forward proxies), which would otherwise not inherit it.',
      `access_log syslog:server=${target},tag=nginx,severity=info ${LOG_FORMAT_NAME};`,
      '',
    ].join('\n'),
  };
}

// systemd unit shipping keepalived's journal to the manager (the agent can't manage files outside nginx's dirs),
// plus a report every 10 s of the addresses on the server's interfaces, so the manager knows which server holds
// the VIP without sharing its subnet (lib/vip). Needs only sh, awk, ip, journalctl and util-linux logger —
// present on Debian/Ubuntu and RHEL/Rocky/Alma alike.
const KA_SCRIPT = [
  '#!/bin/sh',
  '# nginx-manager keepalived forwarder — usage: nm-keepalived.sh <manager> <udp port>',
  'H="$1"; P="$2"',
  'send() { logger --udp --rfc3164 -n "$H" -P "$P" "$@"; }',
  '(',
  '  while :; do',
  `    A=$(ip -o -4 addr show 2>/dev/null | awk '{ split($4, a, "/"); printf "%s\\"%s\\"", (n++ ? "," : ""), a[1] }')`,
  '    # pidof, not systemctl: an unprivileged systemctl needs D-Bus, which minimal containers often lack',
  '    if command -v pidof >/dev/null; then pidof keepalived >/dev/null && S=active || S=inactive; else S=$(systemctl is-active keepalived 2>/dev/null || true); fi',
  '    send -t keepalived_state "{\\"v\\":1,\\"keepalived\\":\\"${S:-unknown}\\",\\"addrs\\":[${A}]}"',
  '    sleep 10',
  '  done',
  ') &',
  'journalctl -u keepalived -f -n 200 -o short-iso | send -t keepalived',
].join('\n');

function keepalivedForwarderScript(receiver, port = DEFAULT_PORT) {
  return [
    '#!/bin/bash',
    '# Run as root on each keepalived server (Debian/Ubuntu or RHEL/Rocky/Alma): forwards keepalived journal',
    '# lines to nginx-manager and reports which server holds the VIP',
    'set -euo pipefail',
    'install -d -m 755 /usr/local/lib/nginx-manager',
    "cat > /usr/local/lib/nginx-manager/nm-keepalived.sh <<'NMKA'",
    KA_SCRIPT,
    'NMKA',
    'chmod 755 /usr/local/lib/nginx-manager/nm-keepalived.sh',
    "cat > /etc/systemd/system/nginx-manager-keepalived-log.service <<'EOF'",
    '[Unit]',
    'Description=Forward keepalived logs and VIP state to nginx-manager',
    'After=network-online.target keepalived.service',
    'Wants=network-online.target',
    '',
    '[Service]',
    `ExecStart=/bin/sh /usr/local/lib/nginx-manager/nm-keepalived.sh ${receiver} ${port}`,
    'Restart=always',
    'RestartSec=5',
    'DynamicUser=yes',
    'SupplementaryGroups=systemd-journal',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    'EOF',
    'systemctl daemon-reload',
    'systemctl enable --now nginx-manager-keepalived-log.service',
    'systemctl restart nginx-manager-keepalived-log.service',
    'systemctl --no-pager --lines=0 status nginx-manager-keepalived-log.service',
  ].join('\n') + '\n';
}

module.exports = {
  LogReceiver, DEFAULT_PORT, LOG_FORMAT, LOG_FORMAT_NAME,
  parseSyslog, parseAccess, parseStream, parseKeepalived, classify,
  remoteLogPaths, remoteLogFiles, remoteLogInclude, keepalivedForwarderScript,
};
