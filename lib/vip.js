/**
 * nginx-manager — lib/vip.js
 *
 * Watches a group's virtual IP (keepalived/VRRP) without logging in anywhere:
 *   1. TCP-connect to the VIP — proves it answers from the manager's side.
 *   2. Who holds it, from the data plane: the keepalived forwarder on each server
 *      (lib/logrx keepalivedForwarderScript) reports every 10 s which addresses are on
 *      its interfaces and whether keepalived is running (syslog tag keepalived_state).
 *      The member with the VIP on an interface is the holder — works across VLANs/routers.
 *   3. Fallback when no member has reported recently: keepalived announces the VIP from
 *      the holder's own interface, so the VIP's MAC in /proc/net/arp equals the MAC of
 *      the member holding it. Only works with the manager on the members' L2 segment.
 */

'use strict';

const fs  = require('fs');
const net = require('net');
const EventEmitter = require('events');

const PROBE_TIMEOUT_MS = 1500;
const REPORT_FRESH_MS = 45000;     // keepalived_state reports arrive every 10 s

function tcpProbe(host, port, timeout = PROBE_TIMEOUT_MS) {
  return new Promise(resolve => {
    const started = Date.now();
    const sock = net.connect({ host, port, timeout });
    const done = r => { sock.destroy(); resolve(r); };
    sock.on('connect', () => done({ ok: true, ms: Date.now() - started }));
    sock.on('timeout', () => done({ ok: false, error: 'timeout' }));
    sock.on('error', err => done({ ok: false, error: err.code || err.message }));
  });
}

// /proc/net/arp → Map(ip -> mac) for complete entries (flags 0x2)
function readArp(path = '/proc/net/arp') {
  const out = new Map();
  let text;
  try { text = fs.readFileSync(path, 'utf8'); } catch { return out; }
  for (const line of text.split('\n').slice(1)) {
    const [ip, , flags, mac] = line.trim().split(/\s+/);
    if (ip && mac && flags === '0x2' && mac !== '00:00:00:00:00:00') out.set(ip, mac.toLowerCase());
  }
  return out;
}

// Pure decision from probe results — kept separate so it can be unit-tested.
//   members: [{ id, name, address }]
//   reports: Map(agentId -> { at: ms, addrs: [ip], keepalived: 'active'|'inactive'|… }) from the servers
function resolveHolder({ vip, vipProbe, arp, members, reports = new Map(), now = Date.now() }) {
  const fresh = members.map(m => ({ m, r: reports.get(m.id) })).filter(x => x.r && now - x.r.at < REPORT_FRESH_MS);
  const vipMac = arp.get(vip) || null;
  let holders, source;
  if (fresh.length) {
    source = 'keepalived';
    holders = fresh.filter(x => x.r.addrs.includes(vip)).map(x => x.m);
  } else {
    source = vipMac ? 'arp' : null;
    holders = vipMac ? members.filter(m => m.address && arp.get(m.address) === vipMac) : [];
  }
  return {
    reachable: !!vipProbe.ok,
    latencyMs: vipProbe.ok ? vipProbe.ms : null,
    error: vipProbe.ok ? null : vipProbe.error,
    vipMac,
    source,
    // per-member view from the keepalived reports (empty when none are coming in)
    members: fresh.map(({ m, r }) => ({ name: m.name, keepalived: r.keepalived, holds: r.addrs.includes(vip) })),
    holderId: holders.length === 1 ? holders[0].id : null,
    holderName: holders.length === 1 ? holders[0].name : null,
    // more than one member answering for the VIP = split brain
    conflict: holders.length > 1 ? holders.map(h => h.name) : null,
  };
}

class VipMonitor extends EventEmitter {
  constructor({ getGroups, getMembers, intervalMs = 15000, arpPath }) {
    super();
    this.getGroups = getGroups;     // () => [{ name, vip, port }]
    this.getMembers = getMembers;   // groupName => [{ id, name, address }]
    this.intervalMs = intervalMs;
    this.arpPath = arpPath;
    this.status = new Map();        // group name -> status
    this.reports = new Map();       // agentId -> { at, addrs, keepalived } (keepalived_state)
  }

  // from the keepalived forwarder on a server; re-checks that server's group straight away
  // when what it holds (or keepalived's state) changes, so failover shows within seconds
  report(agentId, msg, groupOf) {
    if (!msg || !Array.isArray(msg.addrs)) return;
    const addrs = msg.addrs.filter(a => typeof a === 'string' && a.length <= 45).slice(0, 256);
    const keepalived = String(msg.keepalived || 'unknown').slice(0, 20);
    const prev = this.reports.get(agentId);
    this.reports.set(agentId, { at: Date.now(), addrs, keepalived });
    if (prev && prev.keepalived === keepalived && prev.addrs.join() === addrs.join()) return;
    const name = groupOf && groupOf(agentId);
    const group = name && this.getGroups().find(g => g.name === name && g.vip);
    if (group) this.check(group).catch(() => {});
  }

  start() {
    this.tick();
    this.timer = setInterval(() => this.tick(), this.intervalMs);
    this.timer.unref();
  }

  stop() { clearInterval(this.timer); }

  async check(group) {
    const port = group.port || 443;
    const members = this.getMembers(group.name);
    const [vipProbe] = await Promise.all([
      tcpProbe(group.vip, port),
      // only for the ARP fallback: connecting to each member fills the ARP cache
      ...members.filter(m => m.address && !this.reports.has(m.id)).map(m => tcpProbe(m.address, port)),
    ]);
    const result = resolveHolder({ vip: group.vip, vipProbe, arp: readArp(this.arpPath), members, reports: this.reports });
    const prev = this.status.get(group.name);
    const now = new Date().toISOString();
    const status = {
      vip: group.vip, port, ...result, checkedAt: now,
      holderSince: prev && prev.vip === group.vip && prev.holderId === result.holderId ? prev.holderSince : now,
      previousHolder: prev && prev.holderId !== result.holderId ? prev.holderName : (prev && prev.previousHolder) || null,
    };
    if (prev && prev.holderId && result.holderId && prev.holderId !== result.holderId) {
      this.emit('failover', { group: group.name, from: prev.holderName, to: result.holderName, at: now });
    }
    const changed = !prev || ['reachable', 'holderId', 'vipMac', 'vip', 'source'].some(k => prev[k] !== status[k]) ||
      JSON.stringify(prev.conflict) !== JSON.stringify(status.conflict) || JSON.stringify(prev.members) !== JSON.stringify(status.members);
    this.status.set(group.name, status);
    if (changed) this.emit('change', group.name, status);
    return status;
  }

  async tick() {
    const groups = this.getGroups().filter(g => g.vip);
    for (const name of [...this.status.keys()]) {
      if (!groups.some(g => g.name === name)) { this.status.delete(name); this.emit('change', name, null); }
    }
    await Promise.all(groups.map(g => this.check(g).catch(() => {})));
  }
}

module.exports = { VipMonitor, resolveHolder, readArp, tcpProbe, REPORT_FRESH_MS };
