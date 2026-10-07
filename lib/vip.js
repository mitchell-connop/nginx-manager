/**
 * nginx-manager — lib/vip.js
 *
 * Watches a group's virtual IP (keepalived/VRRP) without logging in anywhere:
 *   1. TCP-connect to the VIP and to each member's own address (the IP its agent
 *      connects from) — proves the VIP answers and fills the kernel ARP cache.
 *   2. keepalived announces the VIP from the holder's own interface, so the VIP's
 *      MAC in /proc/net/arp equals the MAC of whichever member currently holds it.
 * Holder detection needs the manager on the same L2 segment as the members; otherwise
 * only reachability is reported.
 */

'use strict';

const fs  = require('fs');
const net = require('net');
const EventEmitter = require('events');

const PROBE_TIMEOUT_MS = 1500;

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
function resolveHolder({ vip, vipProbe, arp, members }) {
  const vipMac = arp.get(vip) || null;
  const holders = vipMac ? members.filter(m => m.address && arp.get(m.address) === vipMac) : [];
  return {
    reachable: !!vipProbe.ok,
    latencyMs: vipProbe.ok ? vipProbe.ms : null,
    error: vipProbe.ok ? null : vipProbe.error,
    vipMac,
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
      ...members.filter(m => m.address).map(m => tcpProbe(m.address, port)),
    ]);
    const result = resolveHolder({ vip: group.vip, vipProbe, arp: readArp(this.arpPath), members });
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
    const changed = !prev || ['reachable', 'holderId', 'vipMac', 'vip'].some(k => prev[k] !== status[k]) ||
      JSON.stringify(prev.conflict) !== JSON.stringify(status.conflict);
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

module.exports = { VipMonitor, resolveHolder, readArp, tcpProbe };
