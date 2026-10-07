'use strict';

const test   = require('node:test');
const assert = require('node:assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const { resolveHolder, readArp } = require('../lib/vip');

process.env.DATA_DIR = process.env.DATA_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'nm-vip-'));
const { peerAddress } = require('../lib/mpi');

const members = [
  { id: 'a', name: 'lb-a', address: '192.0.2.51' },
  { id: 'b', name: 'lb-b', address: '192.0.2.52' },
];
const up = { ok: true, ms: 3 };

test('holder is the member whose MAC answers for the VIP', () => {
  const arp = new Map([['192.0.2.50', 'aa:aa'], ['192.0.2.51', 'aa:aa'], ['192.0.2.52', 'bb:bb']]);
  const r = resolveHolder({ vip: '192.0.2.50', vipProbe: up, arp, members });
  assert.equal(r.holderId, 'a');
  assert.equal(r.holderName, 'lb-a');
  assert.equal(r.reachable, true);
  assert.equal(r.conflict, null);
});

test('failover: VIP MAC moves to the other member', () => {
  const arp = new Map([['192.0.2.50', 'bb:bb'], ['192.0.2.51', 'aa:aa'], ['192.0.2.52', 'bb:bb']]);
  assert.equal(resolveHolder({ vip: '192.0.2.50', vipProbe: up, arp, members }).holderName, 'lb-b');
});

test('unknown holder when the MAC matches nobody (e.g. different subnet)', () => {
  const r = resolveHolder({ vip: '192.0.2.50', vipProbe: up, arp: new Map(), members });
  assert.equal(r.holderId, null);
  assert.equal(r.reachable, true);
});

test('unreachable VIP', () => {
  const r = resolveHolder({ vip: '192.0.2.50', vipProbe: { ok: false, error: 'timeout' }, arp: new Map(), members });
  assert.equal(r.reachable, false);
  assert.equal(r.error, 'timeout');
});

test('split brain is reported', () => {
  // two members sharing one MAC can only happen if both claim it (or misconfigured MACs)
  const arp = new Map([['192.0.2.50', 'aa:aa'], ['192.0.2.51', 'aa:aa'], ['192.0.2.52', 'aa:aa']]);
  const r = resolveHolder({ vip: '192.0.2.50', vipProbe: up, arp, members });
  assert.equal(r.holderId, null);
  assert.deepEqual(r.conflict, ['lb-a', 'lb-b']);
});

test('reads complete entries from /proc/net/arp format', () => {
  const f = path.join(process.env.DATA_DIR, 'arp');
  fs.writeFileSync(f, [
    'IP address       HW type     Flags       HW address            Mask     Device',
    '192.0.2.50       0x1         0x2         BC:24:11:C2:46:52     *        eth0',
    '192.0.2.52       0x1         0x2         bc:24:11:a9:7e:9d     *        eth0',
    '192.0.2.99       0x1         0x0         00:00:00:00:00:00     *        eth0',
  ].join('\n'));
  const arp = readArp(f);
  assert.equal(arp.get('192.0.2.50'), 'bc:24:11:c2:46:52');
  assert.equal(arp.size, 2, 'incomplete entries ignored');
});

test('agent address from the gRPC peer string', () => {
  const call = p => ({ getPeer: () => p });
  assert.equal(peerAddress(call('192.0.2.52:52190')), '192.0.2.52');
  assert.equal(peerAddress(call('[::ffff:192.0.2.52]:52190')), '192.0.2.52');
  assert.equal(peerAddress(call('ipv4:10.0.0.5:443')), '10.0.0.5');
  assert.equal(peerAddress(call('[2001:db8::1]:443')), '2001:db8::1');
  assert.equal(peerAddress({}), null);
});
