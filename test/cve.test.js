'use strict';

const test = require('node:test');
const assert = require('node:assert');
const c = require('../lib/cve');

const HTML = `<ul>
<li><p>Buffer overflow when using ngx_http_v3_module<br>Severity: medium<br><a href="https://example.com/a1">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2099-0001">CVE-2099-0001</a><br>Not vulnerable: 1.31.6+, 1.30.5+<br>Vulnerable: 1.29.2-1.31.5</p></li>
<li><p>Buffer overflow when using map and regex<br>Severity: <b>major</b><br><a href="https://example.com/a2">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2099-0002">CVE-2099-0002</a><br>Not vulnerable: 1.31.3+, 1.30.4+<br>Vulnerable: 0.9.6-1.31.2</p></li>
<li><p>1-byte memory overwrite in resolver<br>Severity: medium<br><a href="https://www.cve.org/CVERecord?id=CVE-2099-0003">CVE-2099-0003</a><br>Not vulnerable: 1.21.0+, 1.20.1+<br>Vulnerable: 0.6.18-1.20.0</p></li>
<li><p>Escape sequences in log<br>Severity: none<br><a href="https://www.cve.org/CVERecord?id=CVE-2009-4487">CVE-2009-4487</a><br>Not vulnerable: none<br>Vulnerable: all</p></li>
<li><p>Directory traversal<br>Severity: major<br>Not vulnerable: 1.3.1+<br>Vulnerable: nginx/Windows 0.7.52-1.3.0</p></li>
<li><p>Two ranges<br>Severity: low<br>Not vulnerable: 1.5.0+, 1.4.1+<br>Vulnerable: 1.1.4-1.2.8, 1.3.9-1.4.0</p></li>
</ul>`;

test('parses advisories', () => {
  const list = c.parseAdvisories(HTML);
  assert.strictEqual(list.length, 6);
  assert.deepStrictEqual(list[1], { title: 'Buffer overflow when using map and regex', severity: 'major', cves: ['CVE-2099-0002'],
    advisory: 'https://example.com/a2', notVulnerable: '1.31.3+, 1.30.4+', vulnerable: '0.9.6-1.31.2' });
});

test('version ranges and fixed releases', () => {
  assert.strictEqual(c.inRanges('1.31.2', c.parseRanges('0.9.6-1.31.2')), true);
  assert.strictEqual(c.inRanges('1.31.3', c.parseRanges('0.9.6-1.31.2')), false);
  assert.strictEqual(c.inRanges('1.3.9', c.parseRanges('1.1.4-1.2.8, 1.3.9-1.4.0')), true);
  assert.strictEqual(c.inRanges('1.3.0', c.parseRanges('1.1.4-1.2.8, 1.3.9-1.4.0')), false);
  assert.strictEqual(c.parseRanges('nginx/Windows 0.7.52-1.3.0').windowsOnly, true);
  assert.strictEqual(c.fixedFor('1.30.1', '1.31.3+, 1.30.4+'), '1.30.4');
  assert.strictEqual(c.fixedFor('1.31.0', '1.31.3+, 1.30.4+'), '1.31.3');
  assert.strictEqual(c.fixedFor('1.24.0', '1.31.3+, 1.30.4+'), '1.30.4');
});

test('assesses a server: config decides module-specific advisories', () => {
  const list = c.parseAdvisories(HTML);
  const conf = 'server { listen 443 ssl; http2 on; }\nmap $host $v { default 1; ~^[0-9.]+$ 0; }\n';
  const r = c.assessNginx('1.31.2', list, conf);
  const by = Object.fromEntries(r.findings.map(f => [f.id, f]));
  assert.strictEqual(by['CVE-2099-0002'].status, 'affected');          // map with regex is in the config
  assert.strictEqual(by['CVE-2099-0001'].status, 'not_in_use');        // no quic / http3
  assert.strictEqual(by['CVE-2099-0001'].feature, 'HTTP/3 (QUIC)');
  assert.strictEqual(by['CVE-2009-4487'].status, 'info');
  assert.ok(!by['CVE-2099-0003']);                                      // not in range
  assert.ok(!r.findings.some(f => /traversal/.test(f.title)));          // Windows only
  assert.strictEqual(r.findings[0].id, 'CVE-2099-0002');                // affected first
  assert.strictEqual(r.upgradeTo, '1.31.3');
  const quic = c.assessNginx('1.31.2', list, conf + 'server { listen 443 quic reuseport; }');
  assert.strictEqual(quic.findings.find(f => f.id === 'CVE-2099-0001').status, 'affected');
  assert.strictEqual(quic.upgradeTo, '1.31.6');
  assert.strictEqual(c.assessNginx('1.31.6', list, conf).findings.filter(f => f.status === 'affected').length, 0);
});

test('scanner caches sources and queries OSV per agent version', async () => {
  const calls = [];
  const fetcher = async (url, opts = {}) => {
    calls.push(url);
    if (url.includes('nginx.org')) return HTML;
    const body = JSON.parse(opts.body);
    assert.strictEqual(body.package.name, 'github.com/nginx/agent/v3');
    return JSON.stringify(body.version === 'v3.0.0' ? { vulns: [{ id: 'GO-2099-1', aliases: ['CVE-2099-9'], summary: 'Agent bug',
      affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: 'v3.1.0' }] }] }] }] } : {});
  };
  const s = new c.CveScanner({ fetcher });
  await s.refresh({ agentVersions: ['v3.12.0', 'v3.0.0', 'v3.12.0'] });
  assert.strictEqual(calls.length, 3);
  await s.refresh({ agentVersions: ['v3.12.0'] });
  assert.strictEqual(calls.length, 3);                                  // fresh cache: no refetch
  const a = s.assess({ id: 'x', name: 'lb', nginxVersion: '1.31.2', agentVersion: 'v3.0.0' }, 'map $a $b { ~x 1; }');
  assert.strictEqual(a.agent.findings[0].cves[0], 'CVE-2099-9');
  assert.strictEqual(a.agent.findings[0].fixedIn, '3.1.0');
  assert.strictEqual(s.assess({ id: 'y', name: 'lb2', nginxVersion: '1.31.6', agentVersion: 'v3.12.0' }, '').agent.findings.length, 0);
  // a failed fetch keeps the cached list and reports the error
  const s2 = new c.CveScanner({ fetcher: async () => { throw new Error('offline'); } });
  s2.cache = s.cache;
  await s2.refresh({ force: true });
  assert.strictEqual(s2.sources().nginx.error, 'offline');
  assert.strictEqual(s2.sources().nginx.count, 6);
});

test('optional upgrade when only unused modules are vulnerable', () => {
  const r = c.assessNginx('1.31.4', c.parseAdvisories(HTML), 'server { listen 80; }');
  assert.strictEqual(r.upgradeTo, null);
  assert.strictEqual(r.upgradeToAll, '1.31.6');
});
