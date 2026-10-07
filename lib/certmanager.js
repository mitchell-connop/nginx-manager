/**
 * nginx-manager — lib/certmanager.js
 *
 * Managed certificates: issued (or exported) once on the manager, then deployed to every
 * target server through its agent. A deployment only pushes the certificate + key files
 * (never unrelated pending edits); the agent runs `nginx -t`, reloads, and rolls back on
 * failure. Renewal is checked every few minutes and redeploys automatically.
 *
 *   data/managed-certs.json   definitions + status (no secrets)
 *   data/cert-secrets.json    EAB HMAC keys, DNS API tokens, AWS secret keys (mode 600)
 *   data/certbot/             certbot state (ACME account keys, issued certificates)
 *   data/acm/<id>/            certificates exported from AWS ACM
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const store  = require('./store');
const certbot = require('./certbot');
const acm    = require('./acm');
const { ISSUERS, DNS_PROVIDERS, validateCredentials } = require('./issuers');

const DEFS_FILE    = path.join(store.DATA_DIR, 'managed-certs.json');
const SECRETS_FILE = path.join(store.DATA_DIR, 'cert-secrets.json');
const ACM_DIR      = path.join(store.DATA_DIR, 'acm');
const TICK_MS      = 10 * 60 * 1000;
const ACM_CHECK_MS = 6 * 60 * 60 * 1000;
const LOG_LINES    = 200;

const DOMAIN = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL  = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ABS_PATH = /^\/[A-Za-z0-9._@/-]+$/;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

const sha = buf => crypto.createHash('sha256').update(buf).digest('base64');

function slug(s) {
  return String(s).toLowerCase().replace(/^\*\./, 'wildcard.').replace(/[^a-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'cert';
}

// Inspect an issued bundle: dates, names, issuer, and that the key matches.
function inspect(bundle) {
  const x = new crypto.X509Certificate(bundle.fullchain);
  const key = crypto.createPrivateKey(bundle.privkey);
  const cn = s => ((s || '').match(/CN=([^\n,]+)/) || [])[1] || '';
  return {
    notBefore: new Date(x.validFrom).toISOString(),
    notAfter: new Date(x.validTo).toISOString(),
    subject: cn(x.subject),
    issuer: cn(x.issuer) || (x.issuer || '').split('\n').pop(),
    sans: (x.subjectAltName || '').split(',').map(s => s.trim().replace(/^DNS:/, '')).filter(Boolean),
    serial: x.serialNumber,
    fingerprint: x.fingerprint256,
    keyMatches: x.checkPrivateKey(key),
  };
}

class CertManager extends EventEmitter {
  constructor({ mp, providers = DNS_PROVIDERS }) {
    super();
    this.mp = mp;
    this.providers = providers;
    this.busy = new Map();     // id -> Promise
    this.logs = new Map();     // id -> [lines]
  }

  // ── persistence ───────────────────────────────────────────────────────────
  list() { return readJson(DEFS_FILE, []); }
  get(id) { return this.list().find(c => c.id === id) || null; }
  save(cert) {
    const all = this.list();
    const i = all.findIndex(c => c.id === cert.id);
    if (i === -1) all.push(cert); else all[i] = cert;
    writeJson(DEFS_FILE, all);
    this.emit('change', cert.id);
    return cert;
  }
  secrets(id) { return readJson(SECRETS_FILE, {})[id] || {}; }
  saveSecrets(id, patch) {
    const all = readJson(SECRETS_FILE, {});
    const cur = all[id] || {};
    const next = { ...cur };
    if (patch.eabHmac !== undefined && patch.eabHmac !== '') next.eabHmac = patch.eabHmac;
    if (patch.dns) next.dns = { ...(cur.dns || {}), ...Object.fromEntries(Object.entries(patch.dns).filter(([, v]) => v !== '' && v !== undefined)) };
    if (patch.aws) next.aws = { ...(cur.aws || {}), ...Object.fromEntries(Object.entries(patch.aws).filter(([, v]) => v !== '' && v !== undefined)) };
    all[id] = next;
    writeJson(SECRETS_FILE, all);
    fs.chmodSync(SECRETS_FILE, 0o600);
  }

  log(id, line) {
    const lines = this.logs.get(id) || [];
    const stamped = `[${new Date().toISOString().slice(11, 19)}] ${line}`;
    lines.push(stamped);
    if (lines.length > LOG_LINES) lines.splice(0, lines.length - LOG_LINES);
    this.logs.set(id, lines);
    this.emit('log', id, stamped);
  }

  // Public view: what the UI sees (no secrets, but which secrets are set)
  view(cert) {
    const s = this.secrets(cert.id);
    return {
      ...cert,
      hasSecrets: {
        eabHmac: !!s.eabHmac,
        dns: Object.fromEntries(Object.entries(s.dns || {}).map(([k, v]) => [k, !!v])),
        aws: { secretAccessKey: !!(s.aws && s.aws.secretAccessKey) },
      },
      log: (this.logs.get(cert.id) || []).slice(-50),
      busy: this.busy.has(cert.id),
    };
  }

  // ── validation / create / update ─────────────────────────────────────────
  normalize(input, existing) {
    const errors = [];
    const sourceId = input.source || (existing && existing.source) || 'letsencrypt';
    const issuer = ISSUERS[sourceId];
    if (!issuer) errors.push(`unknown certificate source ${sourceId}`);

    const name = String(input.name || (existing && existing.name) || '').trim();
    if (!name || name.length > 80 || /[\r\n]/.test(name)) errors.push('Name is required (max 80 characters)');

    const targets = (input.targets || (existing && existing.targets) || []).filter(id => store.findAgent(id));
    if (!targets.length) errors.push('Pick at least one server to deploy to');

    const base = `/etc/nginx/ssl/${slug(name)}`;
    const certPath = String(input.certPath || (existing && existing.certPath) || `${base}/fullchain.pem`).trim();
    const keyPath = String(input.keyPath || (existing && existing.keyPath) || `${base}/privkey.pem`).trim();
    if (!ABS_PATH.test(certPath) || path.posix.normalize(certPath) !== certPath) errors.push('Certificate path must be an absolute path');
    if (!ABS_PATH.test(keyPath) || path.posix.normalize(keyPath) !== keyPath) errors.push('Key path must be an absolute path');
    if (certPath === keyPath) errors.push('Certificate and key paths must differ');

    const renewDays = parseInt(input.renewDays || (existing && existing.renewDays) || 30, 10);
    if (!(renewDays >= 1 && renewDays <= 120)) errors.push('Renew-before days must be 1-120');

    const out = {
      name, source: sourceId, targets, certPath, keyPath, renewDays,
      keyType: (input.keyType || (existing && existing.keyType)) === 'rsa' ? 'rsa' : 'ecdsa',
    };

    if (issuer && issuer.type === 'acme') {
      const domains = (input.domains || (existing && existing.domains) || []).map(d => String(d).trim().toLowerCase()).filter(Boolean);
      if (!domains.length) errors.push('At least one domain is required');
      for (const d of domains) if (!DOMAIN.test(d)) errors.push(`"${d}" is not a valid domain`);
      const directory = issuer.editableDirectory
        ? String((input.issuer && input.issuer.directory) || (existing && existing.issuer && existing.issuer.directory) || issuer.directory).trim()
        : issuer.directory;
      if (!/^https:\/\/[^\s]+$/.test(directory)) errors.push('ACME directory must be an https:// URL');
      const email = String((input.issuer && input.issuer.email) ?? (existing && existing.issuer && existing.issuer.email) ?? '').trim();
      if (email && !EMAIL.test(email)) errors.push('Email looks invalid');
      const eabKid = String((input.issuer && input.issuer.eabKid) ?? (existing && existing.issuer && existing.issuer.eabKid) ?? '').trim();
      if (eabKid && !/^[A-Za-z0-9_.:-]{1,200}$/.test(eabKid)) errors.push('EAB key ID looks invalid');
      const provider = (input.challenge && input.challenge.provider) || (existing && existing.challenge && existing.challenge.provider) || 'cloudflare';
      if (!this.providers[provider]) errors.push(`unknown DNS provider ${provider}`);
      const propagationSeconds = parseInt((input.challenge && input.challenge.propagationSeconds) || (existing && existing.challenge && existing.challenge.propagationSeconds) || 30, 10);
      Object.assign(out, {
        domains,
        issuer: { directory, email, eabKid },
        challenge: { provider, propagationSeconds: Math.min(Math.max(propagationSeconds, 5), 600) },
      });
    } else if (issuer && issuer.type === 'acm') {
      const a = { ...(existing && existing.acm), ...(input.acm || {}) };
      if (!/^arn:aws[a-z-]*:acm:[a-z0-9-]+:\d{12}:certificate\/[0-9a-f-]+$/.test(a.arn || '')) errors.push('ACM certificate ARN looks invalid');
      const region = (a.arn || '').split(':')[3] || '';
      if (a.accessKeyId && !/^[A-Z0-9]{16,128}$/.test(a.accessKeyId)) errors.push('Access key ID looks invalid');
      Object.assign(out, { acm: { arn: a.arn, region, accessKeyId: a.accessKeyId || '' }, domains: (existing && existing.domains) || [] });
    }
    return { cert: out, errors };
  }

  checkSecrets(cert, secretsIn) {
    const s = this.secrets(cert.id);
    const errors = [];
    const issuer = ISSUERS[cert.source];
    if (issuer.type === 'acme') {
      const dns = { ...(s.dns || {}), ...Object.fromEntries(Object.entries((secretsIn && secretsIn.dns) || {}).filter(([, v]) => v)) };
      if (DNS_PROVIDERS[cert.challenge.provider]) errors.push(...validateCredentials(cert.challenge.provider, dns));
      const needsEab = issuer.eab === true;
      if (needsEab && !cert.issuer.eabKid) errors.push(`${issuer.label} requires an EAB key ID`);
      if ((needsEab || cert.issuer.eabKid) && !(s.eabHmac || (secretsIn && secretsIn.eabHmac))) errors.push('EAB HMAC key is required');
    } else if (issuer.type === 'acm') {
      const sk = (secretsIn && secretsIn.aws && secretsIn.aws.secretAccessKey) || (s.aws && s.aws.secretAccessKey);
      if (cert.acm.accessKeyId && !sk) errors.push('Secret access key is required with an access key ID');
    }
    return errors;
  }

  create(input, secretsIn) {
    const { cert, errors } = this.normalize(input, null);
    cert.id = `${slug(cert.name)}-${crypto.randomBytes(3).toString('hex')}`;
    errors.push(...(errors.length ? [] : this.checkSecrets(cert, secretsIn)));
    if (errors.length) throw Object.assign(new Error(errors.join('; ')), { status: 400 });
    this.assertNoPathClash(cert);
    cert.createdAt = cert.updatedAt = new Date().toISOString();
    cert.status = { state: 'pending', message: 'Not issued yet', deployments: {} };
    this.saveSecrets(cert.id, secretsIn || {});
    return this.save(cert);
  }

  update(id, input, secretsIn) {
    const existing = this.get(id);
    if (!existing) throw Object.assign(new Error('not found'), { status: 404 });
    const { cert, errors } = this.normalize({ ...input, source: existing.source }, existing);
    cert.id = id;
    errors.push(...(errors.length ? [] : this.checkSecrets(cert, secretsIn)));
    if (errors.length) throw Object.assign(new Error(errors.join('; ')), { status: 400 });
    this.assertNoPathClash(cert);
    const reissue = JSON.stringify(existing.domains) !== JSON.stringify(cert.domains) ||
      existing.keyType !== cert.keyType || JSON.stringify(existing.issuer) !== JSON.stringify(cert.issuer);
    this.saveSecrets(id, secretsIn || {});
    return this.save({ ...existing, ...cert, status: { ...existing.status, ...(reissue ? { needsReissue: true } : {}) }, updatedAt: new Date().toISOString() });
  }

  assertNoPathClash(cert) {
    for (const other of this.list()) {
      if (other.id === cert.id) continue;
      if (!other.targets.some(t => cert.targets.includes(t))) continue;
      if ([other.certPath, other.keyPath].some(p => p === cert.certPath || p === cert.keyPath)) {
        throw Object.assign(new Error(`Paths clash with managed certificate "${other.name}"`), { status: 409 });
      }
    }
  }

  remove(id) {
    const all = this.list().filter(c => c.id !== id);
    writeJson(DEFS_FILE, all);
    const secrets = readJson(SECRETS_FILE, {});
    delete secrets[id];
    writeJson(SECRETS_FILE, secrets);
    fs.rmSync(path.join(ACM_DIR, id), { recursive: true, force: true });
    this.logs.delete(id);
    this.emit('change', id);
  }

  // ── issue / renew / export ───────────────────────────────────────────────
  bundle(cert) {
    if (ISSUERS[cert.source].type === 'acm') {
      try {
        return {
          fullchain: fs.readFileSync(path.join(ACM_DIR, cert.id, 'fullchain.pem')),
          privkey: fs.readFileSync(path.join(ACM_DIR, cert.id, 'privkey.pem')),
        };
      } catch { return null; }
    }
    return certbot.readIssued(store.DATA_DIR, cert.id);
  }

  due(cert, bundle) {
    if (!bundle || cert.status.needsReissue) return true;
    const notAfter = cert.status.notAfter ? Date.parse(cert.status.notAfter) : 0;
    return notAfter - Date.now() < cert.renewDays * 86400000;
  }

  async obtain(cert, { force }) {
    const issuer = ISSUERS[cert.source];
    const secrets = this.secrets(cert.id);
    if (issuer.type === 'acme') {
      const res = await certbot.obtain({
        dataDir: store.DATA_DIR, cert, secrets, force: true, providers: this.providers,
        log: line => this.log(cert.id, line),
      });
      if (!res.ok) throw new Error(res.output.split('\n').filter(Boolean).slice(-3).join(' | ') || `certbot exited ${res.code}`);
      return;
    }
    // AWS ACM
    const opts = { ...cert.acm, secretAccessKey: secrets.aws && secrets.aws.secretAccessKey };
    const d = await acm.describe(opts);
    this.log(cert.id, `ACM ${d.type || ''} certificate ${d.status || ''}, serial ${d.serial || '?'}, expires ${d.notAfter || '?'}`);
    if (!d.exportable) throw new Error('This ACM certificate is not exportable — request it with export enabled (or use AWS Private CA)');
    if (!force && cert.status.serial && d.serial && normalizeSerial(d.serial) === normalizeSerial(cert.status.serial) && this.bundle(cert)) {
      this.log(cert.id, 'Serial unchanged — nothing to export');
      return;
    }
    const b = await acm.exportCert(opts);
    const dir = path.join(ACM_DIR, cert.id);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, 'fullchain.pem'), b.fullchain, { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'privkey.pem'), b.privkey, { mode: 0o600 });
    cert.domains = d.domains;
    this.log(cert.id, 'Exported certificate and key from ACM');
  }

  // Run the whole pipeline for one certificate. Serialized per certificate.
  process(id, { force = false, deploy = true } = {}) {
    if (this.busy.has(id)) return this.busy.get(id);
    const p = this._process(id, { force, deploy }).finally(() => { this.busy.delete(id); this.emit('change', id); });
    this.busy.set(id, p);
    this.emit('change', id);
    return p;
  }

  async _process(id, { force, deploy }) {
    let cert = this.get(id);
    if (!cert) return null;
    const issuer = ISSUERS[cert.source];
    const now = new Date().toISOString();
    let bundle = this.bundle(cert);

    const acmCheckDue = issuer.type === 'acm' &&
      (!cert.status.lastCheckAt || Date.now() - Date.parse(cert.status.lastCheckAt) > ACM_CHECK_MS);
    if (force || this.due(cert, bundle) || acmCheckDue) {
      this.log(id, force ? 'Renewing now (forced)' : bundle ? 'Certificate due — renewing' : 'Requesting certificate');
      cert.status = { ...cert.status, state: 'issuing', message: 'Requesting certificate…' };
      this.save(cert);
      try {
        await this.obtain(cert, { force });
        bundle = this.bundle(cert);
        if (!bundle) throw new Error('No certificate files after issuance');
        const info = inspect(bundle);
        if (!info.keyMatches) throw new Error('Issued private key does not match the certificate');
        cert = { ...this.get(id), domains: cert.domains };
        cert.status = {
          ...cert.status, ...info, state: 'ok', message: 'Issued', lastError: null,
          lastIssuedAt: cert.status.serial !== info.serial ? now : cert.status.lastIssuedAt,
          lastCheckAt: now, needsReissue: false,
        };
        this.log(id, `✅ Certificate for ${info.sans.join(', ')} valid until ${info.notAfter} (issuer ${info.issuer})`);
      } catch (err) {
        cert = this.get(id);
        cert.status = { ...cert.status, state: bundle ? 'warning' : 'error', message: `Renewal failed: ${err.message}`, lastError: err.message, lastCheckAt: now };
        this.log(id, `❌ ${err.message}`);
        this.save(cert);
        if (!bundle) return cert;     // nothing to deploy yet
      }
      this.save(cert);
    } else if (bundle && !cert.status.serial) {
      cert.status = { ...cert.status, ...inspect(bundle), state: 'ok', message: 'Issued' };
      this.save(cert);
    }

    if (deploy && bundle) await this.deploy(id, bundle);
    return this.get(id);
  }

  // Push cert + key to every target whose files differ. Only these two files are applied.
  async deploy(id, bundle) {
    const cert = this.get(id);
    bundle = bundle || this.bundle(cert);
    if (!bundle) return;
    const want = { cert: sha(bundle.fullchain), key: sha(bundle.privkey) };
    const deployments = { ...(cert.status.deployments || {}) };

    for (const agentId of cert.targets) {
      const agent = store.findAgent(agentId);
      if (!agent) continue;
      const st = store.readState(agentId);
      const haveCert = store.currentFile(st, cert.certPath);
      const haveKey = store.currentFile(st, cert.keyPath);
      if (haveCert && haveKey && haveCert.hash === want.cert && haveKey.hash === want.key) {
        if (!deployments[agentId] || deployments[agentId].hash !== want.cert || deployments[agentId].state !== 'ok') {
          deployments[agentId] = { state: 'ok', hash: want.cert, at: new Date().toISOString(), message: 'Up to date' };
        }
        continue;
      }
      if (!this.mp.isOnline(agentId)) {
        deployments[agentId] = { ...(deployments[agentId] || {}), state: 'offline', message: 'Agent offline — will deploy when it reconnects' };
        continue;
      }
      this.log(id, `Deploying to ${agent.name}…`);
      const res = await this.mp.configApply(agentId, {
        label: `Deploying certificate "${cert.name}"`,
        files: {
          [cert.certPath]: { content: bundle.fullchain, permissions: '0644', pin: true },
          [cert.keyPath]: { content: bundle.privkey, permissions: '0600', pin: true },
        },
      });
      deployments[agentId] = res.success
        ? { state: 'ok', hash: want.cert, at: new Date().toISOString(), message: res.unchanged ? 'Up to date' : 'Deployed' }
        : { state: 'error', hash: (deployments[agentId] || {}).hash, at: new Date().toISOString(), message: res.output };
      this.log(id, res.success ? `✅ ${agent.name}: deployed` : `❌ ${agent.name}: ${res.output}`);
    }
    const latest = this.get(id);
    latest.status = { ...latest.status, deployments };
    this.save(latest);
  }

  // ── scheduling ────────────────────────────────────────────────────────────
  async tick() {
    for (const cert of this.list()) {
      try { await this.process(cert.id); }
      catch (err) { this.log(cert.id, `❌ ${err.message}`); }
    }
  }

  start() {
    setTimeout(() => this.tick(), 30 * 1000).unref();
    this.timer = setInterval(() => this.tick(), TICK_MS);
    this.timer.unref();
  }

  stop() { clearInterval(this.timer); }
}

function normalizeSerial(s) { return String(s).replace(/[^0-9a-f]/gi, '').replace(/^0+/, '').toLowerCase(); }

module.exports = { CertManager, inspect };
