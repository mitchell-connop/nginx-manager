/**
 * nginx-manager — lib/certbot.js
 *
 * Runs certbot on the manager with all of its state under data/certbot (config, work,
 * logs), so one certificate is issued once and then deployed to every server through
 * the agents. Uses DNS-01 only: works for wildcards and for servers that aren't
 * reachable from the internet, and needs nothing on the nginx servers.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { DNS_PROVIDERS } = require('./issuers');

const CERTBOT_BIN = process.env.CERTBOT_BIN || 'certbot';
const RUN_TIMEOUT_MS = 10 * 60 * 1000;

function dirs(dataDir) {
  const base = path.join(dataDir, 'certbot');
  const d = {
    config: path.join(base, 'config'),
    work: path.join(base, 'work'),
    logs: path.join(base, 'logs'),
    creds: path.join(base, 'credentials'),
  };
  for (const p of Object.values(d)) fs.mkdirSync(p, { recursive: true, mode: 0o700 });
  return d;
}

function livePaths(dataDir, certName) {
  const live = path.join(dataDir, 'certbot', 'config', 'live', certName);
  return {
    fullchain: path.join(live, 'fullchain.pem'),
    privkey: path.join(live, 'privkey.pem'),
    chain: path.join(live, 'chain.pem'),
    cert: path.join(live, 'cert.pem'),
  };
}

function readIssued(dataDir, certName) {
  const p = livePaths(dataDir, certName);
  try {
    return { fullchain: fs.readFileSync(p.fullchain), privkey: fs.readFileSync(p.privkey) };
  } catch { return null; }
}

/**
 * Obtain or renew `cert` (a managed certificate definition).
 *   secrets: { eabHmac, dns: { ...provider fields } }
 *   force:   renew even if not due
 *   log:     line => void
 */
function obtain({ dataDir, cert, secrets, force = false, log = () => {}, providers = DNS_PROVIDERS }) {
  const d = dirs(dataDir);
  const provider = providers[cert.challenge.provider];
  if (!provider) return Promise.resolve({ ok: false, output: `unknown DNS provider ${cert.challenge.provider}` });

  let credFile = null;
  if (provider.credentialsFile) {
    credFile = path.join(d.creds, `${cert.id}.ini`);
    fs.writeFileSync(credFile, provider.credentialsFile(secrets.dns || {}), { mode: 0o600 });
    fs.chmodSync(credFile, 0o600);
  }

  const args = [
    'certonly', '--non-interactive', '--agree-tos',
    '--config-dir', d.config, '--work-dir', d.work, '--logs-dir', d.logs,
    '--cert-name', cert.id,
    '--server', cert.issuer.directory,
    '--key-type', cert.keyType === 'rsa' ? 'rsa' : 'ecdsa',
    ...(cert.keyType === 'rsa' ? ['--rsa-key-size', '2048'] : ['--elliptic-curve', 'secp256r1']),
    ...(cert.issuer.email ? ['--email', cert.issuer.email, '--no-eff-email'] : ['--register-unsafely-without-email']),
    ...(cert.issuer.eabKid && secrets.eabHmac ? ['--eab-kid', cert.issuer.eabKid, '--eab-hmac-key', secrets.eabHmac] : []),
    force ? '--force-renewal' : '--keep-until-expiring',
    // accept a changed domain list for this cert name without prompting
    '--expand',
    ...provider.args(credFile, cert.challenge.propagationSeconds, secrets.dns || {}),
    ...cert.domains.flatMap(dn => ['-d', dn]),
  ];

  // never echo secrets into the log
  const redact = s => {
    let out = s;
    if (secrets.eabHmac) out = out.split(secrets.eabHmac).join('<eab-hmac>');
    for (const f of provider.fields.filter(x => x.secret)) {
      const v = (secrets.dns || {})[f.key];
      if (v && v.length > 3) out = out.split(v).join('<secret>');
    }
    return out;
  };

  log(`$ certbot certonly --cert-name ${cert.id} --server ${cert.issuer.directory} ${cert.domains.map(x => `-d ${x}`).join(' ')}${force ? ' --force-renewal' : ''}`);

  return new Promise(resolve => {
    let output = '';
    let child;
    try {
      child = spawn(CERTBOT_BIN, args, {
        env: { ...process.env, ...provider.env(secrets.dns || {}), ...(provider.extraEnv || {}) },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      return resolve({ ok: false, output: `could not run certbot: ${err.message}` });
    }
    const timer = setTimeout(() => { child.kill('SIGTERM'); }, RUN_TIMEOUT_MS);
    const onData = chunk => {
      const text = redact(chunk.toString());
      output += text;
      for (const line of text.split('\n')) if (line.trim()) log(line);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', err => {
      clearTimeout(timer);
      resolve({ ok: false, output: err.code === 'ENOENT' ? 'certbot is not installed on the manager (apt install certbot python3-certbot-dns-cloudflare python3-certbot-dns-route53)' : err.message });
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (credFile) { try { fs.unlinkSync(credFile); } catch {} }
      const renewed = /Successfully received certificate|Congratulations/i.test(output);
      const notDue = /Certificate not yet due for renewal|not yet due/i.test(output);
      resolve({ ok: code === 0, code, renewed, notDue, output: output.trim().split('\n').slice(-15).join('\n') });
    });
  });
}

module.exports = { obtain, readIssued, livePaths };
