/**
 * nginx-manager — lib/tls.js
 *
 * TLS material for the agent gRPC listener. NGINX Agent only sends its token over
 * TLS, so on first start we create a small private CA plus a server certificate
 * signed by it (via the openssl CLI). Agents trust the CA (`command.tls.ca`).
 *
 * Bring your own instead by setting GRPC_TLS_CERT / GRPC_TLS_KEY (and GRPC_TLS_CA
 * for the copy shown in the UI).
 */

'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function defaultSans() {
  const sans = new Set([`DNS:${os.hostname()}`, 'DNS:localhost', 'IP:127.0.0.1']);
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) sans.add(`IP:${a.address}`);
    }
  }
  return [...sans];
}

// GRPC_TLS_SANS="DNS:nginx-manager.example.com,IP:172.16.40.10"
function configuredSans() {
  const raw = (process.env.GRPC_TLS_SANS || '').trim();
  if (!raw) return defaultSans();
  return raw.split(',').map(s => s.trim()).filter(Boolean)
    .map(s => /^(DNS|IP):/.test(s) ? s : (/^[\d.]+$|:/.test(s) ? `IP:${s}` : `DNS:${s}`));
}

function openssl(args) {
  execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });
}

function ensureTls(dir) {
  if (process.env.GRPC_TLS_CERT && process.env.GRPC_TLS_KEY) {
    const caPath = process.env.GRPC_TLS_CA || process.env.GRPC_TLS_CERT;
    return {
      cert: fs.readFileSync(process.env.GRPC_TLS_CERT),
      key:  fs.readFileSync(process.env.GRPC_TLS_KEY),
      ca:   fs.readFileSync(caPath, 'utf8'),
      serverName: process.env.GRPC_TLS_SERVER_NAME || '',
    };
  }

  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const caKey   = path.join(dir, 'ca.key');
  const caCert  = path.join(dir, 'ca.pem');
  const srvKey  = path.join(dir, 'server.key');
  const srvCert = path.join(dir, 'server.pem');
  const sansFile = path.join(dir, 'server.sans');
  const sans = configuredSans();

  if (!fs.existsSync(caKey) || !fs.existsSync(caCert)) {
    openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', caKey, '-out', caCert, '-days', '3650', '-subj', '/CN=nginx-manager agent CA',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    console.log('[nginx-manager] Generated agent CA at', caCert);
  }

  // (Re)issue the server cert when missing or when the SAN list changed.
  const prevSans = fs.existsSync(sansFile) ? fs.readFileSync(sansFile, 'utf8') : '';
  if (!fs.existsSync(srvKey) || !fs.existsSync(srvCert) || prevSans !== sans.join(',')) {
    const csr = path.join(dir, 'server.csr');
    const ext = path.join(dir, 'server.ext');
    openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', srvKey, '-out', csr, '-subj', '/CN=nginx-manager']);
    fs.writeFileSync(ext, [
      'basicConstraints=CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      `subjectAltName=${sans.join(',')}`,
    ].join('\n') + '\n');
    openssl(['x509', '-req', '-in', csr, '-CA', caCert, '-CAkey', caKey, '-CAcreateserial',
      '-out', srvCert, '-days', '825', '-extfile', ext]);
    fs.unlinkSync(csr);
    fs.writeFileSync(sansFile, sans.join(','));
    console.log('[nginx-manager] Issued agent gRPC server certificate for', sans.join(', '));
  }
  for (const f of [caKey, srvKey]) fs.chmodSync(f, 0o600);

  return {
    cert: fs.readFileSync(srvCert),
    key:  fs.readFileSync(srvKey),
    ca:   fs.readFileSync(caCert, 'utf8'),
    sans,
  };
}

module.exports = { ensureTls };
