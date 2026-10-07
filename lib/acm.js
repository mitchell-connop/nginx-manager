/**
 * nginx-manager — lib/acm.js
 *
 * Export a certificate from AWS Certificate Manager so it can be deployed to nginx.
 * Only exportable certificates work: public certificates requested with export enabled,
 * or certificates from AWS Private CA. AWS handles renewal; we compare the serial number
 * (DescribeCertificate is free) and only export again when it changes.
 */

'use strict';

const crypto = require('crypto');

function client({ region, accessKeyId, secretAccessKey }) {
  const { ACMClient } = require('@aws-sdk/client-acm');
  return new ACMClient({
    region,
    ...(accessKeyId && secretAccessKey ? { credentials: { accessKeyId, secretAccessKey } } : {}),
  });
}

async function describe(opts) {
  const { DescribeCertificateCommand } = require('@aws-sdk/client-acm');
  const res = await client(opts).send(new DescribeCertificateCommand({ CertificateArn: opts.arn }));
  const c = res.Certificate || {};
  return {
    serial: c.Serial || null,
    status: c.Status,
    domains: c.SubjectAlternativeNames || (c.DomainName ? [c.DomainName] : []),
    notAfter: c.NotAfter ? new Date(c.NotAfter).toISOString() : null,
    exportable: !!(c.Options && c.Options.Export === 'ENABLED') || c.Type === 'PRIVATE',
    type: c.Type,
  };
}

// Returns { fullchain: Buffer, privkey: Buffer } with an unencrypted PKCS#8 key.
async function exportCert(opts) {
  const { ExportCertificateCommand } = require('@aws-sdk/client-acm');
  const passphrase = crypto.randomBytes(24).toString('base64url');
  const res = await client(opts).send(new ExportCertificateCommand({
    CertificateArn: opts.arn,
    Passphrase: Buffer.from(passphrase),
  }));
  const key = crypto.createPrivateKey({ key: res.PrivateKey, format: 'pem', passphrase });
  const privkey = key.export({ type: 'pkcs8', format: 'pem' });
  const fullchain = `${res.Certificate.trim()}\n${(res.CertificateChain || '').trim()}\n`.replace(/\n+$/, '\n');
  return { fullchain: Buffer.from(fullchain), privkey: Buffer.from(privkey) };
}

module.exports = { describe, exportCert };
