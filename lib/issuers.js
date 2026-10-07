/**
 * nginx-manager — lib/issuers.js
 *
 * Certificate sources and DNS-01 challenge providers for managed certificates.
 *
 * ACME CAs all go through certbot (`--server`, plus External Account Binding where the
 * CA requires an account key). AWS Certificate Manager is exported via its API.
 */

'use strict';

const ISSUERS = {
  letsencrypt: {
    label: "Let's Encrypt", type: 'acme', default: true,
    directory: 'https://acme-v02.api.letsencrypt.org/directory', eab: false,
  },
  'letsencrypt-staging': {
    label: "Let's Encrypt staging (untrusted test certificates)", type: 'acme',
    directory: 'https://acme-staging-v02.api.letsencrypt.org/directory', eab: false,
  },
  zerossl: {
    label: 'ZeroSSL', type: 'acme',
    directory: 'https://acme.zerossl.com/v2/DV90', eab: true,
    hint: 'EAB credentials: ZeroSSL dashboard → Developer → EAB Credentials',
  },
  google: {
    label: 'Google Trust Services', type: 'acme',
    directory: 'https://dv.acme-v02.api.pki.goog/directory', eab: true,
    hint: 'EAB key: `gcloud publicca external-account-keys create`',
  },
  digicert: {
    label: 'DigiCert (ACME)', type: 'acme',
    directory: 'https://one.digicert.com/mpki/api/v1/acme/v2/directory', eab: true, editableDirectory: true,
    hint: 'Use the ACME directory URL and EAB key ID / HMAC from your DigiCert account (CertCentral → Automation → ACME, or DigiCert ONE)',
  },
  sectigo: {
    label: 'Sectigo', type: 'acme',
    directory: 'https://acme.sectigo.com/v2/DV', eab: true, editableDirectory: true,
    hint: 'Use the ACME URL and EAB credentials from your Sectigo account',
  },
  'custom-acme': {
    label: 'Other ACME CA', type: 'acme', directory: '', eab: 'optional', editableDirectory: true,
  },
  'aws-acm': {
    label: 'AWS Certificate Manager (exportable certificate)', type: 'acm',
    hint: 'The certificate must be requested in ACM with export enabled (public exportable or Private CA). ' +
      'AWS renews it; nginx-manager re-exports and redeploys when the serial changes. ' +
      'IAM: acm:DescribeCertificate and acm:ExportCertificate on the certificate ARN.',
  },
};

// DNS-01 challenge providers (certbot DNS plugins). DNS-01 works for wildcard
// certificates and for servers that aren't reachable from the internet.
const DNS_PROVIDERS = {
  cloudflare: {
    label: 'Cloudflare',
    fields: [{ key: 'apiToken', label: 'API token (Zone → DNS → Edit)', secret: true }],
    // credentials file, written per run (mode 600)
    credentialsFile: c => `dns_cloudflare_api_token = ${c.apiToken}\n`,
    args: (credFile, propagation) => [
      '--dns-cloudflare', '--dns-cloudflare-credentials', credFile,
      '--dns-cloudflare-propagation-seconds', String(propagation || 20),
    ],
    env: () => ({}),
  },
  route53: {
    label: 'AWS Route 53',
    fields: [
      { key: 'accessKeyId', label: 'Access key ID' },
      { key: 'secretAccessKey', label: 'Secret access key', secret: true },
    ],
    credentialsFile: null,
    args: (credFile, propagation) => ['--dns-route53', '--dns-route53-propagation-seconds', String(propagation || 30)],
    env: c => ({ AWS_ACCESS_KEY_ID: c.accessKeyId, AWS_SECRET_ACCESS_KEY: c.secretAccessKey }),
  },
  hooks: {
    label: 'Custom hook scripts (any DNS host)',
    fields: [
      { key: 'authHook', label: 'Auth hook — absolute path to a script on the manager' },
      { key: 'cleanupHook', label: 'Cleanup hook — absolute path to a script on the manager' },
    ],
    hint: 'certbot runs the auth hook with CERTBOT_DOMAIN and CERTBOT_VALIDATION set; it must create the TXT record ' +
      '_acme-challenge.$CERTBOT_DOMAIN, and the cleanup hook removes it. Use for DNS hosts without a certbot plugin (e.g. Technitium via its API).',
    credentialsFile: null,
    args: (credFile, propagation, c) => [
      '--manual', '--preferred-challenges', 'dns',
      '--manual-auth-hook', c.authHook, '--manual-cleanup-hook', c.cleanupHook,
    ],
    env: () => ({}),
    validate: c => ['authHook', 'cleanupHook'].filter(k => !/^\/[A-Za-z0-9._/-]+$/.test(c[k] || '')).map(k => `${k === 'authHook' ? 'Auth' : 'Cleanup'} hook must be an absolute path`),
  },
};

// Field validation for DNS credentials (values end up in a certbot ini file)
function validateCredentials(provider, creds) {
  const p = DNS_PROVIDERS[provider];
  if (!p) return [`unknown DNS provider ${provider}`];
  const errors = p.validate ? p.validate(creds || {}) : [];
  if (errors.length) return errors;
  for (const f of p.fields) {
    const v = creds && creds[f.key];
    if (!v) errors.push(`${f.label} is required`);
    else if (/[\r\n]/.test(v) || v.length > 512) errors.push(`${f.label} looks invalid`);
  }
  return errors;
}

// Public description for the UI (no functions)
function catalog() {
  return {
    issuers: Object.entries(ISSUERS).map(([id, i]) => ({ id, ...i })),
    dnsProviders: Object.entries(DNS_PROVIDERS).map(([id, p]) => ({ id, label: p.label, fields: p.fields, hint: p.hint || '' })),
  };
}

module.exports = { ISSUERS, DNS_PROVIDERS, validateCredentials, catalog };
