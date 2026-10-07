/**
 * nginx-manager — lib/branding.js
 *
 * Customisable app name, login text and logo, stored in data/ (never in the repo):
 *   data/branding.json        { title, subtitle, logo: "logo.png" | null, updatedAt }
 *   data/branding/logo.<ext>  uploaded image (PNG, JPEG, WebP or GIF — detected from content)
 *
 * SVG is refused on purpose: served from this origin it could run script if opened directly.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const store = require('./store');

const FILE = path.join(store.DATA_DIR, 'branding.json');
const DIR  = path.join(store.DATA_DIR, 'branding');
const MAX_LOGO_BYTES = 512 * 1024;

const DEFAULTS = { title: 'Nginx Manager', subtitle: 'Nginx config control', logo: null };

const TYPES = [
  { ext: 'png',  mime: 'image/png',  test: b => b.length > 8 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  { ext: 'jpg',  mime: 'image/jpeg', test: b => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { ext: 'webp', mime: 'image/webp', test: b => b.length > 12 && b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP' },
  { ext: 'gif',  mime: 'image/gif',  test: b => b.length > 6 && /^GIF8[79]a$/.test(b.toString('ascii', 0, 6)) },
];

function read() {
  let saved = {};
  try { saved = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
  return { ...DEFAULTS, ...saved };
}

function write(b) {
  const tmp = `${FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ ...b, updatedAt: new Date().toISOString() }, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, FILE);
}

// Public view for the login screen and header
function publicView() {
  const b = read();
  const logoFile = b.logo && fs.existsSync(path.join(DIR, b.logo)) ? b.logo : null;
  return {
    title: b.title,
    subtitle: b.subtitle,
    // cache-busting version so a new upload shows immediately
    logoUrl: logoFile ? `/branding/logo?v=${encodeURIComponent(b.updatedAt || '')}` : null,
  };
}

function cleanText(v, max, field) {
  const s = String(v == null ? '' : v).replace(/\s+/g, ' ').trim();
  if (s.length > max) throw Object.assign(new Error(`${field} must be at most ${max} characters`), { status: 400 });
  return s;
}

function updateText({ title, subtitle }) {
  const b = read();
  if (title !== undefined) b.title = cleanText(title, 40, 'App name') || DEFAULTS.title;
  if (subtitle !== undefined) b.subtitle = cleanText(subtitle, 120, 'Login text');
  write(b);
  return publicView();
}

function setLogo(buf) {
  if (!buf || !buf.length) throw Object.assign(new Error('No image uploaded'), { status: 400 });
  if (buf.length > MAX_LOGO_BYTES) throw Object.assign(new Error('Logo must be 512 KB or smaller'), { status: 400 });
  const type = TYPES.find(t => t.test(buf));
  if (!type) throw Object.assign(new Error('Logo must be a PNG, JPEG, WebP or GIF image'), { status: 400 });
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  for (const f of fs.readdirSync(DIR)) if (/^logo\./.test(f)) fs.unlinkSync(path.join(DIR, f));
  const name = `logo.${type.ext}`;
  fs.writeFileSync(path.join(DIR, name), buf, { mode: 0o600 });
  const b = read();
  b.logo = name;
  write(b);
  return publicView();
}

function clearLogo() {
  const b = read();
  if (b.logo) { try { fs.unlinkSync(path.join(DIR, b.logo)); } catch {} }
  b.logo = null;
  write(b);
  return publicView();
}

function reset() {
  clearLogo();
  write({ ...DEFAULTS });
  return publicView();
}

// { path, mime } of the current logo, or null
function logoFile() {
  const b = read();
  if (!b.logo) return null;
  const p = path.join(DIR, path.basename(b.logo));
  if (!fs.existsSync(p)) return null;
  const type = TYPES.find(t => t.ext === path.extname(p).slice(1));
  return type ? { path: p, mime: type.mime } : null;
}

module.exports = { DEFAULTS, MAX_LOGO_BYTES, read, publicView, updateText, setLogo, clearLogo, reset, logoFile };
