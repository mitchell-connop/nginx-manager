'use strict';

const test   = require('node:test');
const assert = require('node:assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nm-brand-'));
const branding = require('../lib/branding');

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32)]);
const JPG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(32)]);

test('defaults when nothing is configured', () => {
  assert.deepEqual(branding.publicView(), { title: 'Nginx Manager', subtitle: 'Nginx config control', logoUrl: null });
});

test('text is trimmed, length-limited, and the app name never ends up empty', () => {
  const v = branding.updateText({ title: '  My   Proxies ', subtitle: ' Welcome   back ' });
  assert.equal(v.title, 'My Proxies');
  assert.equal(v.subtitle, 'Welcome back');
  assert.equal(branding.updateText({ title: '   ' }).title, 'Nginx Manager');
  assert.throws(() => branding.updateText({ title: 'x'.repeat(41) }), /at most 40/);
  assert.throws(() => branding.updateText({ subtitle: 'x'.repeat(121) }), /at most 120/);
});

test('logo type comes from the content, not the name; SVG and junk refused', () => {
  const v = branding.setLogo(PNG);
  assert.match(v.logoUrl, /^\/branding\/logo\?v=/);
  assert.equal(branding.logoFile().mime, 'image/png');
  branding.setLogo(JPG);
  assert.equal(branding.logoFile().mime, 'image/jpeg');
  assert.deepEqual(fs.readdirSync(path.join(process.env.DATA_DIR, 'branding')), ['logo.jpg'], 'old logo replaced');
  assert.throws(() => branding.setLogo(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')), /PNG, JPEG, WebP or GIF/);
  assert.throws(() => branding.setLogo(Buffer.concat([PNG, Buffer.alloc(branding.MAX_LOGO_BYTES)])), /512 KB/);
  assert.throws(() => branding.setLogo(Buffer.alloc(0)), /No image/);
});

test('remove logo and reset', () => {
  branding.setLogo(PNG);
  assert.equal(branding.clearLogo().logoUrl, null);
  assert.equal(branding.logoFile(), null);
  branding.updateText({ title: 'X', subtitle: 'Y' });
  branding.setLogo(PNG);
  assert.deepEqual(branding.reset(), { title: 'Nginx Manager', subtitle: 'Nginx config control', logoUrl: null });
});
