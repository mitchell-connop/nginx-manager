/**
 * nginx-manager — lib/store.js
 *
 * On-disk state under ./data (never committed — see .gitignore):
 *   agents.json             manually-added nginx servers (token stored as a SHA-256 hash only)
 *   state/<agentId>.json    file overview reported by the agent ("live") + unpushed edits ("draft")
 *   blobs/<sha256hex>       file contents, content-addressed
 *   certs/<agentId>.json    certificate registry
 *   sites/<agentId>/*.json  visual-builder site definitions
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const DATA_DIR   = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const AGENTS_FILE = path.join(DATA_DIR, 'agents.json');
const STATE_DIR  = path.join(DATA_DIR, 'state');
const BLOBS_DIR  = path.join(DATA_DIR, 'blobs');
const CERTS_DIR  = path.join(DATA_DIR, 'certs');
const SITES_DIR  = path.join(DATA_DIR, 'sites');

[DATA_DIR, STATE_DIR, BLOBS_DIR, CERTS_DIR, SITES_DIR].forEach(d => {
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
});
if (!fs.existsSync(AGENTS_FILE)) fs.writeFileSync(AGENTS_FILE, '[]\n', { mode: 0o600 });

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

// Write via rename so a crash never leaves a half-written JSON file behind.
function writeJson(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

// ---------------------------------------------------------------------------
// Hashing — must match NGINX Agent (pkg/files: base64(sha256(contents)))
// ---------------------------------------------------------------------------
function fileHash(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
}

// pkg/files GenerateConfigVersion: hash of the concatenated file hashes sorted by name
function configVersion(files) {
  const joined = [...files]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map(f => f.hash).join('');
  return fileHash(Buffer.from(joined));
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function newToken() {
  return crypto.randomBytes(32).toString('base64url');
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------
function readAgents() { return readJson(AGENTS_FILE, []); }
function writeAgents(agents) { writeJson(AGENTS_FILE, agents); }

function findAgent(id) { return readAgents().find(a => a.id === id) || null; }

function findAgentByToken(token) {
  if (!token) return null;
  const want = Buffer.from(hashToken(token), 'hex');
  return readAgents().find(a => {
    if (!a.tokenHash) return false;
    const have = Buffer.from(a.tokenHash, 'hex');
    return have.length === want.length && crypto.timingSafeEqual(have, want);
  }) || null;
}

function updateAgent(id, patch) {
  const agents = readAgents();
  const idx = agents.findIndex(a => a.id === id);
  if (idx === -1) return null;
  agents[idx] = { ...agents[idx], ...patch, id: agents[idx].id };
  writeAgents(agents);
  return agents[idx];
}

function removeAgentData(id) {
  for (const p of [path.join(STATE_DIR, `${id}.json`), path.join(CERTS_DIR, `${id}.json`)]) {
    try { fs.unlinkSync(p); } catch {}
  }
  fs.rmSync(path.join(SITES_DIR, id), { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Blobs
// ---------------------------------------------------------------------------
function blobPath(hash) {
  return path.join(BLOBS_DIR, Buffer.from(hash, 'base64').toString('hex'));
}

function putBlob(buf) {
  const hash = fileHash(buf);
  const p = blobPath(hash);
  if (!fs.existsSync(p)) fs.writeFileSync(p, buf, { mode: 0o600 });
  return hash;
}

function getBlob(hash) {
  try { return fs.readFileSync(blobPath(hash)); }
  catch { return null; }
}

function hasBlob(hash) { return !!hash && fs.existsSync(blobPath(hash)); }

// ---------------------------------------------------------------------------
// File state per agent
//   live:  { [absPath]: FileEntry }  — what the agent last reported
//   draft: { [absPath]: FileEntry | { name, deleted: true } } — pending changes
//   FileEntry = { name, hash, permissions, size, modifiedTime, unmanaged, certificateMeta? }
// ---------------------------------------------------------------------------
function statePath(agentId) { return path.join(STATE_DIR, `${agentId}.json`); }

function readState(agentId) {
  return readJson(statePath(agentId), { instanceId: null, configPath: null, live: {}, draft: {} });
}

function writeState(agentId, st) { writeJson(statePath(agentId), st); }

// Merged view: live overlaid with draft (deleted entries removed).
function desiredFiles(st) {
  const out = { ...st.live };
  for (const [name, d] of Object.entries(st.draft)) {
    if (d.deleted) delete out[name];
    else out[name] = d;
  }
  return out;
}

function stageFile(agentId, name, contents, permissions) {
  const st  = readState(agentId);
  const buf = Buffer.isBuffer(contents) ? contents : Buffer.from(contents, 'utf8');
  const hash = putBlob(buf);
  const prev = st.draft[name] && !st.draft[name].deleted ? st.draft[name] : st.live[name];
  if (st.live[name] && st.live[name].hash === hash) {
    delete st.draft[name];            // edited back to what is live — nothing pending
  } else {
    st.draft[name] = {
      name, hash, size: buf.length,
      permissions: permissions || (prev && prev.permissions) || '0644',
      modifiedTime: new Date().toISOString(),
      unmanaged: false,
    };
  }
  writeState(agentId, st);
  return st;
}

function stageDelete(agentId, name) {
  const st = readState(agentId);
  if (st.live[name]) st.draft[name] = { name, deleted: true };
  else delete st.draft[name];
  writeState(agentId, st);
  return st;
}

// ---------------------------------------------------------------------------
// Certificates registry & sites
// ---------------------------------------------------------------------------
function readCerts(agentId) { return readJson(path.join(CERTS_DIR, `${agentId}.json`), []); }
function writeCerts(agentId, certs) { writeJson(path.join(CERTS_DIR, `${agentId}.json`), certs); }

function sitesDir(agentId) {
  const d = path.join(SITES_DIR, agentId);
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  return d;
}

function readSites(agentId) {
  const dir = sitesDir(agentId);
  return fs.readdirSync(dir).filter(f => f.endsWith('.json'))
    .map(f => readJson(path.join(dir, f), null)).filter(Boolean);
}

function readSite(agentId, siteId) {
  return readJson(path.join(sitesDir(agentId), `${path.basename(siteId)}.json`), null);
}

function writeSite(agentId, site) {
  writeJson(path.join(sitesDir(agentId), `${path.basename(site.id)}.json`), site);
}

function deleteSite(agentId, siteId) {
  try { fs.unlinkSync(path.join(sitesDir(agentId), `${path.basename(siteId)}.json`)); return true; }
  catch { return false; }
}

module.exports = {
  DATA_DIR,
  fileHash, configVersion, hashToken, newToken,
  readAgents, writeAgents, findAgent, findAgentByToken, updateAgent, removeAgentData,
  putBlob, getBlob, hasBlob,
  readState, writeState, desiredFiles, stageFile, stageDelete,
  readCerts, writeCerts,
  readSites, readSite, writeSite, deleteSite,
};
