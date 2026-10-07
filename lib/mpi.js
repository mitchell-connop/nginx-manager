/**
 * nginx-manager — lib/mpi.js
 *
 * Management-plane side of the NGINX Agent v3 gRPC protocol (mpi.v1, protos in ./proto).
 * Agents dial in to us; we never connect out or hold host credentials.
 *
 *   CommandService.CreateConnection / UpdateDataPlaneStatus / UpdateDataPlaneHealth
 *   CommandService.Subscribe   bidi stream: we send ConfigApply/ConfigUpload/Health requests,
 *                              the agent answers with DataPlaneResponse (matched by correlation id)
 *   FileService.UpdateOverview agent reports its file set; we reply with the files we lack
 *   FileService.UpdateFile(Stream) agent uploads file contents
 *   FileService.GetFile(Stream) agent downloads contents during a config apply
 *
 * Every RPC must carry a per-agent token in the `authorization` metadata. Tokens are
 * issued when a server is added manually in the UI — unknown agents are rejected.
 */

'use strict';

const path         = require('path');
const EventEmitter = require('events');
const grpc         = require('@grpc/grpc-js');
const protoLoader  = require('@grpc/proto-loader');
const { randomUUID: uuidv4 } = require('crypto');
const store        = require('./store');

const PROTO_DIR = path.join(__dirname, '..', 'proto');
const pkgDef = protoLoader.loadSync(
  ['mpi/v1/command.proto', 'mpi/v1/files.proto'],
  { includeDirs: [PROTO_DIR], keepCase: false, longs: String, enums: String, defaults: true, oneofs: true },
);
const mpi = grpc.loadPackageDefinition(pkgDef).mpi.v1;

const APPLY_TIMEOUT_MS  = 180 * 1000;
const UPLOAD_TIMEOUT_MS = 120 * 1000;
const HEALTH_INTERVAL_MS = 60 * 1000;
const STREAM_CHUNK_SIZE = 1024 * 1024;
const MAX_MESSAGE_BYTES = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------
function now() {
  const ms = Date.now();
  return { seconds: String(Math.floor(ms / 1000)), nanos: (ms % 1000) * 1e6 };
}

function tsToIso(ts) {
  if (!ts || ts.seconds === undefined) return null;
  return new Date(Number(ts.seconds) * 1000 + Math.floor((ts.nanos || 0) / 1e6)).toISOString();
}

function isoToTs(iso) {
  const ms = iso ? Date.parse(iso) : NaN;
  if (Number.isNaN(ms)) return null;
  return { seconds: String(Math.floor(ms / 1000)), nanos: (ms % 1000) * 1e6 };
}

function meta(correlationId) {
  return { messageId: uuidv4(), correlationId: correlationId || uuidv4(), timestamp: now() };
}

function certSummary(cm) {
  if (!cm) return null;
  return {
    subject: cm.subject ? cm.subject.commonName : '',
    issuer:  cm.issuer ? cm.issuer.commonName : '',
    dnsNames: cm.sans ? cm.sans.dnsNames : [],
    notBefore: cm.dates && Number(cm.dates.notBefore) ? new Date(Number(cm.dates.notBefore) * 1000).toISOString() : null,
    notAfter:  cm.dates && Number(cm.dates.notAfter)  ? new Date(Number(cm.dates.notAfter)  * 1000).toISOString() : null,
    serial: cm.serialNumber || '',
  };
}

function fromProtoFile(f) {
  const m = f.fileMeta || {};
  return {
    name: m.name,
    hash: m.hash,
    permissions: m.permissions || '0644',
    size: Number(m.size || 0),
    modifiedTime: tsToIso(m.modifiedTime),
    unmanaged: !!f.unmanaged,
    certificateMeta: certSummary(m.certificateMeta),
  };
}

function toProtoFile(e) {
  return {
    fileMeta: {
      name: e.name,
      hash: e.hash,
      permissions: e.permissions || '0644',
      size: String(e.size || 0),
      modifiedTime: isoToTs(e.modifiedTime),
    },
    unmanaged: !!e.unmanaged,
  };
}

function summarizeResource(resource) {
  const info = resource.hostInfo || resource.containerInfo || {};
  const rel  = info.releaseInfo || {};
  const instances = (resource.instances || []).map(i => {
    const im = i.instanceMeta || {};
    const rt = i.instanceRuntime || {};
    return {
      instanceId: im.instanceId,
      type: im.instanceType,
      version: im.version,
      processId: rt.processId,
      binaryPath: rt.binaryPath,
      configPath: rt.configPath,
    };
  });
  return {
    resourceId: resource.resourceId,
    hostname: info.hostname || '',
    os: [rel.name, rel.versionId || rel.version].filter(Boolean).join(' '),
    instances,
  };
}

function primaryNginx(instances) {
  return instances.find(i => i.type === 'INSTANCE_TYPE_NGINX_PLUS')
      || instances.find(i => i.type === 'INSTANCE_TYPE_NGINX')
      || null;
}

// ---------------------------------------------------------------------------
// Management plane
// ---------------------------------------------------------------------------
class ManagementPlane extends EventEmitter {
  constructor({ tls, port, host }) {
    super();
    this.tls  = tls;
    this.port = port;
    this.host = host || '0.0.0.0';
    this.streams = new Map();   // agentId -> Subscribe call
    this.pending = new Map();   // correlationId -> { agentId, kind, onResponse }
    this.busy    = new Set();   // agentIds with an apply/upload in flight
    this.health  = new Map();   // agentId -> [{ instanceId, status, description, at }]
    this.pendingUploads = new Map(); // agentId -> correlation id of an overview awaiting uploads
  }

  start() {
    const server = new grpc.Server({
      'grpc.max_receive_message_length': MAX_MESSAGE_BYTES,
      'grpc.max_send_message_length': MAX_MESSAGE_BYTES,
      'grpc.keepalive_permit_without_calls': 1,
      'grpc.http2.min_ping_interval_without_data_ms': 5000,
    });

    server.addService(mpi.CommandService.service, {
      createConnection:      this.wrapUnary('CreateConnection', this.createConnection),
      updateDataPlaneStatus: this.wrapUnary('UpdateDataPlaneStatus', this.updateDataPlaneStatus),
      updateDataPlaneHealth: this.wrapUnary('UpdateDataPlaneHealth', this.updateDataPlaneHealth),
      subscribe:             call => this.subscribe(call),
    });

    server.addService(mpi.FileService.service, {
      getOverview:      this.wrapUnary('GetOverview', this.getOverview),
      updateOverview:   this.wrapUnary('UpdateOverview', this.updateOverview),
      getFile:          this.wrapUnary('GetFile', this.getFile),
      updateFile:       this.wrapUnary('UpdateFile', this.updateFile),
      getFileStream:    call => this.getFileStream(call),
      updateFileStream: (call, cb) => this.updateFileStream(call, cb),
    });

    const creds = grpc.ServerCredentials.createSsl(null, [{ cert_chain: this.tls.cert, private_key: this.tls.key }], false);
    return new Promise((resolve, reject) => {
      server.bindAsync(`${this.host}:${this.port}`, creds, (err, port) => {
        if (err) return reject(err);
        this.server = server;
        this.healthTimer = setInterval(() => {
          for (const agentId of this.streams.keys()) this.requestHealth(agentId);
        }, HEALTH_INTERVAL_MS);
        this.healthTimer.unref();
        console.log(`[nginx-manager] Agent gRPC (TLS) listening on ${this.host}:${port}`);
        resolve(port);
      });
    });
  }

  stop() {
    clearInterval(this.healthTimer);
    if (this.server) this.server.forceShutdown();
  }

  // ── auth ──────────────────────────────────────────────────────────────────
  authenticate(call) {
    const token = (call.metadata.get('authorization')[0] || '').toString().replace(/^Bearer\s+/i, '').trim();
    const agent = store.findAgentByToken(token);
    if (!agent) {
      const peer = typeof call.getPeer === 'function' ? call.getPeer() : 'unknown';
      console.warn(`[nginx-manager] Rejected agent connection from ${peer}: unknown or missing token`);
      const err = new Error('unknown or missing agent token — add this server in nginx-manager first');
      err.code = grpc.status.UNAUTHENTICATED;
      throw err;
    }
    return agent;
  }

  wrapUnary(name, fn) {
    return (call, callback) => {
      let agent;
      try { agent = this.authenticate(call); }
      catch (err) { return callback(err); }
      Promise.resolve()
        .then(() => fn.call(this, agent, call.request, call))
        .then(res => callback(null, res))
        .catch(err => {
          if (err.code === undefined) {
            console.error(`[nginx-manager] ${name} failed for ${agent.name}:`, err);
            err.code = grpc.status.INTERNAL;
          }
          callback(err);
        });
    };
  }

  log(agentId, line) {
    this.emit('log', agentId, line.endsWith('\n') ? line : line + '\n');
  }

  touch(agentId, patch = {}) {
    store.updateAgent(agentId, { ...patch, lastSeen: new Date().toISOString() });
    this.emit('agents');
  }

  // ── CommandService ────────────────────────────────────────────────────────
  recordResource(agent, resource) {
    const res = summarizeResource(resource || {});
    const nginx = primaryNginx(res.instances);
    const agentInst = res.instances.find(i => i.type === 'INSTANCE_TYPE_AGENT');
    this.touch(agent.id, {
      resourceId: res.resourceId,
      hostname: res.hostname,
      os: res.os,
      agentVersion: agentInst ? agentInst.version : agent.agentVersion,
      nginxVersion: nginx ? nginx.version : null,
      nginxType: nginx ? nginx.type : null,
      instanceId: nginx ? nginx.instanceId : null,
      configPath: nginx ? nginx.configPath : null,
    });
    if (nginx) {
      const st = store.readState(agent.id);
      if (st.instanceId !== nginx.instanceId || st.configPath !== nginx.configPath) {
        st.instanceId = nginx.instanceId;
        st.configPath = nginx.configPath;
        store.writeState(agent.id, st);
      }
    }
    return { res, nginx };
  }

  createConnection(agent, req) {
    const { res, nginx } = this.recordResource(agent, req.resource);
    this.log(agent.id, `🔌 Agent connected from ${res.hostname || 'unknown host'}` +
      (nginx ? ` — nginx ${nginx.version} (${nginx.configPath})` : ' — no nginx instance detected yet'));
    return { response: { status: 'COMMAND_STATUS_OK', message: 'Success' } };
  }

  updateDataPlaneStatus(agent, req) {
    this.recordResource(agent, req.resource);
    return {};
  }

  updateDataPlaneHealth(agent, req) {
    const at = new Date().toISOString();
    this.health.set(agent.id, (req.instanceHealths || []).map(h => ({
      instanceId: h.instanceId,
      status: (h.instanceHealthStatus || '').replace('INSTANCE_HEALTH_STATUS_', '').toLowerCase(),
      description: h.description,
      at,
    })));
    this.touch(agent.id);
    return {};
  }

  subscribe(call) {
    let agent;
    try { agent = this.authenticate(call); }
    catch (err) { call.destroy(err); return; }

    const prev = this.streams.get(agent.id);
    if (prev && prev !== call) { try { prev.end(); } catch {} }
    this.streams.set(agent.id, call);
    this.touch(agent.id);
    this.requestHealth(agent.id);

    call.on('data', msg => this.onDataPlaneResponse(agent.id, msg));
    const drop = () => {
      if (this.streams.get(agent.id) === call) {
        this.streams.delete(agent.id);
        this.log(agent.id, '⚠️  Agent disconnected');
        this.emit('agents');
      }
    };
    call.on('end', () => { drop(); try { call.end(); } catch {} });
    call.on('error', drop);
    call.on('cancelled', drop);
  }

  onDataPlaneResponse(agentId, msg) {
    const corr = msg.messageMeta && msg.messageMeta.correlationId;
    const p = corr && this.pending.get(corr);
    if (p && p.agentId === agentId) p.onResponse(msg);
    this.touch(agentId);
  }

  isOnline(agentId) { return this.streams.has(agentId); }

  send(agentId, request) {
    const call = this.streams.get(agentId);
    if (!call) throw new Error('Agent is not connected');
    call.write(request);
  }

  requestHealth(agentId) {
    try { this.send(agentId, { messageMeta: meta(), healthRequest: {} }); }
    catch {}
  }

  // Send a request and resolve when the agent sends a terminal response.
  roundTrip(agentId, kind, request, timeoutMs, label) {
    const corr = request.messageMeta.correlationId;
    return new Promise((resolve) => {
      const finish = result => {
        clearTimeout(timer);
        this.pending.delete(corr);
        resolve(result);
      };
      const timer = setTimeout(() => {
        this.log(agentId, `❌ ${label}: no response from agent after ${timeoutMs / 1000}s`);
        finish({ success: false, output: 'Timed out waiting for agent' });
      }, timeoutMs);

      this.pending.set(corr, {
        agentId, kind,
        onResponse: (msg) => {
          const r = msg.commandResponse || {};
          const st = (r.status || '').replace('COMMAND_STATUS_', '');
          const text = [r.message, r.error].filter(Boolean).join(' — ');
          if (st === 'OK') {
            this.log(agentId, `✅ ${text}`);
            finish({ success: true, output: text });
          } else if (st === 'FAILURE') {
            this.log(agentId, `❌ ${text}`);
            finish({ success: false, output: text });
          } else {
            // IN_PROGRESS, or ERROR ("rolling back") which is followed by a final FAILURE
            this.log(agentId, `${st === 'ERROR' ? '⚠️ ' : '⏳'} ${text}`);
          }
        },
      });

      try { this.send(agentId, request); }
      catch (err) {
        this.log(agentId, `❌ ${label}: ${err.message}`);
        finish({ success: false, output: err.message });
      }
    });
  }

  async withLock(agentId, fn) {
    if (this.busy.has(agentId)) {
      this.log(agentId, '⏳ Another operation is already running for this server');
      return { success: false, output: 'Another operation is already running' };
    }
    this.busy.add(agentId);
    try { return await fn(); }
    finally { this.busy.delete(agentId); }
  }

  // Push the desired file set (live + draft). The agent writes the changed files,
  // runs `nginx -t`, reloads, and rolls back automatically on any failure.
  configApply(agentId) {
    return this.withLock(agentId, async () => {
      const st = store.readState(agentId);
      if (!st.instanceId) {
        this.log(agentId, '❌ No nginx instance reported by this agent yet');
        return { success: false, output: 'No nginx instance known for this server' };
      }
      const desired = store.desiredFiles(st);
      const files = Object.values(desired);
      const missing = files.filter(f => !f.unmanaged && !store.hasBlob(f.hash));
      if (missing.length) {
        const names = missing.map(f => f.name).join(', ');
        this.log(agentId, `❌ Contents not yet synced from agent for: ${names} — run Sync first`);
        return { success: false, output: 'Some file contents are missing — run Sync first' };
      }

      const changes = Object.values(st.draft);
      this.log(agentId, `📤 Applying config to nginx (${changes.length} change${changes.length === 1 ? '' : 's'}):`);
      for (const c of changes) this.log(agentId, `   ${c.deleted ? '−' : st.live[c.name] ? '~' : '+'} ${c.name}`);

      const versionedFiles = files.map(f => ({ name: f.name, hash: f.hash }));
      const request = {
        messageMeta: meta(),
        configApplyRequest: {
          overview: {
            files: files.map(toProtoFile),
            configVersion: { instanceId: st.instanceId, version: store.configVersion(versionedFiles) },
            configPath: st.configPath || '',
          },
        },
      };
      const result = await this.roundTrip(agentId, 'apply', request, APPLY_TIMEOUT_MS, 'Config apply');

      if (result.success) {
        const now = store.readState(agentId);
        for (const c of changes) {
          if (now.draft[c.name] !== undefined && JSON.stringify(now.draft[c.name]) === JSON.stringify(c)) {
            if (c.deleted) delete now.live[c.name];
            else now.live[c.name] = c;
            delete now.draft[c.name];
          }
        }
        store.writeState(agentId, now);
        this.emit('files', agentId);
      }
      return result;
    });
  }

  // Ask the agent to (re)upload its current files.
  configUpload(agentId) {
    return this.withLock(agentId, async () => {
      const st = store.readState(agentId);
      if (!st.instanceId) {
        this.log(agentId, '❌ No nginx instance reported by this agent yet');
        return { success: false, output: 'No nginx instance known for this server' };
      }
      const files = Object.values(st.live);
      this.log(agentId, `🔄 Asking agent to upload ${files.length} file${files.length === 1 ? '' : 's'}...`);
      const request = {
        messageMeta: meta(),
        configUploadRequest: {
          overview: {
            files: files.map(toProtoFile),
            configVersion: { instanceId: st.instanceId, version: store.configVersion(files) },
            configPath: st.configPath || '',
          },
        },
      };
      const result = await this.roundTrip(agentId, 'upload', request, UPLOAD_TIMEOUT_MS, 'Config upload');
      this.emit('files', agentId);
      return result;
    });
  }

  // ── FileService ───────────────────────────────────────────────────────────
  checkInstance(agent, instanceId) {
    const st = store.readState(agent.id);
    if (!st.instanceId && instanceId) {
      st.instanceId = instanceId;
      store.writeState(agent.id, st);
    }
    return st.instanceId === instanceId ? st : null;
  }

  getOverview(agent, req) {
    const instanceId = req.configVersion ? req.configVersion.instanceId : '';
    const st = this.checkInstance(agent, instanceId);
    if (!st) return { overview: { files: [], configVersion: req.configVersion } };
    const files = Object.values(st.live);
    return {
      overview: {
        files: files.map(toProtoFile),
        configVersion: { instanceId, version: store.configVersion(files) },
        configPath: st.configPath || '',
      },
    };
  }

  updateOverview(agent, req) {
    const ov = req.overview || {};
    const instanceId = ov.configVersion ? ov.configVersion.instanceId : '';
    const st = this.checkInstance(agent, instanceId);
    if (!st) {
      // A second nginx instance on the same host — we only manage the primary one.
      return { overview: { files: [], configVersion: ov.configVersion } };
    }

    const files = (ov.files || []).map(fromProtoFile).filter(f => f.name);
    // After uploading the files we asked for, the agent re-sends an overview of just those
    // files under the same correlation id; any other overview is its complete file set.
    const corr = req.messageMeta ? req.messageMeta.correlationId : '';
    if (corr && this.pendingUploads.get(agent.id) === corr) {
      // The follow-up echoes our delta reply, which carries no certificate metadata.
      for (const f of files) {
        const prev = st.live[f.name];
        st.live[f.name] = { ...f, certificateMeta: f.certificateMeta || (prev && prev.certificateMeta) || null };
      }
      this.pendingUploads.delete(agent.id);
    } else {
      st.live = Object.fromEntries(files.map(f => [f.name, f]));
    }
    if (ov.configPath) st.configPath = ov.configPath;

    // Drop draft edits that the server now already matches.
    for (const [name, d] of Object.entries(st.draft)) {
      if (d.deleted ? !st.live[name] : (st.live[name] && st.live[name].hash === d.hash)) delete st.draft[name];
    }
    store.writeState(agent.id, st);

    const delta = files.filter(f => !f.unmanaged && !store.hasBlob(f.hash));
    if (delta.length) {
      this.pendingUploads.set(agent.id, corr);
      this.log(agent.id, `⬇ Agent reported ${files.length} files; requesting ${delta.length} new/changed`);
    } else {
      this.log(agent.id, `✅ File overview in sync (${files.length} files)`);
    }
    this.touch(agent.id);
    this.emit('files', agent.id);

    return {
      overview: {
        files: delta.map(toProtoFile),
        configVersion: ov.configVersion,
        configPath: ov.configPath || '',
      },
    };
  }

  acceptUpload(agent, fileMeta, buf) {
    const hash = store.putBlob(buf);
    if (fileMeta.hash && fileMeta.hash !== hash) {
      console.warn(`[nginx-manager] ${agent.name}: hash mismatch for ${fileMeta.name} (agent ${fileMeta.hash}, computed ${hash})`);
    }
    const st = store.readState(agent.id);
    if (fileMeta.name) {
      const prev = st.live[fileMeta.name] || {};
      st.live[fileMeta.name] = {
        ...prev,
        name: fileMeta.name,
        hash,
        permissions: fileMeta.permissions || prev.permissions || '0644',
        size: buf.length,
        modifiedTime: tsToIso(fileMeta.modifiedTime) || prev.modifiedTime || null,
        unmanaged: false,
        certificateMeta: certSummary(fileMeta.certificateMeta) || prev.certificateMeta || null,
      };
      store.writeState(agent.id, st);
    }
    this.touch(agent.id);
    this.emit('files', agent.id);
    return { fileMeta: { ...fileMeta, hash } };
  }

  updateFile(agent, req) {
    const fileMeta = (req.file && req.file.fileMeta) || {};
    const buf = (req.contents && req.contents.contents) || Buffer.alloc(0);
    return this.acceptUpload(agent, fileMeta, Buffer.from(buf));
  }

  updateFileStream(call, callback) {
    let agent;
    try { agent = this.authenticate(call); }
    catch (err) { return callback(err); }
    let header = null;
    const chunks = [];
    call.on('data', chunk => {
      if (chunk.header) header = chunk.header;
      else if (chunk.content) chunks[chunk.content.chunkId] = Buffer.from(chunk.content.data || []);
    });
    call.on('error', () => {});
    call.on('end', () => {
      if (!header) {
        return callback({ code: grpc.status.INVALID_ARGUMENT, message: 'missing file header chunk' });
      }
      try { callback(null, this.acceptUpload(agent, header.fileMeta || {}, Buffer.concat(chunks.filter(Boolean)))); }
      catch (err) { callback({ code: grpc.status.INTERNAL, message: err.message }); }
    });
  }

  // Only serve blobs that belong to this agent's own desired/live file set.
  lookupFile(agent, fileMeta) {
    const st = store.readState(agent.id);
    const name = fileMeta && fileMeta.name;
    const hash = fileMeta && fileMeta.hash;
    const known = [st.live[name], st.draft[name]].some(e => e && !e.deleted && e.hash === hash);
    if (!known) return null;
    return store.getBlob(hash);
  }

  getFile(agent, req) {
    const buf = this.lookupFile(agent, req.fileMeta);
    if (!buf) {
      const err = new Error(`file not found: ${req.fileMeta && req.fileMeta.name}`);
      err.code = grpc.status.NOT_FOUND;
      throw err;
    }
    return { contents: { contents: buf } };
  }

  getFileStream(call) {
    let agent;
    try { agent = this.authenticate(call); }
    catch (err) { call.destroy(err); return; }
    const fileMeta = call.request.fileMeta || {};
    const buf = this.lookupFile(agent, fileMeta);
    if (!buf) {
      call.destroy({ code: grpc.status.NOT_FOUND, message: `file not found: ${fileMeta.name}` });
      return;
    }
    const chunks = Math.max(1, Math.ceil(buf.length / STREAM_CHUNK_SIZE));
    call.write({ meta: meta(), header: { fileMeta, chunks, chunkSize: STREAM_CHUNK_SIZE } });
    for (let i = 0; i < chunks; i++) {
      call.write({ meta: meta(), content: { chunkId: i, data: buf.subarray(i * STREAM_CHUNK_SIZE, (i + 1) * STREAM_CHUNK_SIZE) } });
    }
    call.end();
  }
}

module.exports = { ManagementPlane, mpi };
