'use strict';

const crypto = require('crypto');
const net = require('net');

const DEFAULT_URL = 'https://monitor.reoos.ir/api/v2ray-session/telemetry';

function normalizeIp(raw) {
  let value = String(raw || '').trim();
  if (!value) return '';
  if (value.startsWith('::ffff:')) value = value.slice(7);
  const zone = value.indexOf('%');
  if (zone !== -1) value = value.slice(0, zone);
  return net.isIP(value) ? value : '';
}

function ipCandidates(raw) {
  return String(raw || '')
    .split(',')
    .map((x) => normalizeIp(x))
    .filter(Boolean);
}

function isNonPublicIp(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true;
    if (p[0] >= 224) return true;
    return false;
  }
  if (kind === 6) {
    const v = ip.toLowerCase();
    if (v === '::' || v === '::1') return true;
    if (v.startsWith('fc') || v.startsWith('fd')) return true;
    if (/^fe[89ab]/.test(v)) return true;
    return false;
  }
  return true;
}

function sourceIp(req, route = '') {
  const h = (req && req.headers) || {};
  const r = String(route || '').trim().toLowerCase();

  const singleHeaders = (r === 'arvan' || r.startsWith('direct-'))
    ? [h['ar-real-ip'], h['x-client-ip'], h['x-real-ip']]
    : [h['x-real-ip'], h['x-client-ip'], h['ar-real-ip']];

  const privateFallback = [];
  for (const raw of singleHeaders) {
    for (const ip of ipCandidates(raw)) {
      if (!isNonPublicIp(ip)) return ip;
      if (!privateFallback.includes(ip)) privateFallback.push(ip);
    }
  }

  const forwarded = ipCandidates(h['x-forwarded-for']).reverse();
  for (const ip of forwarded) {
    if (!isNonPublicIp(ip)) return ip;
    if (!privateFallback.includes(ip)) privateFallback.push(ip);
  }

  const remote = normalizeIp(req && req.socket && req.socket.remoteAddress);
  if (remote && !isNonPublicIp(remote)) return remote;
  if (remote && !privateFallback.includes(remote)) privateFallback.push(remote);

  return privateFallback[0] || '';
}

function uuidFromHeader(header) {
  if (!Buffer.isBuffer(header) || header.length < 17) return '';
  const b = header.subarray(1, 17);
  const hex = b.toString('hex');
  if (hex.length !== 32) return '';
  return (
    hex.slice(0, 8) + '-' +
    hex.slice(8, 12) + '-' +
    hex.slice(12, 16) + '-' +
    hex.slice(16, 20) + '-' +
    hex.slice(20)
  ).toLowerCase();
}

function uuidHash(uuid) {
  return crypto.createHash('sha256').update(uuid).digest('hex');
}

function proof(uuid, hash, ip, route, event, ts, sessionId) {
  const message = [hash, ip, route, event, String(ts), sessionId].join('|');
  return crypto.createHmac('sha256', uuid).update(message).digest('hex');
}

async function postTelemetry(url, payload, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function waitForBytes(stream, needed, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream.removeListener('readable', onReadable);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
      if (err) reject(err); else resolve(value);
    };
    const onReadable = () => {
      const chunk = stream.read(needed);
      if (!chunk) return;
      try { stream.unshift(chunk); } catch {}
      finish(null, chunk);
    };
    const onEnd = () => finish(new Error('stream ended before VLESS header'));
    const onError = (err) => finish(err || new Error('stream error'));
    const timer = setTimeout(
      () => finish(new Error('timeout waiting for VLESS header')),
      timeoutMs
    );
    stream.on('readable', onReadable);
    stream.once('end', onEnd);
    stream.once('error', onError);
    onReadable();
  });
}

function createSessionGuard(options = {}) {
  const route = String(options.route || 'parspack').trim().toLowerCase();
  const telemetryUrl = String(options.telemetryUrl || DEFAULT_URL).trim();
  const heartbeatMs = Number(options.heartbeatMs || 5000);
  const requestTimeoutMs = Number(options.requestTimeoutMs || 1800);
  const enabled = String(process.env.CONCURRENCY_GUARD || '1') !== '0';

  async function emit(meta, event) {
    if (!enabled || !meta) return null;
    const ts = Math.floor(Date.now() / 1000);
    const payload = {
      uuid_hash: meta.hash,
      source_ip: meta.ip,
      route,
      event,
      ts,
      session_id: meta.sessionId,
      proof: proof(meta.uuid, meta.hash, meta.ip, route, event, ts, meta.sessionId),
    };
    return postTelemetry(telemetryUrl, payload, requestTimeoutMs);
  }

  const sessionGroups = new Map();

  function stopGroup(key, group) {
    if (!group || group.stopped) return;
    group.stopped = true;
    if (group.timer) clearInterval(group.timer);
    if (sessionGroups.get(key) === group) sessionGroups.delete(key);
    emit(group.meta, 'close').catch(() => {});
  }

  function startGroupHeartbeat(key, group) {
    if (group.timer || group.stopped) return;
    group.timer = setInterval(async () => {
      if (group.stopped || group.heartbeatRunning || group.sockets.size === 0) return;
      group.heartbeatRunning = true;
      try {
        let state = await emit(group.meta, 'heartbeat');
        if (!group.stopped && state && state.known && state.session_known === false) {
          state = await emit(group.meta, 'open');
        }
        if (state && state.locked) {
          group.locked = true;
          for (const socket of [...group.sockets]) {
            try { socket.terminate(); } catch {}
          }
          stopGroup(key, group);
        }
      } finally {
        group.heartbeatRunning = false;
      }
    }, heartbeatMs);
    if (group.timer.unref) group.timer.unref();
  }

  async function authorizeHeader(header, ws, req) {
    if (!enabled) return {ok: true, guarded: false};

    const ip = sourceIp(req, route);
    if (!ip) {
      return {ok: true, guarded: false, reason: 'source_ip_unavailable'};
    }

    const uuid = uuidFromHeader(header);
    if (!uuid) {
      return {ok: false, guarded: true, reason: 'invalid_vless_uuid'};
    }

    const hash = uuidHash(uuid);
    const key = hash + '|' + ip;
    let group = sessionGroups.get(key);

    if (!group || group.stopped) {
      const meta = {
        uuid,
        hash,
        ip,
        sessionId: crypto.randomBytes(12).toString('hex'),
      };
      group = {
        meta,
        sockets: new Set(),
        timer: null,
        heartbeatRunning: false,
        stopped: false,
        locked: false,
        decision: null,
        authPromise: null,
      };
      group.authPromise = (async () => {
        const opened = await emit(meta, 'open');
        if (opened && opened.locked) {
          group.locked = true;
          group.decision = {
            ok: false,
            guarded: true,
            reason: opened.reason || 'concurrency_locked',
            activeSources: Number(opened.active_sources || 0),
          };
          return group.decision;
        }

        group.decision = {
          ok: true,
          guarded: true,
          activeSources: opened ? Number(opened.active_sources || 0) : null,
        };
        startGroupHeartbeat(key, group);
        return group.decision;
      })();
      sessionGroups.set(key, group);
    }

    group.sockets.add(ws);
    let detached = false;
    const detach = () => {
      if (detached) return;
      detached = true;
      group.sockets.delete(ws);
      if (group.sockets.size === 0) {
        stopGroup(key, group);
      }
    };
    ws.once('close', detach);
    ws.once('error', detach);

    const decision = group.decision || await group.authPromise;
    if (!decision || !decision.ok || group.locked || group.stopped) {
      detach();
      return decision || {
        ok: false,
        guarded: true,
        reason: group.locked ? 'concurrency_locked' : 'guard_stopped',
      };
    }

    return decision;
  }

  async function authorizeStream(stream, ws, req) {
    if (!enabled) return {ok: true, guarded: false};

    let header;
    try {
      stream.pause();
      header = await waitForBytes(stream, 17, 5000);
    } catch {
      return {ok: false, guarded: true, reason: 'invalid_vless_header'};
    }
    return authorizeHeader(header, ws, req);
  }

  return {
    enabled,
    route,
    telemetryUrl,
    authorizeHeader,
    authorizeStream,
  };
}

module.exports = {
  createSessionGuard,
  normalizeIp,
  sourceIp,
  uuidFromHeader,
};
