'use strict';

const crypto = require('crypto');
const net = require('net');

const DEFAULT_URL = 'https://monitor.cspf.shop/api/v2ray-session/telemetry';

function normalizeIp(raw) {
  let value = String(raw || '').trim();
  if (!value) return '';
  if (value.includes(',')) value = value.split(',')[0].trim();
  if (value.startsWith('::ffff:')) value = value.slice(7);
  const zone = value.indexOf('%');
  if (zone !== -1) value = value.slice(0, zone);
  return net.isIP(value) ? value : '';
}

function sourceIp(req, route = '') {
  const h = (req && req.headers) || {};
  const r = String(route || '').trim().toLowerCase();
  const candidates = r === 'arvan'
    ? [
        h['ar-real-ip'],
        h['x-client-ip'],
        h['x-real-ip'],
        h['x-forwarded-for'],
        req && req.socket && req.socket.remoteAddress,
      ]
    : [
        h['x-real-ip'],
        h['x-forwarded-for'],
        h['x-client-ip'],
        h['ar-real-ip'],
        req && req.socket && req.socket.remoteAddress,
      ];
  for (const candidate of candidates) {
    const ip = normalizeIp(candidate);
    if (ip) return ip;
  }
  return '';
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

function proof(uuid, hash, ip, route, event, ts) {
  const message = [hash, ip, route, event, String(ts)].join('|');
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
  const heartbeatMs = Number(options.heartbeatMs || 10000);
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
      proof: proof(meta.uuid, meta.hash, meta.ip, route, event, ts),
    };
    return postTelemetry(telemetryUrl, payload, requestTimeoutMs);
  }

  async function authorizeStream(stream, ws, req) {
    if (!enabled) return {ok: true, guarded: false};

    const ip = sourceIp(req, route);
    if (!ip) {
      // Fail open if the platform does not expose a usable client IP.
      return {ok: true, guarded: false, reason: 'source_ip_unavailable'};
    }

    let header;
    try {
      stream.pause();
      header = await waitForBytes(stream, 17, 5000);
    } catch {
      return {ok: false, guarded: true, reason: 'invalid_vless_header'};
    }

    const uuid = uuidFromHeader(header);
    if (!uuid) {
      return {ok: false, guarded: true, reason: 'invalid_vless_uuid'};
    }

    const meta = {uuid, hash: uuidHash(uuid), ip};
    const opened = await emit(meta, 'open');

    // Telemetry outages must not become connectivity outages.
    if (opened && opened.locked) {
      return {
        ok: false,
        guarded: true,
        reason: opened.reason || 'concurrency_locked',
        activeSources: Number(opened.active_sources || 0),
      };
    }

    let stopped = false;
    let heartbeatRunning = false;
    const stop = () => {
      if (stopped) return;
      stopped = true;
      clearInterval(timer);
      emit(meta, 'close').catch(() => {});
    };

    const timer = setInterval(async () => {
      if (stopped || heartbeatRunning) return;
      heartbeatRunning = true;
      try {
        const state = await emit(meta, 'heartbeat');
        if (state && state.locked) {
          stop();
          try { ws.terminate(); } catch {}
        }
      } finally {
        heartbeatRunning = false;
      }
    }, heartbeatMs);

    if (timer.unref) timer.unref();
    ws.once('close', stop);
    ws.once('error', stop);

    return {
      ok: true,
      guarded: true,
      activeSources: opened ? Number(opened.active_sources || 0) : null,
    };
  }

  return {
    enabled,
    route,
    telemetryUrl,
    authorizeStream,
  };
}

module.exports = {
  createSessionGuard,
  normalizeIp,
  sourceIp,
  uuidFromHeader,
};
