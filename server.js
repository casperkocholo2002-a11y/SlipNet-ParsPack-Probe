'use strict';

const http = require('http');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const { WebSocket, WebSocketServer, createWebSocketStream } = require('ws');
const { createSessionGuard } = require('./session_guard');

const PORT = Number(process.env.PORT || 3000);
const DIRECT_DIAG_PATH = '/__r3diag_7f2b9d4c';
const DIRECT_DIAG = {
  startedAt: new Date().toISOString(), upgrades: 0, accepted: 0, binaryFrames: 0, bytesIn: 0,
  authStarted: 0, authOk: 0, authFail: 0, backendStart: 0, backendOpen: 0, backendRetry: 0, backendFallbackSwitch: 0, backendExhausted: 0,
  pendingFlushes: 0, framesToBackend: 0, bytesToBackend: 0, backendMessages: 0, bytesFromBackend: 0,
  framesToClient: 0, bytesToClient: 0, sendCallbacks: 0, sendErrors: 0, closes: 0, lastCloseReason: null, lastBackendCloseCode: null,
  lastBackendCloseReason: null, lastBackendCfRay: null, backendCfRayCounts: {}, lastError: null, lastEventAt: null,
};
function directDiagMark(field, value = 1) {
  if (typeof DIRECT_DIAG[field] === 'number') DIRECT_DIAG[field] += value;
  DIRECT_DIAG.lastEventAt = new Date().toISOString();
}
function directDiagSet(field, value) { DIRECT_DIAG[field] = value; DIRECT_DIAG.lastEventAt = new Date().toISOString(); }
const MAX_ECHO = 16 * 1024 * 1024;
const MAX_STREAM = 8 * 1024 * 1024;
const MAX_WS = 1024 * 1024;
function envValue(primary, fallback) {
  return String(process.env[primary] || process.env[fallback] || '').trim();
}

const RELAY_PATH = envValue('RELAY_PATH', 'relaypath') || '/tunnel';
const V2_SESSION_GUARD = createSessionGuard({
  route: 'arvan',
  telemetryUrl:
    envValue('SESSION_TELEMETRY_URL', 'sessiontelemetryurl') ||
    'https://monitor.reoos.ir/api/v2ray-session/telemetry',
  heartbeatMs: 5000,
  requestTimeoutMs: 1800,
});
const DIRECT_RELAY_PATH = envValue('DIRECT_RELAY_PATH', 'directrelaypath') || '/direct';
const DIRECT_ROUTE_PREFIX = DIRECT_RELAY_PATH.replace(/\/+$/, '') + '/';
const DIRECT_GUARD_ROUTE = envValue('DIRECT_GUARD_ROUTE', 'directguardroute') || 'direct-r1';
const DIRECT_TELEMETRY_URL =
  envValue('DIRECT_SESSION_TELEMETRY_URL', 'directsessiontelemetryurl') ||
  'https://monitor.reoos.ir/api/direct-session/telemetry';
const DIRECT_SESSION_GUARD = createSessionGuard({
  route: DIRECT_GUARD_ROUTE,
  telemetryUrl: DIRECT_TELEMETRY_URL,
  heartbeatMs: 5000,
  requestTimeoutMs: 1800,
});
const DIRECT_ROUTE_GUARDS = new Map();

function directRouteGuard(route) {
  if (!route || route === DIRECT_GUARD_ROUTE) return DIRECT_SESSION_GUARD;
  let guard = DIRECT_ROUTE_GUARDS.get(route);
  if (!guard) {
    guard = createSessionGuard({
      route,
      telemetryUrl: DIRECT_TELEMETRY_URL,
      heartbeatMs: 5000,
      requestTimeoutMs: 1800,
    });
    DIRECT_ROUTE_GUARDS.set(route, guard);
  }
  return guard;
}

function directOriginConfig() {
  const host = envValue('DIRECT_ORIGIN_HOST', 'directoriginhost');
  const port = Number(envValue('DIRECT_ORIGIN_PORT', 'directoriginport') || 0);
  const servername = envValue('DIRECT_ORIGIN_SERVERNAME', 'directoriginservername');
  const path = envValue('DIRECT_ORIGIN_PATH', 'directoriginpath');
  return { host, port, servername, path };
}

function directOriginUrl(config) {
  const authority = config.port === 443 ? config.servername : config.servername + ':' + config.port;
  return 'wss://' + authority + config.path;
}

let DIRECT_BACKEND_PREFERRED_HOST = null;

function directBackendFallbackHosts() {
  const raw = envValue('DIRECT_BACKEND_FALLBACK_HOSTS', 'directbackendfallbackhosts');
  if (!raw) return [];
  const out = [];
  for (const part of raw.split(',')) {
    const host = String(part || '').trim();
    if (!host || out.includes(host)) continue;
    out.push(host);
  }
  return out;
}

function directOriginCandidates(config) {
  const out = [config];
  for (const host of directBackendFallbackHosts()) {
    if (!host || host === config.host) continue;
    out.push({
      host,
      port: config.port,
      servername: host,
      path: config.path,
    });
  }
  if (DIRECT_BACKEND_PREFERRED_HOST) {
    const idx = out.findIndex((item) => item.host === DIRECT_BACKEND_PREFERRED_HOST);
    if (idx > 0) out.unshift(out.splice(idx, 1)[0]);
  }
  return out;
}

function directRouteCodeFromPath(pathname) {
  if (!pathname.startsWith(DIRECT_ROUTE_PREFIX)) return null;
  const code = pathname.slice(DIRECT_ROUTE_PREFIX.length).trim().toUpperCase();
  if (!/^[A-Z0-9_-]{2,16}$/.test(code)) return null;
  return code;
}

const DIRECT_MULTIROUTE_PRIMARY_HOST = envValue('DIRECT_MULTIROUTE_PRIMARY_HOST', 'directmultirouteprimaryhost') || 'cfws-test-1108.reoos.ir';
const DIRECT_BUILTIN_ROUTE_PATHS = Object.freeze({ TUS: '/tor/us', TJP: '/tor/jp', TFR: '/tor/fr', TSE: '/tor/se', TAT: '/tor/at', TNO: '/tor/no' });

function directRouteConfig(code) {
  if (!code) {
    return {
      code: 'LEGACY',
      publicPath: DIRECT_RELAY_PATH,
      guard: DIRECT_SESSION_GUARD,
      origin: directOriginConfig(),
    };
  }
  const prefix = 'DIRECT_ROUTE_' + code + '_';
  const configuredHost = envValue(prefix + 'HOST', (prefix + 'HOST').toLowerCase());
  const host = DIRECT_MULTIROUTE_PRIMARY_HOST || configuredHost;
  const port = Number(envValue(prefix + 'PORT', (prefix + 'PORT').toLowerCase()) || 443);
  const servername = host;
  const path = envValue(prefix + 'PATH', (prefix + 'PATH').toLowerCase()) || DIRECT_BUILTIN_ROUTE_PATHS[code] || '';
  const guardRoute = envValue(prefix + 'GUARD_ROUTE', (prefix + 'GUARD_ROUTE').toLowerCase()) || ('direct-' + code.toLowerCase());
  return {
    code,
    publicPath: DIRECT_ROUTE_PREFIX + code.toLowerCase(),
    guard: directRouteGuard(guardRoute),
    origin: { host, port, servername, path },
  };
}

function configuredDirectRouteCodes() {
  const codes = new Set(Object.keys(DIRECT_BUILTIN_ROUTE_PATHS));
  for (const key of Object.keys(process.env)) {
    const m = /^DIRECT_ROUTE_([A-Z0-9_-]{2,16})_HOST$/.exec(key);
    if (m && process.env[key]) codes.add(m[1]);
  }
  return Array.from(codes).sort();
}

function json(res, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(body.length),
    'cache-control': 'no-store',
    'x-slipnet-probe': '1',
  });
  res.end(body);
}

function numberParam(url, key, fallback, min, max) {
  const raw = url.searchParams.get(key);
  const value = raw === null ? fallback : Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://probe.local');

  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, {
      ok: true,
      service: 'slipnet-parspack-ingress-probe',
      node: process.version,
      relayConfigured: Boolean(
        envValue('ORIGIN_HOST', 'originhost') &&
        Number(envValue('ORIGIN_PORT', 'originport') || 0) &&
        envValue('ORIGIN_SERVERNAME', 'originservername')
      ),
      directRelayConfigured: (() => {
        const d = directOriginConfig();
        return Boolean(d.host && Number.isInteger(d.port) && d.port > 0 && d.port <= 65535 && d.servername && d.path);
      })(),
      originSniSent: false,
      directOriginSniSent: true,
      originTlsMin: 'TLSv1.3',
      directRelayMode: 'wss',
      directGuardRoute: DIRECT_SESSION_GUARD.route,
      directRoutesConfigured: configuredDirectRouteCodes(),
      directRouteMode: 'path-dispatch',
      directBackendFallbackCount: 0,
      concurrencyGuardEnabled: V2_SESSION_GUARD.enabled,
      concurrencyGuardRoute: V2_SESSION_GUARD.route,
      build: 'arvan-direct-realip-v25-tor-6country',
      directRelayImpl: 'ws-edgecache-v10-v14-core-arvan-tor-6country',
      now: new Date().toISOString(),
    });
  }

  if (req.method === 'GET' && url.pathname === DIRECT_DIAG_PATH) {
    return json(res, 200, { ok: true, build: 'arvan-direct-realip-v25-tor-6country', diag: DIRECT_DIAG });
  }

  if (req.method === 'GET' && url.pathname === '/direct-proxy-diag') {
    const d = directOriginConfig();
    if (!d.servername) return json(res, 503, { ok: false, error: 'direct_origin_not_configured' });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    fetch('https://' + d.servername + '/diag-proxy', { signal: controller.signal, headers: { 'cache-control': 'no-cache' } })
      .then(async (r) => {
        const text = await r.text();
        let body = text;
        try { body = JSON.parse(text); } catch {}
        json(res, 200, { ok: r.ok, status: r.status, cfRay: r.headers.get('cf-ray'), server: r.headers.get('server'), body });
      })
      .catch((err) => json(res, 502, { ok: false, error: String(err && err.message || err) }))
      .finally(() => clearTimeout(timer));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/direct-origin-check') {
    const requestedCode = String(url.searchParams.get('route') || '').trim().toUpperCase();
    const selected = requestedCode ? directRouteConfig(requestedCode) : directRouteConfig(null);
    const d = selected.origin;
    if (!d.host || !Number.isInteger(d.port) || d.port < 1 || d.port > 65535 || !d.servername || !d.path) {
      return json(res, 503, { ok: false, error: 'direct_origin_check_not_configured' });
    }

    const started = Date.now();
    let settled = false;
    let backend;
    const finish = (status, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { backend && backend.close(); } catch {}
      return json(res, status, value);
    };
    const timer = setTimeout(() => {
      finish(504, { ok: false, connected: false, error: 'timeout', ms: Date.now() - started });
    }, 5000);

    try {
      backend = new WebSocket(directOriginUrl(d));
      backend.binaryType = 'arraybuffer';
      backend.addEventListener('open', () => {
        finish(200, { ok: true, connected: true, mode: 'wss', route: selected.code, ms: Date.now() - started });
      }, { once: true });
      backend.addEventListener('error', () => {
        finish(502, { ok: false, connected: false, error: 'wss_connect_error', ms: Date.now() - started });
      }, { once: true });
    } catch {
      finish(502, { ok: false, connected: false, error: 'wss_connect_exception', ms: Date.now() - started });
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/origin-check') {
    const targetHost = envValue('ORIGIN_HOST', 'originhost');
    const targetPort = Number(envValue('ORIGIN_PORT', 'originport') || 0);
    if (!targetHost || !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      return json(res, 503, { ok: false, error: 'origin_check_not_configured' });
    }

    const started = Date.now();
    const socket = net.createConnection({ host: targetHost, port: targetPort });
    let settled = false;
    let banner = Buffer.alloc(0);

    const finish = (status, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(overallTimer);
      socket.destroy();
      return json(res, status, value);
    };

    const overallTimer = setTimeout(() => {
      finish(504, { ok: false, connected: false, error: 'timeout', ms: Date.now() - started });
    }, 5000);

    socket.once('connect', () => {
      const connectMs = Date.now() - started;
      const settleTimer = setTimeout(() => {
        finish(200, {
          ok: true,
          connected: true,
          ms: connectMs,
          banner: banner.toString('utf8').replace(/[^\x20-\x7e\r\n]/g, '').slice(0, 160),
        });
      }, 800);
      socket.once('close', () => clearTimeout(settleTimer));
    });

    socket.on('data', (chunk) => {
      if (banner.length < 256) {
        banner = Buffer.concat([banner, chunk]).subarray(0, 256);
      }
      if (banner.includes(0x0a)) {
        finish(200, {
          ok: true,
          connected: true,
          ms: Date.now() - started,
          banner: banner.toString('utf8').replace(/[^\x20-\x7e\r\n]/g, '').slice(0, 160),
        });
      }
    });

    socket.once('error', (error) => {
      finish(502, {
        ok: false,
        connected: false,
        error: error && error.code ? String(error.code) : 'connect_error',
        ms: Date.now() - started,
      });
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/echo') {
    let size = 0;
    const hash = crypto.createHash('sha256');
    let aborted = false;

    req.on('data', (chunk) => {
      if (aborted) return;
      size += chunk.length;
      if (size > MAX_ECHO) {
        aborted = true;
        res.writeHead(413, { 'connection': 'close', 'x-slipnet-probe': '1' });
        res.end();
        req.destroy();
        return;
      }
      hash.update(chunk);
    });

    req.on('end', () => {
      if (aborted) return;
      json(res, 200, { ok: true, bytes: size, sha256: hash.digest('hex') });
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/stream') {
    const total = numberParam(url, 'bytes', 1024 * 1024, 1, MAX_STREAM);
    const chunkSize = numberParam(url, 'chunk', 16 * 1024, 1, 64 * 1024);
    const delayMs = numberParam(url, 'delay_ms', 0, 0, 1000);
    let sent = 0;

    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'cache-control': 'no-store',
      'x-slipnet-probe': '1',
      'x-probe-total-bytes': String(total),
    });

    const pump = () => {
      if (sent >= total) return res.end();
      const n = Math.min(chunkSize, total - sent);
      const chunk = Buffer.alloc(n, 0x53);
      sent += n;
      if (!res.write(chunk)) {
        res.once('drain', () => delayMs ? setTimeout(pump, delayMs) : pump());
      } else if (delayMs) {
        setTimeout(pump, delayMs);
      } else {
        setImmediate(pump);
      }
    };
    pump();
    return;
  }

  if (req.method === 'GET' && url.pathname === '/hold') {
    const seconds = numberParam(url, 'seconds', 30, 1, 120);
    let i = 0;
    res.writeHead(200, {
      'content-type': 'text/plain',
      'cache-control': 'no-store',
      'x-slipnet-probe': '1',
    });
    const timer = setInterval(() => {
      i += 1;
      res.write('tick\n');
      if (i >= seconds) {
        clearInterval(timer);
        res.end('done\n');
      }
    }, 1000);
    req.on('close', () => clearInterval(timer));
    return;
  }

  json(res, 404, { ok: false, error: 'not_found' });
});

const relayWss = new WebSocketServer({
  noServer: true,
  perMessageDeflate: false,
  clientTracking: false,
  maxPayload: MAX_WS,
});

function rejectUpgrade(socket, status = '503 Service Unavailable') {
  try {
    socket.end(
      'HTTP/1.1 ' + status + '\r\n' +
      'Connection: close\r\n' +
      'Content-Length: 0\r\n\r\n'
    );
  } catch {
    try { socket.destroy(); } catch {}
  }
}

function tuneSocket(socket) {
  try { socket.setNoDelay(true); } catch {}
  try { socket.setKeepAlive(true, 30000); } catch {}
}

function acceptWebSocket(req, socket, head, onAccepted) {
  tuneSocket(socket);
  try {
    relayWss.handleUpgrade(req, socket, head, (ws) => {
      try { tuneSocket(ws._socket); } catch {}
      onAccepted(ws);
    });
  } catch {
    try { socket.destroy(); } catch {}
  }
}

function bridgeStreams(clientStream, upstreamStream, closeAll) {
  let closed = false;
  const closeOnce = () => {
    if (closed) return;
    closed = true;
    closeAll();
  };

  // Do not tear both sides down on readable "end". pipe() must be allowed
  // to flush the destination writable buffer first, otherwise the final
  // WebSocket frames can be truncated on slower provider links.
  clientStream.on('error', closeOnce);
  upstreamStream.on('error', closeOnce);

  // The outer client closing means there is nowhere left to flush to.
  clientStream.once('close', closeOnce);

  // An upstream close without a normal readable end is an abort. A normal
  // end is handled by pipe(), which ends and flushes the client stream.
  upstreamStream.once('close', () => {
    if (!upstreamStream.readableEnded) closeOnce();
  });

  clientStream.pipe(upstreamStream);
  upstreamStream.pipe(clientStream);
}

function handleEchoWebSocket(req, socket, head) {
  acceptWebSocket(req, socket, head, (ws) => {
    ws.on('message', (data, isBinary) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(data, { binary: isBinary, compress: false });
    });
    ws.on('error', () => {});
  });
}

function handlePrimaryRelayWebSocket(req, socket, head) {
  const originHost = envValue('ORIGIN_HOST', 'originhost');
  const originPort = Number(envValue('ORIGIN_PORT', 'originport') || 0);
  const originServername = envValue('ORIGIN_SERVERNAME', 'originservername');

  if (!originHost || !originServername || !Number.isInteger(originPort) || originPort < 1 || originPort > 65535) {
    return rejectUpgrade(socket);
  }

  let client = null;
  let clientStream = null;
  let closed = false;

  const origin = tls.connect({
    host: originHost,
    port: originPort,
    servername: undefined,
    rejectUnauthorized: true,
    checkServerIdentity: (_networkHost, cert) =>
      tls.checkServerIdentity(originServername, cert),
    minVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1'],
    highWaterMark: 1024 * 1024,
  });
  tuneSocket(origin);

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { clientStream && clientStream.destroy(); } catch {}
    try { client && client.terminate(); } catch {}
    try { origin.destroy(); } catch {}
    try { if (!client) socket.destroy(); } catch {}
  };

  origin.setTimeout(15000, () => {
    if (!client) rejectUpgrade(socket, '504 Gateway Timeout');
    closeAll();
  });

  origin.once('secureConnect', () => {
    origin.setTimeout(0);

    acceptWebSocket(req, socket, head, (ws) => {
      client = ws;
      clientStream = createWebSocketStream(ws, {
        encoding: null,
        highWaterMark: 1024 * 1024,
      });
      clientStream.pause();

      V2_SESSION_GUARD.authorizeStream(clientStream, ws, req)
        .then((decision) => {
          if (!decision || !decision.ok || closed) {
            closeAll();
            return;
          }
          bridgeStreams(clientStream, origin, closeAll);
        })
        .catch(closeAll);
    });
  });

  origin.once('error', () => {
    if (!client) rejectUpgrade(socket, '502 Bad Gateway');
    closeAll();
  });
  socket.once('error', closeAll);
  socket.once('close', () => { if (!client) closeAll(); });
}

function handleDirectRelayWebSocket(req, socket, head, selectedRoute = null) {
  directDiagMark('upgrades');
  const selected = selectedRoute || directRouteConfig(null);
  const d = selected.origin;
  const sessionGuard = selected.guard;

  if (!d.host || !d.servername || !d.path || !Number.isInteger(d.port) || d.port < 1 || d.port > 65535) {
    return rejectUpgrade(socket);
  }

  const DIRECT_FRAME_CHUNK = 32 * 1024;
  const DIRECT_PENDING_MAX = 2 * 1024 * 1024;

  let client = null;
  let backend = null;
  let backendOpenTimer = null;
  let closed = false;
  let backendReady = false;
  let authorized = false;
  let authStarted = false;
  let header = Buffer.alloc(0);
  let pending = [];
  let pendingBytes = 0;
  let clientToBackend = Promise.resolve();
  let backendToClient = Promise.resolve();

  const closeAll = (reason = 'unknown') => {
    if (closed) return;
    closed = true;
    directDiagMark('closes');
    directDiagSet('lastCloseReason', String(reason && reason.message ? reason.message : reason));
    pending = [];
    pendingBytes = 0;
    if (backendOpenTimer) clearTimeout(backendOpenTimer);
    try { client && client.terminate(); } catch {}
    try { backend && backend.close(); } catch {}
    try { if (!client) socket.destroy(); } catch {}
  };

  const sendChunked = async (ws, data, native = false, direction = 'backend') => {
    if (!ws || ws.readyState !== 1) throw new Error('websocket_not_open');
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    for (let offset = 0; offset < buf.length; offset += DIRECT_FRAME_CHUNK) {
      if (ws.readyState !== 1) throw new Error('websocket_closed_during_send');
      const chunk = buf.subarray(offset, Math.min(buf.length, offset + DIRECT_FRAME_CHUNK));
      if (native) {
        ws.send(chunk);
      } else {
        await new Promise((resolve, reject) => {
          ws.send(chunk, { binary: true, compress: false }, (err) => {
            if (err) {
              directDiagMark('sendErrors');
              reject(err);
              return;
            }
            directDiagMark('sendCallbacks');
            resolve();
          });
        });
      }
      if (direction === 'backend') {
        directDiagMark('framesToBackend');
        directDiagMark('bytesToBackend', chunk.length);
      } else {
        directDiagMark('framesToClient');
        directDiagMark('bytesToClient', chunk.length);
      }
      if (ws.bufferedAmount > DIRECT_PENDING_MAX) {
        await new Promise((resolve, reject) => {
          const started = Date.now();
          const poll = () => {
            if (ws.readyState !== WebSocket.OPEN) return reject(new Error('websocket_closed_during_backpressure'));
            if (ws.bufferedAmount <= DIRECT_PENDING_MAX / 2) return resolve();
            if (Date.now() - started >= 5000) return reject(new Error('websocket_backpressure_timeout'));
            setTimeout(poll, 5);
          };
          poll();
        });
      }
    }
  };

  const flushPending = () => {
    if (!authorized || !backendReady || closed || !pending.length) return;
    directDiagMark('pendingFlushes');
    const frames = pending;
    pending = [];
    pendingBytes = 0;
    for (const frame of frames) {
      clientToBackend = clientToBackend
        .then(() => sendChunked(backend, frame, false, 'backend'))
        .catch((err) => {
          directDiagSet('lastError', String(err && err.message || err));
          closeAll('backend_send_error');
        });
    }
  };

  const startBackend = () => {
    if (!authorized || backend || closed) return;
    directDiagMark('backendStart');

    backend = new WebSocket(directOriginUrl(d), {
      perMessageDeflate: false,
      handshakeTimeout: 15000,
      maxPayload: MAX_WS,
    });
    backend.binaryType = 'arraybuffer';

    backendOpenTimer = setTimeout(() => {
      if (!backendReady) closeAll('backend_open_timeout');
    }, 15000);

    backend.once('upgrade', (response) => {
      try {
        const ray = String(response && response.headers && response.headers['cf-ray'] || '');
        if (ray) {
          directDiagSet('lastBackendCfRay', ray);
          const colo = (ray.split('-').pop() || 'UNKNOWN').toUpperCase();
          DIRECT_DIAG.backendCfRayCounts[colo] = Number(DIRECT_DIAG.backendCfRayCounts[colo] || 0) + 1;
        }
      } catch {}
    });

    backend.once('open', () => {
      try { tuneSocket(backend._socket); } catch {}
      if (backendOpenTimer) clearTimeout(backendOpenTimer);
      backendOpenTimer = null;
      backendReady = true;
      directDiagSet('lastBackendHost', d.host);
      directDiagSet('preferredBackendHost', null);
      directDiagMark('backendOpen');
      flushPending();
    });

    backend.on('message', (data, isBinary) => {
      directDiagMark('backendMessages');
      directDiagMark('bytesFromBackend', Buffer.byteLength(data));
      if (closed || !client || !isBinary) {
        closeAll('backend_nonbinary_or_no_client');
        return;
      }
      const frame = Buffer.from(data);
      backendToClient = backendToClient
        .then(() => sendChunked(client, frame, false, 'client'))
        .catch((err) => {
          directDiagSet('lastError', String(err && err.message || err));
          closeAll('client_send_error');
        });
    });

    backend.once('close', (code, reason) => {
      directDiagSet('lastBackendCloseCode', Number(code));
      directDiagSet('lastBackendCloseReason', Buffer.from(reason || '').toString().slice(0, 120));
      closeAll('backend_close_' + code);
    });

    backend.once('error', (err) => {
      directDiagSet('lastError', String(err && err.message || err));
      closeAll('backend_error');
    });
  };

  const startAuthorization = () => {
    if (authStarted || header.length < 17 || !client || closed) return;
    authStarted = true;
    directDiagMark('authStarted');
    sessionGuard.authorizeHeader(header.subarray(0, 17), client, req)
      .then((decision) => {
        if (!decision || !decision.ok || closed) {
          directDiagMark('authFail');
          closeAll('auth_denied');
          return;
        }
        authorized = true;
        directDiagMark('authOk');
        startBackend();
      })
      .catch((err) => {
        directDiagSet('lastError', String(err && err.message || err));
        closeAll('auth_error');
      });
  };

  acceptWebSocket(req, socket, head, (ws) => {
    client = ws;
    directDiagMark('accepted');

    ws.on('message', (data, isBinary) => {
      if (closed || !isBinary) {
        closeAll();
        return;
      }

      const frame = Buffer.from(data);
      directDiagMark('binaryFrames');
      directDiagMark('bytesIn', frame.length);

      if (!authorized || !backendReady) {
        pendingBytes += frame.length;
        if (pendingBytes > DIRECT_PENDING_MAX) {
          closeAll();
          return;
        }
        pending.push(frame);

        if (header.length < 17) {
          const need = 17 - header.length;
          header = Buffer.concat([header, frame.subarray(0, need)]);
        }
        startAuthorization();
        return;
      }

      clientToBackend = clientToBackend
        .then(() => sendChunked(backend, frame, false, 'backend'))
        .catch((err) => {
          directDiagSet('lastError', String(err && err.message || err));
          closeAll('backend_send_error');
        });
    });

    ws.once('close', (code) => closeAll('client_close_' + code));
    ws.once('error', (err) => {
      directDiagSet('lastError', String(err && err.message || err));
      closeAll('client_error');
    });
  });

  socket.once('error', closeAll);
  socket.once('close', () => { if (!client) closeAll(); });
}

server.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://probe.local');
  } catch {
    return socket.destroy();
  }

  if (url.pathname === '/ws') return handleEchoWebSocket(req, socket, head);
  if (url.pathname === RELAY_PATH) return handlePrimaryRelayWebSocket(req, socket, head);
  if (url.pathname === DIRECT_RELAY_PATH) return handleDirectRelayWebSocket(req, socket, head, directRouteConfig(null));
  const routeCode = directRouteCodeFromPath(url.pathname);
  if (routeCode) {
    const selected = directRouteConfig(routeCode);
    const d = selected.origin;
    if (d.host && d.servername && d.path && Number.isInteger(d.port) && d.port > 0 && d.port <= 65535) {
      return handleDirectRelayWebSocket(req, socket, head, selected);
    }
  }
  return socket.destroy();
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('slipnet-parspack-ingress-probe listening on', PORT);
});