'use strict';

const http = require('http');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const { WebSocket, WebSocketServer, createWebSocketStream } = require('ws');
const { createSessionGuard } = require('./session_guard');

const PORT = Number(process.env.PORT || 3000);
const MAX_ECHO = 16 * 1024 * 1024;
const MAX_STREAM = 8 * 1024 * 1024;
const MAX_WS = 1024 * 1024;
function envValue(primary, fallback) {
  return String(process.env[primary] || process.env[fallback] || '').trim();
}

const RELAY_PATH = envValue('RELAY_PATH', 'relaypath') || '/tunnel';
const V2_SESSION_GUARD = createSessionGuard({
  route: 'parspack',
  telemetryUrl:
    envValue('SESSION_TELEMETRY_URL', 'sessiontelemetryurl') ||
    'https://monitor.cspf.shop/api/v2ray-session/telemetry',
  heartbeatMs: 10000,
  requestTimeoutMs: 1800,
});
const DIRECT_RELAY_PATH = envValue('DIRECT_RELAY_PATH', 'directrelaypath') || '/direct';

const WORKER_DIRECT_RELAY_PATH =
  envValue('WORKER_DIRECT_RELAY_PATH', 'workerdirectrelaypath') ||
  '/pw/6b7a4e1c9d8f2a35f4b20caa7e9d3f6c5a11b7c4';
const WORKER_DIRECT_HOST =
  envValue('WORKER_DIRECT_HOST', 'workerdirecthost') ||
  'ppw-3c19aa324d48.edgecache-628bbe41dc.workers.dev';
const WORKER_DIRECT_PATH =
  envValue('WORKER_DIRECT_PATH', 'workerdirectpath') ||
  '/w/986b32e37335922c2faab7ce2153a8c9f9c6aff9de334f28';

const WORKER_FIXED_RELAY_PATH =
  envValue('WORKER_FIXED_RELAY_PATH', 'workerfixedrelaypath') ||
  '/pf/4e1b9c72a6d0f5e38b4c1a97d2f6e0ab3c8d5f11';
const WORKER_FIXED_HOST =
  envValue('WORKER_FIXED_HOST', 'workerfixedhost') ||
  'ppf-56cf1bc939.edgecache-628bbe41dc.workers.dev';
const WORKER_FIXED_PATH =
  envValue('WORKER_FIXED_PATH', 'workerfixedpath') ||
  '/ppwf/124b41395c04d8a24b794893309742a2f20b5482116d1e32';

const LEGACY_DIRECT_ORIGIN = 'cdn.cspf.online';
const CURRENT_DIRECT_ORIGIN = 'slipnet.wordpresscsp.ir';

function normalizeDirectOrigin(value) {
  return value === LEGACY_DIRECT_ORIGIN ? CURRENT_DIRECT_ORIGIN : value;
}

function directOriginConfig() {
  const host = normalizeDirectOrigin(envValue('DIRECT_ORIGIN_HOST', 'directoriginhost'));
  const port = Number(envValue('DIRECT_ORIGIN_PORT', 'directoriginport') || 0);
  const servername = normalizeDirectOrigin(envValue('DIRECT_ORIGIN_SERVERNAME', 'directoriginservername'));
  const path = envValue('DIRECT_ORIGIN_PATH', 'directoriginpath');
  return { host, port, servername, path };
}

function directOriginUrl(config) {
  const authority = config.port === 443 ? config.servername : config.servername + ':' + config.port;
  return 'wss://' + authority + config.path;
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
      workerDirectConfigured: Boolean(WORKER_DIRECT_HOST && WORKER_DIRECT_PATH),
      workerFixedConfigured: Boolean(WORKER_FIXED_HOST && WORKER_FIXED_PATH),
      workerRelayMode: 'wss',
      concurrencyGuardEnabled: V2_SESSION_GUARD.enabled,
      concurrencyGuardRoute: V2_SESSION_GUARD.route,
      build: 'graceful-drain-relay-v9-concurrency-guard',
      now: new Date().toISOString(),
    });
  }

  if (req.method === 'GET' && url.pathname === '/direct-origin-check') {
    const d = directOriginConfig();
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
        finish(200, { ok: true, connected: true, mode: 'wss', ms: Date.now() - started });
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
          clientStream.resume();
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

function handleDirectRelayWebSocket(req, socket, head) {
  const d = directOriginConfig();

  if (!d.host || !d.servername || !d.path || !Number.isInteger(d.port) || d.port < 1 || d.port > 65535) {
    return rejectUpgrade(socket);
  }

  let client = null;
  let clientStream = null;
  let backendStream = null;
  let closed = false;

  const backend = new WebSocket(directOriginUrl(d), {
    perMessageDeflate: false,
    handshakeTimeout: 15000,
    maxPayload: MAX_WS,
  });

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { clientStream && clientStream.destroy(); } catch {}
    try { backendStream && backendStream.destroy(); } catch {}
    try { client && client.terminate(); } catch {}
    try { backend.terminate(); } catch {}
    try { if (!client) socket.destroy(); } catch {}
  };

  backend.once('open', () => {
    try { tuneSocket(backend._socket); } catch {}

    acceptWebSocket(req, socket, head, (ws) => {
      client = ws;
      clientStream = createWebSocketStream(ws, {
        encoding: null,
        highWaterMark: 1024 * 1024,
      });
      backendStream = createWebSocketStream(backend, {
        encoding: null,
        highWaterMark: 1024 * 1024,
      });

      bridgeStreams(clientStream, backendStream, closeAll);
    });
  });

  backend.once('error', () => {
    if (!client) rejectUpgrade(socket, '502 Bad Gateway');
    closeAll();
  });
  socket.once('error', closeAll);
  socket.once('close', () => { if (!client) closeAll(); });
}

function handleWorkerRelayWebSocket(req, socket, head, workerHost, workerPath) {
  if (!workerHost || !workerPath) {
    return rejectUpgrade(socket);
  }

  let client = null;
  let clientStream = null;
  let backendStream = null;
  let closed = false;

  const backend = new WebSocket('wss://' + workerHost + workerPath, {
    perMessageDeflate: false,
    handshakeTimeout: 15000,
    maxPayload: MAX_WS,
  });

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { clientStream && clientStream.destroy(); } catch {}
    try { backendStream && backendStream.destroy(); } catch {}
    try { client && client.terminate(); } catch {}
    try { backend.terminate(); } catch {}
    try { if (!client) socket.destroy(); } catch {}
  };

  backend.once('open', () => {
    try { tuneSocket(backend._socket); } catch {}

    acceptWebSocket(req, socket, head, (ws) => {
      client = ws;
      clientStream = createWebSocketStream(ws, {
        encoding: null,
        highWaterMark: 1024 * 1024,
      });
      backendStream = createWebSocketStream(backend, {
        encoding: null,
        highWaterMark: 1024 * 1024,
      });

      bridgeStreams(clientStream, backendStream, closeAll);
    });
  });

  backend.once('error', () => {
    if (!client) rejectUpgrade(socket, '502 Bad Gateway');
    closeAll();
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
  if (url.pathname === DIRECT_RELAY_PATH) return handleDirectRelayWebSocket(req, socket, head);
  if (url.pathname === WORKER_DIRECT_RELAY_PATH) {
    return handleWorkerRelayWebSocket(
      req, socket, head, WORKER_DIRECT_HOST, WORKER_DIRECT_PATH
    );
  }
  if (url.pathname === WORKER_FIXED_RELAY_PATH) {
    return handleWorkerRelayWebSocket(
      req, socket, head, WORKER_FIXED_HOST, WORKER_FIXED_PATH
    );
  }
  return socket.destroy();
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('slipnet-parspack-ingress-probe listening on', PORT);
});