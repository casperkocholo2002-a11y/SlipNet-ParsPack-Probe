'use strict';

const http = require('http');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');

const PORT = Number(process.env.PORT || 3000);
const MAX_ECHO = 16 * 1024 * 1024;
const MAX_STREAM = 8 * 1024 * 1024;
const MAX_WS = 1024 * 1024;
function envValue(primary, fallback) {
  return String(process.env[primary] || process.env[fallback] || '').trim();
}

const RELAY_PATH = envValue('RELAY_PATH', 'relaypath') || '/tunnel';
const DIRECT_RELAY_PATH = envValue('DIRECT_RELAY_PATH', 'directrelaypath') || '/direct';

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
      build: 'multi-origin-wss-backend-v4',
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

function makeFrame(opcode, payload) {
  const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let head;
  if (p.length < 126) {
    head = Buffer.from([0x80 | opcode, p.length]);
  } else if (p.length <= 0xffff) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(p.length, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(p.length), 2);
  }
  return Buffer.concat([head, p]);
}

function websocketAccept(key) {
  return crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}

function parseClientFrames(socket, initial, onPayload, onClose) {
  let buf = initial && initial.length ? Buffer.from(initial) : Buffer.alloc(0);

  const parse = () => {
    while (buf.length >= 2) {
      const b0 = buf[0];
      const b1 = buf[1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;

      if (!masked) return onClose();
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_WS)) return onClose();
        len = Number(big);
        off = 10;
      }
      if (len > MAX_WS) return onClose();
      if (buf.length < off + 4 + len) return;

      const mask = buf.subarray(off, off + 4);
      off += 4;
      const payload = Buffer.from(buf.subarray(off, off + len));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      buf = buf.subarray(off + len);

      if (opcode === 0x8) {
        socket.write(makeFrame(0x8, payload));
        return onClose();
      }
      if (opcode === 0x9) {
        socket.write(makeFrame(0xA, payload));
        continue;
      }
      if (opcode === 0xA) continue;
      if (opcode === 0x0 || opcode === 0x1 || opcode === 0x2) {
        onPayload(payload);
        continue;
      }
      return onClose();
    }
  };

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    parse();
  });
  parse();
}

function handleEchoWebSocket(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  if (!key || version !== '13') return socket.destroy();

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + websocketAccept(key) + '\r\n' +
    'X-SlipNet-Probe: 1\r\n\r\n'
  );

  parseClientFrames(
    socket,
    head,
    (payload) => socket.write(makeFrame(0x2, payload)),
    () => socket.end()
  );
  socket.on('error', () => {});
}

function handlePrimaryRelayWebSocket(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  const originHost = envValue('ORIGIN_HOST', 'originhost');
  const originPort = Number(envValue('ORIGIN_PORT', 'originport') || 0);
  const originServername = envValue('ORIGIN_SERVERNAME', 'originservername');

  if (!key || version !== '13') return socket.destroy();
  if (!originHost || !originServername || !Number.isInteger(originPort) || originPort < 1 || originPort > 65535) {
    socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  let upgraded = false;
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
  });

  const closeBoth = () => {
    if (closed) return;
    closed = true;
    try { origin.destroy(); } catch {}
    try { socket.end(); } catch {}
  };

  origin.setTimeout(15000, closeBoth);

  origin.once('secureConnect', () => {
    origin.setTimeout(0);
    upgraded = true;
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + websocketAccept(key) + '\r\n' +
      'X-SlipNet-Relay: 1\r\n\r\n'
    );

    parseClientFrames(
      socket,
      head,
      (payload) => {
        if (!origin.write(payload)) {
          socket.pause();
          origin.once('drain', () => socket.resume());
        }
      },
      closeBoth
    );
  });

  origin.on('data', (chunk) => {
    if (!upgraded || closed) return;
    if (!socket.write(makeFrame(0x2, chunk))) {
      origin.pause();
      socket.once('drain', () => origin.resume());
    }
  });
  origin.once('end', closeBoth);
  origin.once('close', () => { if (!closed) closeBoth(); });
  origin.once('error', () => {
    if (!upgraded) {
      try {
        socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      } catch {}
    }
    closeBoth();
  });
  socket.once('error', closeBoth);
  socket.once('close', closeBoth);
}

function wsDataToBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return null;
}

function handleDirectRelayWebSocket(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  const d = directOriginConfig();

  if (!key || version !== '13') return socket.destroy();
  if (!d.host || !d.servername || !d.path || !Number.isInteger(d.port) || d.port < 1 || d.port > 65535) {
    socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  let backend;
  let upgraded = false;
  let closed = false;
  let openTimer;

  const closeBoth = () => {
    if (closed) return;
    closed = true;
    clearTimeout(openTimer);
    try { backend && backend.close(); } catch {}
    try { socket.end(); } catch {}
  };

  try {
    backend = new WebSocket(directOriginUrl(d));
    backend.binaryType = 'arraybuffer';
  } catch {
    socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }

  openTimer = setTimeout(() => {
    if (!upgraded) {
      try {
        socket.end('HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      } catch {}
    }
    closeBoth();
  }, 15000);

  backend.addEventListener('open', () => {
    clearTimeout(openTimer);
    upgraded = true;
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + websocketAccept(key) + '\r\n' +
      'X-SlipNet-Relay: direct-wss\r\n\r\n'
    );

    parseClientFrames(
      socket,
      head,
      (payload) => {
        if (closed) return;
        if (backend.bufferedAmount > 8 * 1024 * 1024) return closeBoth();
        try { backend.send(payload); } catch { closeBoth(); }
      },
      closeBoth
    );
  }, { once: true });

  backend.addEventListener('message', (event) => {
    if (!upgraded || closed) return;
    const payload = wsDataToBuffer(event.data);
    if (!payload) return closeBoth();
    if (!socket.write(makeFrame(0x2, payload))) {
      socket.once('drain', () => {});
    }
  });

  backend.addEventListener('close', closeBoth, { once: true });
  backend.addEventListener('error', () => {
    if (!upgraded) {
      try {
        socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      } catch {}
    }
    closeBoth();
  }, { once: true });
  socket.once('error', closeBoth);
  socket.once('close', closeBoth);
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
  return socket.destroy();
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('slipnet-parspack-ingress-probe listening on', PORT);
});