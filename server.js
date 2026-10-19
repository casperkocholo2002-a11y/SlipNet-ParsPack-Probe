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
      originSniSent: false,
      originTlsMin: 'TLSv1.3',
      build: 'nosni-tls13-v2',
      now: new Date().toISOString(),
    });
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

function handleRelayWebSocket(req, socket, head) {
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
    // Hide the internal origin name from the network: no TLS SNI is sent.
    // Certificate-chain validation stays enabled and hostname validation is
    // performed locally against ORIGIN_SERVERNAME.
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

server.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://probe.local');
  } catch {
    return socket.destroy();
  }

  if (url.pathname === '/ws') return handleEchoWebSocket(req, socket, head);
  if (url.pathname === RELAY_PATH) return handleRelayWebSocket(req, socket, head);
  return socket.destroy();
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('slipnet-parspack-ingress-probe listening on', PORT);
});