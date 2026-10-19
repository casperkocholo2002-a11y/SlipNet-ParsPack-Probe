'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const MAX_ECHO = 16 * 1024 * 1024;
const MAX_STREAM = 8 * 1024 * 1024;
const MAX_WS = 1024 * 1024;

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
      now: new Date().toISOString(),
    });
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

server.on('upgrade', (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url, 'http://probe.local');
  } catch {
    return socket.destroy();
  }

  if (url.pathname !== '/ws') return socket.destroy();

  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  if (!key || version !== '13') return socket.destroy();

  const accept = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n' +
    'X-SlipNet-Probe: 1\r\n\r\n'
  );

  let buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);

  const parse = () => {
    while (buf.length >= 2) {
      const b0 = buf[0];
      const b1 = buf[1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;

      if (!masked) return socket.destroy();
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_WS)) return socket.destroy();
        len = Number(big);
        off = 10;
      }
      if (len > MAX_WS) return socket.destroy();
      if (buf.length < off + 4 + len) return;

      const mask = buf.subarray(off, off + 4);
      off += 4;
      const payload = Buffer.from(buf.subarray(off, off + len));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      buf = buf.subarray(off + len);

      if (opcode === 0x8) {
        socket.write(makeFrame(0x8, payload));
        return socket.end();
      }
      if (opcode === 0x9) {
        socket.write(makeFrame(0xA, payload));
        continue;
      }
      if (opcode === 0x1 || opcode === 0x2) {
        socket.write(makeFrame(opcode, payload));
        continue;
      }
      return socket.destroy();
    }
  };

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    parse();
  });
  socket.on('error', () => {});
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('slipnet-parspack-ingress-probe listening on', PORT);
});
